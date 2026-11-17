#!/usr/bin/env python3
"""基于 v2ray-rules-dat 与 domain-list-community 生成 SSR/Shadowsocks 兼容 ACL 规则。"""

from __future__ import annotations

from dataclasses import dataclass, field
import ipaddress
import json
import logging
import re
import time
from typing import Iterable
from urllib.error import URLError
from urllib.request import Request, urlopen

logger = logging.getLogger(__name__)

# 兼容 shadowsocks-libev 的单行缓冲区上限 (MAX_HOSTNAME_LEN = 256，留出换行与终止符余量)
MAX_ACL_RULE_BYTES = 254

# 仅转义 ACL 正则元字符，保留连字符 `-` 以与现有规则输出风格一致
_DOMAIN_META_RE = re.compile(r"[.*+?^${}()|[\]\\]")

# Loyalsoldier/v2ray-rules-dat 上游明文清单（主源 GitHub Raw，备源 jsDelivr CDN）
LOYAL_SOURCES: dict[str, tuple[str, ...]] = {
    "proxy": (
        "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/proxy-list.txt",
        "https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/proxy-list.txt",
    ),
    "gfw": (
        "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/gfw.txt",
        "https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/gfw.txt",
    ),
    "direct": (
        "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/direct-list.txt",
        "https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/direct-list.txt",
    ),
    "direct_tld": (
        "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/direct-tld-list.txt",
        "https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/direct-tld-list.txt",
    ),
    "google_cn": (
        "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/google-cn.txt",
        "https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/google-cn.txt",
    ),
    "apple_cn": (
        "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/apple-cn.txt",
        "https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/apple-cn.txt",
    ),
}

# v2fly/domain-list-community 最新 Release 纯文本总表
DLC_PLAIN_URLS: tuple[str, ...] = (
    "https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat_plain.yml",
)

# 在无 [bypass_list] 兜底的纯 [proxy_list]（如 TProxy）场景下，
# 这些大厂/公共 CDN 默认承担大量国内直连与大流量下载，仅保留其中明确在 gfw.txt 中的被墙子域
BYPASS_INFRA_CATEGORIES: tuple[str, ...] = (
    "apple",
    "icloud",
    "microsoft",
    "bing",
    "aws",
    "azure",
    "cloudfront",
    "fastly",
    "akamai",
    "steam",
)

DlcEntry = tuple[str, str, set[str]]


@dataclass
class RuleSet:
    """分流规则中间表示集合，按匹配类型分类存储。"""

    roots: set[str] = field(default_factory=set)
    fulls: set[str] = field(default_factory=set)
    regexps: set[str] = field(default_factory=set)
    keywords: set[str] = field(default_factory=set)
    ips: set[str] = field(default_factory=set)

    def add(self, rule_type: str, value: str) -> None:
        """按规则类型写入并执行基础标准化。"""
        value = value.strip()
        if not value:
            return
        if rule_type in ("domain", "root"):
            self.roots.add(value.lstrip(".").lower())
        elif rule_type == "full":
            self.fulls.add(value.lower())
        elif rule_type == "regexp":
            self.regexps.add(value)
        elif rule_type == "keyword":
            self.keywords.add(value.lower())
        elif rule_type == "ip":
            self.ips.add(value)
        else:
            logger.warning("忽略未知规则类型: %s (%s)", rule_type, value)

    def merge(self, other: RuleSet) -> RuleSet:
        """返回与另一个 RuleSet 合并后的新实例。"""
        return RuleSet(
            roots=self.roots | other.roots,
            fulls=self.fulls | other.fulls,
            regexps=self.regexps | other.regexps,
            keywords=self.keywords | other.keywords,
            ips=self.ips | other.ips,
        )

    def __or__(self, other: RuleSet) -> RuleSet:
        return self.merge(other)


def _is_ip_or_cidr(value: str) -> bool:
    """判断字符串是否为合法 IPv4/IPv6 或 CIDR 网段。"""
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False


def _has_ancestor(domain: str, roots: set[str], allow_self: bool) -> bool:
    """判断域名是否已被 roots 中的自身或父级域名覆盖。"""
    parts = domain.split(".")
    start = 0 if allow_self else 1
    for idx in range(start, len(parts)):
        if ".".join(parts[idx:]) in roots:
            return True
    return False


def _split_attrs(raw: str) -> tuple[str, set[str]]:
    """拆解规则主体与 `:@attr1,@attr2` 属性标签集合。"""
    if ":@" not in raw:
        return raw, set()
    main_part, attr_str = raw.split(":@", 1)
    attrs = {
        item.lstrip("@").strip().lower()
        for item in attr_str.split(",")
        if item.strip()
    }
    return main_part, attrs


def _parse_yaml_scalar(token: str) -> str:
    """解析 dlc.dat_plain.yml 中的单行标量字符串（默认双引号 JSON 转义）。"""
    token = token.strip()
    if token.startswith('"') and token.endswith('"'):
        try:
            decoded = json.loads(token)
            if isinstance(decoded, str):
                return decoded
        except json.JSONDecodeError:
            return token[1:-1]
    if token.startswith("'") and token.endswith("'") and len(token) >= 2:
        return token[1:-1].replace("''", "'")
    return token


def fetch_text(
    urls: Iterable[str],
    timeout: int = 30,
    retries: int = 3,
) -> str:
    """按优先级依次尝试主/备 URL 下载文本内容，支持指数退避重试。"""
    last_err: Exception | None = None
    for url in urls:
        for attempt in range(1, retries + 1):
            try:
                req = Request(url, headers={"User-Agent": "xl.acl-updater/1.0"})
                with urlopen(req, timeout=timeout) as resp:
                    if getattr(resp, "status", 200) >= 400:
                        raise URLError(f"HTTP status {resp.status}")
                    return resp.read().decode("utf-8")
            except (URLError, TimeoutError, OSError) as err:
                last_err = err
                logger.warning(
                    "下载失败 (%s, 第 %d/%d 次): %s", url, attempt, retries, err
                )
                if attempt < retries:
                    time.sleep(min(2 ** (attempt - 1), 4))
    raise RuntimeError(f"所有上游地址均下载失败: {list(urls)}") from last_err


def parse_v2ray_txt(lines: Iterable[str]) -> RuleSet:
    """解析 Loyalsoldier/v2ray-rules-dat 导出的纯文本规则列表。"""
    rule_set = RuleSet()
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        # 去除行内注释
        if " #" in line:
            line = line.split(" #", 1)[0].strip()
        main_part, _ = _split_attrs(line)
        if ":" in main_part and not _is_ip_or_cidr(main_part):
            rtype, rval = main_part.split(":", 1)
            rule_set.add(rtype.strip().lower(), rval)
        elif _is_ip_or_cidr(main_part):
            rule_set.add("ip", main_part)
        else:
            rule_set.add("domain", main_part)
    return rule_set


def parse_dlc_plain_yml(lines: Iterable[str]) -> dict[str, list[DlcEntry]]:
    """解析 v2fly/domain-list-community 发布的 dlc.dat_plain.yml。"""
    lists: dict[str, list[DlcEntry]] = {}
    current_name: str | None = None

    for raw_line in lines:
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("- name:"):
            name_token = stripped.split(":", 1)[1]
            current_name = _parse_yaml_scalar(name_token).lower()
            lists.setdefault(current_name, [])
            continue
        if current_name is None:
            continue
        if stripped.startswith("- "):
            rule_text = _parse_yaml_scalar(stripped[2:])
            main_part, attrs = _split_attrs(rule_text)
            if ":" in main_part and not _is_ip_or_cidr(main_part):
                rtype, rval = main_part.split(":", 1)
                lists[current_name].append((rtype.strip().lower(), rval, attrs))
            elif _is_ip_or_cidr(main_part):
                lists[current_name].append(("ip", main_part, attrs))
            else:
                lists[current_name].append(("domain", main_part, attrs))
    return lists


def extract_dlc_rulesets(
    dlc_lists: dict[str, list[DlcEntry]],
) -> tuple[RuleSet, RuleSet]:
    """从 dlc 解析结果中提取清洗后的代理集合与国内直连集合。

    过滤逻辑对齐 sing-geosite/main.go：
    - 代理集合 (`geolocation-!cn`) 剔除带有 `cn` 或 `ads` 属性的条目。
    - 直连集合合并 `cn`、`geolocation-cn`、`tld-cn`、`category-*-cn`
      以及 `category-*` / `google` / `apple` 中带 `cn` 属性的条目，同时剔除 `ads` 与 `!cn`。
    """
    proxy_set = RuleSet()
    for rtype, rval, attrs in dlc_lists.get("geolocation-!cn", ()):
        if attrs & {"cn", "ads"}:
            continue
        proxy_set.add(rtype, rval)

    direct_set = RuleSet()
    # 基础直连分类：直接收录（剔除 ads 与 !cn）
    direct_base_names = ["cn", "geolocation-cn", "tld-cn"] + [
        name
        for name in dlc_lists
        if name.startswith("category-")
        and name.endswith("-cn")
        and not name.endswith("-!cn")
    ]
    for name in direct_base_names:
        for rtype, rval, attrs in dlc_lists.get(name, ()):
            if attrs & {"ads", "!cn"}:
                continue
            direct_set.add(rtype, rval)

    # 非 -cn 分类及 google/apple 中的 @cn 子集
    for name, entries in dlc_lists.items():
        is_attr_target = (
            name.startswith("category-")
            and not name.endswith("-cn")
            and not name.endswith("-!cn")
        ) or name in ("google", "apple")
        if not is_attr_target:
            continue
        for rtype, rval, attrs in entries:
            if "cn" in attrs and not (attrs & {"ads", "!cn"}):
                direct_set.add(rtype, rval)

    return proxy_set, direct_set


def resolve_conflicts(
    proxy_set: RuleSet,
    direct_set: RuleSet,
    protected_proxy: RuleSet,
) -> tuple[RuleSet, RuleSet]:
    """执行精确冲突仲裁：优先级为 protected_proxy (gfw) > direct_set > proxy_set。"""
    p_roots = set(proxy_set.roots)
    p_fulls = set(proxy_set.fulls)
    p_regexps = set(proxy_set.regexps)
    p_keywords = set(proxy_set.keywords)
    p_ips = set(proxy_set.ips)

    d_roots = set(direct_set.roots)
    d_fulls = set(direct_set.fulls)
    d_regexps = set(direct_set.regexps)
    d_keywords = set(direct_set.keywords)
    d_ips = set(direct_set.ips)

    for domain in p_roots & d_roots:
        if _has_ancestor(domain, protected_proxy.roots, allow_self=True):
            d_roots.discard(domain)
        else:
            p_roots.discard(domain)

    for domain in p_fulls & d_fulls:
        if (
            domain in protected_proxy.fulls
            or _has_ancestor(domain, protected_proxy.roots, allow_self=True)
        ):
            d_fulls.discard(domain)
        else:
            p_fulls.discard(domain)

    for expr in p_regexps & d_regexps:
        if expr in protected_proxy.regexps:
            d_regexps.discard(expr)
        else:
            p_regexps.discard(expr)

    for kw in p_keywords & d_keywords:
        if kw in protected_proxy.keywords:
            d_keywords.discard(kw)
        else:
            p_keywords.discard(kw)

    for ip in p_ips & d_ips:
        if ip in protected_proxy.ips:
            d_ips.discard(ip)
        else:
            p_ips.discard(ip)

    return (
        RuleSet(p_roots, p_fulls, p_regexps, p_keywords, p_ips),
        RuleSet(d_roots, d_fulls, d_regexps, d_keywords, d_ips),
    )


def prune_ruleset(rule_set: RuleSet) -> RuleSet:
    """消除集合内部已被父级根域名或 TLD 覆盖的冗余子域与 full 规则。"""
    kept_roots = {
        domain
        for domain in rule_set.roots
        if not _has_ancestor(domain, rule_set.roots, allow_self=False)
    }
    kept_fulls = {
        domain
        for domain in rule_set.fulls
        if not _has_ancestor(domain, kept_roots, allow_self=True)
    }
    return RuleSet(
        roots=kept_roots,
        fulls=kept_fulls,
        regexps=set(rule_set.regexps),
        keywords=set(rule_set.keywords),
        ips=set(rule_set.ips),
    )


def _escape_domain(domain: str) -> str:
    """转义域名中的正则元字符，保留常规字符与连字符。"""
    return _DOMAIN_META_RE.sub(lambda match: f"\\{match.group(0)}", domain)


def normalize_posix_ere(pattern: str) -> str:
    """将上游正则中的 \\d / \\w / \\s / \\S 简写转换为 POSIX ERE 兼容字符类。"""
    class_map = {
        "d": "0-9",
        "w": "0-9A-Za-z_",
        "s": " ",
    }
    out: list[str] = []
    in_class = False
    class_start_idx = -1
    i = 0
    length = len(pattern)

    while i < length:
        ch = pattern[i]
        if ch == "\\" and i + 1 < length:
            nxt = pattern[i + 1]
            if nxt in class_map:
                inner = class_map[nxt]
                out.append(inner if in_class else f"[{inner}]")
                i += 2
                continue
            if nxt == "S" and not in_class:
                # POSIX ERE 不支持 \t/\r 等转义，主机名非空白匹配使用 [^ ] 最安全
                out.append("[^ ]")
                i += 2
                continue
            out.append(ch)
            out.append(nxt)
            i += 2
            continue

        if ch == "[" and not in_class:
            in_class = True
            class_start_idx = i
            out.append(ch)
        elif ch == "]" and in_class:
            # 紧跟在 `[` 或 `[^` 后的 `]` 在字符类中视为字面量，不结束字符类
            is_literal_close = i == class_start_idx + 1 or (
                i == class_start_idx + 2 and pattern[class_start_idx + 1] == "^"
            )
            if not is_literal_close:
                in_class = False
            out.append(ch)
        else:
            out.append(ch)
        i += 1

    return "".join(out)


def compile_acl_rules(
    rule_set: RuleSet,
    max_bytes: int = MAX_ACL_RULE_BYTES,
) -> list[str]:
    """将标准化 RuleSet 编译为兼容现行 ACL 语法的有序去重规则列表。"""
    candidates: list[str] = []

    for ip in sorted(rule_set.ips):
        candidates.append(ip)
    for domain in sorted(rule_set.roots):
        escaped = _escape_domain(domain)
        # 多级根域严格对齐原版 gfwlist2acl 输出（不加末尾 $）；仅单标签 TLD 保留 $ 防前缀误伤
        if "." in domain:
            candidates.append(rf"(^|\.){escaped}")
        else:
            candidates.append(rf"(^|\.){escaped}$")
    for domain in sorted(rule_set.fulls):
        candidates.append(rf"^{_escape_domain(domain)}$")
    for expr in sorted(rule_set.regexps):
        candidates.append(normalize_posix_ere(expr))
    for kw in sorted(rule_set.keywords):
        candidates.append(_escape_domain(kw))

    compiled: list[str] = []
    seen: set[str] = set()
    for rule in candidates:
        if not rule or rule in seen:
            continue
        if len(rule.encode("utf-8")) > max_bytes:
            logger.warning("规则超过 %d 字节已忽略: %s", max_bytes, rule)
            continue
        try:
            re.compile(rule)
        except re.error as err:
            logger.warning("无效正则表达式已忽略 (%s): %s", err, rule)
            continue
        seen.add(rule)
        compiled.append(rule)

    return compiled


def extract_infra_ruleset(
    dlc_lists: dict[str, list[DlcEntry]],
    categories: Iterable[str] = BYPASS_INFRA_CATEGORIES,
) -> RuleSet:
    """提取默认直连大厂及公共 CDN 域名集合，用于在纯黑名单模式下防误代理。"""
    infra_set = RuleSet()
    for category in categories:
        for rtype, rval, _ in dlc_lists.get(category, ()):
            infra_set.add(rtype, rval)
    return infra_set


def filter_proxy_for_tproxy(
    proxy_set: RuleSet,
    direct_filter: RuleSet,
    infra_set: RuleSet,
    protected_proxy: RuleSet,
) -> RuleSet:
    """净化黑名单：剔除国内直连域、非 gfw .cn/.wang 域及直连大厂 CDN 泛域，同时保留 gfw.txt 保护项。"""
    cn_specific_roots = {
        domain
        for domain in proxy_set.roots
        if domain.endswith(".cn")
        or domain.endswith(".wang")
        or domain == "amazonaws-china.com"
    }
    excluded_roots = (
        direct_filter.roots | infra_set.roots | cn_specific_roots
    ) - protected_proxy.roots
    excluded_fulls = (
        direct_filter.fulls | infra_set.fulls
    ) - protected_proxy.fulls
    excluded_regexps = direct_filter.regexps - protected_proxy.regexps
    excluded_keywords = direct_filter.keywords - protected_proxy.keywords
    excluded_ips = direct_filter.ips - protected_proxy.ips

    return RuleSet(
        roots=proxy_set.roots - excluded_roots,
        fulls=proxy_set.fulls - excluded_fulls,
        regexps=proxy_set.regexps - excluded_regexps,
        keywords=proxy_set.keywords - excluded_keywords,
        ips=proxy_set.ips - excluded_ips,
    )


def drop_single_label_tlds(rule_set: RuleSet) -> RuleSet:
    """剔除单标签顶级域 (TLD)，避免无末尾 $ 时产生前缀误伤；需在剪枝前调用以保留二级域明细。"""
    return RuleSet(
        roots={domain for domain in rule_set.roots if "." in domain},
        fulls=set(rule_set.fulls),
        regexps=set(rule_set.regexps),
        keywords=set(rule_set.keywords),
        ips=set(rule_set.ips),
    )


def build_acl_rules(full_direct: bool = False) -> tuple[list[str], list[str]]:
    """拉取双源数据并生成 (blacklist, whitelist) ACL 规则列表。"""
    loyal_proxy = parse_v2ray_txt(fetch_text(LOYAL_SOURCES["proxy"]).splitlines())
    loyal_gfw = parse_v2ray_txt(fetch_text(LOYAL_SOURCES["gfw"]).splitlines())
    loyal_direct = parse_v2ray_txt(fetch_text(LOYAL_SOURCES["direct"]).splitlines())
    loyal_direct_tld = parse_v2ray_txt(
        fetch_text(LOYAL_SOURCES["direct_tld"]).splitlines()
    )
    loyal_google_cn = parse_v2ray_txt(
        fetch_text(LOYAL_SOURCES["google_cn"]).splitlines()
    )
    loyal_apple_cn = parse_v2ray_txt(
        fetch_text(LOYAL_SOURCES["apple_cn"]).splitlines()
    )

    dlc_lists = parse_dlc_plain_yml(fetch_text(DLC_PLAIN_URLS).splitlines())
    dlc_proxy, dlc_cn = extract_dlc_rulesets(dlc_lists)
    infra_set = extract_infra_ruleset(dlc_lists)

    proxy_set = loyal_proxy | dlc_proxy | loyal_gfw
    direct_set = dlc_cn | loyal_direct_tld | loyal_google_cn | loyal_apple_cn
    if full_direct:
        direct_set = direct_set | loyal_direct

    # 无论白名单采用精简版还是全量版，黑名单始终使用全量直连表 + 直连大厂 CDN 集合进行防误杀净化
    direct_filter = direct_set | loyal_direct
    proxy_set = filter_proxy_for_tproxy(proxy_set, direct_filter, infra_set, loyal_gfw)
    proxy_set, direct_set = resolve_conflicts(proxy_set, direct_set, loyal_gfw)

    proxy_set = prune_ruleset(drop_single_label_tlds(proxy_set))
    direct_set = prune_ruleset(drop_single_label_tlds(direct_set))

    blacklist = compile_acl_rules(proxy_set)
    whitelist = compile_acl_rules(direct_set)
    return blacklist, whitelist
