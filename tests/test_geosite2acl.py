"""geosite2acl 与 update 模块单元测试。"""

import hashlib
import json
import os
import re
import tempfile
import unittest
from datetime import datetime
from unittest.mock import patch

from geosite2acl import (
    CANARY_DIRECT_DOMAINS,
    CANARY_PROXY_DOMAINS,
    CANARY_WHITELIST_DOMAINS,
    MIN_COMPILED_BLACKLIST,
    MIN_COMPILED_WHITELIST,
    MIN_SOURCE_RULES,
    RuleSet,
    compile_acl_rules,
    drop_single_label_tlds,
    extract_dlc_rulesets,
    extract_infra_ruleset,
    fetch_verified_dlc_plain,
    filter_proxy_for_tproxy,
    normalize_posix_ere,
    parse_dlc_plain_yml,
    parse_v2ray_txt,
    prune_ruleset,
    resolve_conflicts,
    validate_acl_rules,
    validate_source_counts,
)
from gfwlist2acl import ACL_TEMPLATE, ChinaTimezone
from update import format_release_note, validate_against_baseline


class TestGeosite2Acl(unittest.TestCase):
    """覆盖解析、清洗、冲突仲裁、剪枝与 ACL 编译逻辑。"""

    def test_parse_v2ray_txt(self):
        lines = [
            "# comment line",
            "",
            "example.com",
            "full:dl.google.com",
            r"regexp:^cdn\d-test\.example\.net$",
            "keyword:tracker",
            "85.17.73.31",
            "192.168.0.0/16",
            "Sub.Domain.Org # inline comment",
        ]
        rs = parse_v2ray_txt(lines)
        self.assertEqual(rs.roots, {"example.com", "sub.domain.org"})
        self.assertEqual(rs.fulls, {"dl.google.com"})
        self.assertEqual(rs.regexps, {r"^cdn\d-test\.example\.net$"})
        self.assertEqual(rs.keywords, {"tracker"})
        self.assertEqual(rs.ips, {"85.17.73.31", "192.168.0.0/16"})

    def test_parse_dlc_plain_yml_and_extract(self):
        yml_lines = [
            "lists:",
            '  - name: "geolocation-!cn"',
            "    length: 5",
            "    rules:",
            '      - "domain:github.com"',
            '      - "domain:265.com:@cn"',
            '      - "domain:ads.example.com:@ads,@telemetry"',
            '      - "full:api.openai.com"',
            '      - "regexp:(^|\\\\.)test[0-9]{2}\\\\.xyz$"',
            '  - name: "cn"',
            "    length: 3",
            "    rules:",
            '      - "domain:baidu.com"',
            '      - "domain:ad.baidu.com:@ads"',
            '      - "domain:blocked.example:@!cn"',
            '  - name: "tld-cn"',
            "    length: 1",
            "    rules:",
            '      - "domain:cn"',
            '  - name: "category-games-cn"',
            "    length: 1",
            "    rules:",
            '      - "domain:mihoyo.com"',
            '  - name: "category-companies"',
            "    length: 2",
            "    rules:",
            '      - "domain:alibaba.com:@cn"',
            '      - "domain:foreign.com"',
            '  - name: "google"',
            "    length: 2",
            "    rules:",
            '      - "full:dl.google.com:@cn"',
            '      - "domain:google.com"',
        ]
        parsed = parse_dlc_plain_yml(yml_lines)
        proxy_set, direct_set = extract_dlc_rulesets(parsed)

        self.assertEqual(proxy_set.roots, {"github.com"})
        self.assertEqual(proxy_set.fulls, {"api.openai.com"})
        self.assertEqual(proxy_set.regexps, {r"(^|\.)test[0-9]{2}\.xyz$"})

        self.assertEqual(
            direct_set.roots, {"baidu.com", "cn", "mihoyo.com", "alibaba.com"}
        )
        self.assertEqual(direct_set.fulls, {"dl.google.com"})

    def test_resolve_conflicts_gfw_priority(self):
        proxy = RuleSet(
            roots={"oklink.com", "265.com", "github.com"},
            fulls={"a.example.com"},
        )
        direct = RuleSet(
            roots={"oklink.com", "265.com", "baidu.com"},
            fulls={"a.example.com", "dl.google.com"},
        )
        gfw = RuleSet(roots={"oklink.com"})

        p_res, d_res = resolve_conflicts(proxy, direct, gfw)
        # gfw.txt 保护 oklink.com 留在 proxy
        self.assertIn("oklink.com", p_res.roots)
        self.assertNotIn("oklink.com", d_res.roots)
        # 非 gfw 冲突 265.com 与 a.example.com 归 direct
        self.assertNotIn("265.com", p_res.roots)
        self.assertIn("265.com", d_res.roots)
        self.assertNotIn("a.example.com", p_res.fulls)
        self.assertIn("a.example.com", d_res.fulls)

    def test_prune_ruleset(self):
        rs = RuleSet(
            roots={"cn", "baidu.cn", "sub.baidu.cn", "qq.com", "vip.qq.com"},
            fulls={"www.qq.com", "news.cn", "special.org"},
        )
        pruned = prune_ruleset(rs)
        self.assertEqual(pruned.roots, {"cn", "qq.com"})
        self.assertEqual(pruned.fulls, {"special.org"})

    def test_normalize_posix_ere(self):
        self.assertEqual(
            normalize_posix_ere(r"^cdn\d-epic-\w+\S+\s\.com$"),
            r"^cdn[0-9]-epic-[0-9A-Za-z_]+[^ ]+[ ]\.com$",
        )
        # 字符类内部不应生成嵌套方括号
        self.assertEqual(
            normalize_posix_ere(r"^item[\d_]+\.com$"),
            r"^item[0-9_]+\.com$",
        )
        # 首字符为 ] 时字符类未结束
        self.assertEqual(
            normalize_posix_ere(r"^[]\d]+\.com$"),
            r"^[]0-9]+\.com$",
        )

    def test_compile_acl_rules_format_and_limits(self):
        long_domain = "a" * 250 + ".com"
        rs = RuleSet(
            roots={"example.com", "x-berry.com", "cn", long_domain},
            fulls={"dl.google.com"},
            regexps={r"^cdn\d\.example\.net$", r"[invalid("},
            ips={"85.17.73.31"},
        )
        rules = compile_acl_rules(rs)
        self.assertEqual(
            rules,
            [
                "85.17.73.31",
                r"(^|\.)cn$",
                r"(^|\.)example\.com",
                r"(^|\.)x-berry\.com",
                r"^dl\.google\.com$",
                r"^cdn[0-9]\.example\.net$",
            ],
        )
        for rule in rules:
            self.assertLessEqual(len(rule.encode("utf-8")), 254)
            re.compile(rule)

        dropped = drop_single_label_tlds(RuleSet(roots={"cn", "gov.cn"}))
        self.assertEqual(dropped.roots, {"gov.cn"})

    def test_acl_template_and_release_note(self):
        rendered = ACL_TEMPLATE.format(
            date=datetime(2026, 11, 17, 10, 0, tzinfo=ChinaTimezone()).isoformat(),
            filename="gfwlist.acl",
            default_action="bypass_all",
            blacklist=r"(^|\.)google\.com$",
            whitelist=r"(^|\.)cn$",
        )
        self.assertIn("[bypass_all]", rendered)
        self.assertIn("[proxy_list]", rendered)
        self.assertIn("[bypass_list]", rendered)

        short_note = format_release_note("2026.11.17", "+a\n-b", max_chars=100)
        self.assertIn("```diff\n+a\n-b\n```", short_note)

        long_diff = "\n".join(f"+line_{i}" for i in range(500))
        long_note = format_release_note("2026.11.17", long_diff, max_chars=200)
        self.assertIn("Summary: +500 / -0 lines", long_note)
        self.assertIn("... (truncated)", long_note)
        self.assertLess(len(long_note), 600)

    def test_filter_proxy_for_tproxy(self):
        dlc_lists = {
            "apple": [("domain", "apple.com", set())],
            "microsoft": [("domain", "microsoft.com", set())],
            "openai": [("domain", "openai.com", set())],
        }
        infra = extract_infra_ruleset(dlc_lists, categories=("apple", "microsoft"))
        self.assertEqual(infra.roots, {"apple.com", "microsoft.com"})

        proxy = RuleSet(
            roots={
                "openai.com",
                "alicloud.com",
                "apple.com",
                "copilot.microsoft.com",
                "microsoft.com",
                "zoom.com.cn",
                "bloomberg.cn",
            }
        )
        direct_filter = RuleSet(roots={"alicloud.com"})
        gfw = RuleSet(roots={"copilot.microsoft.com", "bloomberg.cn"})

        cleaned = filter_proxy_for_tproxy(proxy, direct_filter, infra, gfw)
        self.assertEqual(
            cleaned.roots,
            {"openai.com", "copilot.microsoft.com", "bloomberg.cn"},
        )

    def test_build_acl_rules_end_to_end_mock(self):
        mock_data = {
            "proxy-list.txt": "google.com\n265.com\noklink.com\nalicloud.com\napple.com\nzoom.com.cn\n",
            "gfw.txt": "oklink.com\ntwitter.com\nbloomberg.cn\n",
            "direct-list.txt": "alicloud.com\noklink.com\n",
            "direct-tld-list.txt": "cn\n",
            "google-cn.txt": "full:dl.google.com\n",
            "apple-cn.txt": "full:swcdn.apple.com\n",
            "dlc.dat_plain.yml": "\n".join(
                [
                    "lists:",
                    '  - name: "geolocation-!cn"',
                    "    rules:",
                    '      - "domain:openai.com"',
                    '      - "domain:bloomberg.cn"',
                    '      - "domain:bad.ads:@ads"',
                    '  - name: "apple"',
                    "    rules:",
                    '      - "domain:apple.com"',
                    '  - name: "cn"',
                    "    rules:",
                    '      - "domain:265.com"',
                    '      - "domain:gov.cn"',
                    '      - "domain:oklink.com"',
                ]
            ),
        }

        def fake_fetch(urls, **_kwargs):
            url = next(iter(urls))
            for key, content in mock_data.items():
                if url.endswith(key):
                    return content
            raise AssertionError(f"unexpected url: {url}")

        with patch("geosite2acl.fetch_text", side_effect=fake_fetch):
            from geosite2acl import build_acl_rules

            bl, wl = build_acl_rules(
                verify_integrity=False,
                validate_sources=False,
                validate_output=False,
            )

        self.assertEqual(
            bl,
            [
                r"(^|\.)bloomberg\.cn",
                r"(^|\.)google\.com",
                r"(^|\.)oklink\.com",
                r"(^|\.)openai\.com",
                r"(^|\.)twitter\.com",
            ],
        )
        self.assertEqual(
            wl,
            [
                r"(^|\.)265\.com",
                r"(^|\.)gov\.cn",
                r"^dl\.google\.com$",
                r"^swcdn\.apple\.com$",
            ],
        )
        # 验证 json 序列化契约
        payload = json.loads(json.dumps({"blacklist": bl, "whitelist": wl}))
        self.assertEqual(set(payload.keys()), {"blacklist", "whitelist"})

    def test_fetch_verified_dlc_plain(self):
        yml_content = 'lists:\n  - name: "cn"\n    rules:\n      - "domain:baidu.com"\n'
        good_sha = hashlib.sha256(yml_content.encode("utf-8")).hexdigest()

        def fake_ok(urls, **_kwargs):
            url = next(iter(urls))
            if url.endswith(".sha256sum"):
                return f"{good_sha}  dlc.dat_plain.yml\n"
            return yml_content

        with patch("geosite2acl.fetch_text", side_effect=fake_ok):
            self.assertEqual(fetch_verified_dlc_plain(), yml_content)

        def fake_bad(urls, **_kwargs):
            url = next(iter(urls))
            if url.endswith(".sha256sum"):
                return f"{'0' * 64}  dlc.dat_plain.yml\n"
            return yml_content

        with patch("geosite2acl.fetch_text", side_effect=fake_bad), patch(
            "geosite2acl.time.sleep"
        ):
            with self.assertRaises(RuntimeError):
                fetch_verified_dlc_plain(retries=2)

    def test_validate_source_counts_rejects_truncated(self):
        healthy_sources = {
            name: RuleSet(roots={f"d{i}.example.com" for i in range(cnt)})
            for name, cnt in MIN_SOURCE_RULES.items()
        }
        healthy_dlc = {
            "geolocation-!cn": [("domain", "openai.com", set())],
            "cn": [("domain", "baidu.com", set())],
            "geolocation-cn": [("domain", "qq.com", set())],
            "apple": [("domain", "apple.com", set())],
            "microsoft": [("domain", "microsoft.com", set())],
        }
        validate_source_counts(healthy_sources, healthy_dlc)

        broken_sources = dict(healthy_sources)
        broken_sources["loyal_direct"] = RuleSet(roots={"baidu.com"})
        with self.assertRaises(RuntimeError):
            validate_source_counts(broken_sources, healthy_dlc)

        broken_dlc = dict(healthy_dlc)
        broken_dlc["cn"] = []
        with self.assertRaises(RuntimeError):
            validate_source_counts(healthy_sources, broken_dlc)

    def _build_valid_canary_lists(self):
        bl = [rf"(^|\.){d.replace('.', r'\.')}" for d in CANARY_PROXY_DOMAINS]
        bl.extend(
            rf"(^|\.)extra{i}\.example\.com"
            for i in range(MIN_COMPILED_BLACKLIST - len(bl) + 10)
        )
        wl = [
            rf"(^|\.){d.replace('.', r'\.')}"
            if d != "dl.google.com"
            else r"^dl\.google\.com$"
            for d in CANARY_WHITELIST_DOMAINS
        ]
        wl.extend(
            rf"(^|\.)cn{i}\.example\.cn"
            for i in range(MIN_COMPILED_WHITELIST - len(wl) + 10)
        )
        return bl, wl

    def test_validate_acl_rules_canary_and_contract(self):
        bl, wl = self._build_valid_canary_lists()
        validate_acl_rules(bl, wl)

        # 1. 多级根域误加末尾 $ 必须报错
        bad_dollar = list(bl)
        bad_dollar[-1] = r"(^|\.)extra\.example\.com$"
        with self.assertRaises(RuntimeError):
            validate_acl_rules(bad_dollar, wl)

        # 2. 单标签 TLD 泄漏必须报错
        bad_tld = list(bl) + [r"(^|\.)google"]
        with self.assertRaises(RuntimeError):
            validate_acl_rules(bad_tld, wl)

        # 3. 直连域名混入 blacklist 必须触发金丝雀拦截
        leaked_bl = list(bl) + [rf"(^|\.){CANARY_DIRECT_DOMAINS[3].replace('.', r'\.')}"]
        with self.assertRaises(RuntimeError):
            validate_acl_rules(leaked_bl, wl)

        # 4. 关键代理域名缺失必须拦截
        missing_proxy_bl = [r for r in bl if "openai" not in r]
        with self.assertRaises(RuntimeError):
            validate_acl_rules(missing_proxy_bl, wl)

    def test_validate_against_baseline_rejects_anomaly(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            baseline_file = os.path.join(tmpdir, "gfwlist.acl.json")
            with open(baseline_file, "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "blacklist": [f"r{i}" for i in range(1000)],
                        "whitelist": [f"w{i}" for i in range(500)],
                    },
                    f,
                )

            # 正常小幅波动放行
            validate_against_baseline(
                [f"r{i}" for i in range(950)],
                [f"w{i}" for i in range(520)],
                baseline_path=baseline_file,
            )

            # 缩水 >20% 拦截
            with self.assertRaises(RuntimeError):
                validate_against_baseline(
                    [f"r{i}" for i in range(700)],
                    [f"w{i}" for i in range(500)],
                    baseline_path=baseline_file,
                )

            # 暴涨 >50% 拦截
            with self.assertRaises(RuntimeError):
                validate_against_baseline(
                    [f"r{i}" for i in range(1000)],
                    [f"w{i}" for i in range(800)],
                    baseline_path=baseline_file,
                )

            # --force 放行
            validate_against_baseline(
                [f"r{i}" for i in range(700)],
                [f"w{i}" for i in range(800)],
                baseline_path=baseline_file,
                force=True,
            )


if __name__ == "__main__":
    unittest.main()
