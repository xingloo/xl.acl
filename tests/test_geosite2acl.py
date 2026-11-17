"""geosite2acl 与 update 模块单元测试。"""

import json
import re
import unittest
from datetime import datetime
from unittest.mock import patch

from geosite2acl import (
    RuleSet,
    compile_acl_rules,
    drop_single_label_tlds,
    extract_dlc_rulesets,
    extract_infra_ruleset,
    filter_proxy_for_tproxy,
    normalize_posix_ere,
    parse_dlc_plain_yml,
    parse_v2ray_txt,
    prune_ruleset,
    resolve_conflicts,
)
from gfwlist2acl import ACL_TEMPLATE, ChinaTimezone
from update import format_release_note


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

            bl, wl = build_acl_rules()

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


if __name__ == "__main__":
    unittest.main()
