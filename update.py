#!/usr/bin/env python3
"""CI 自动更新与发布脚本。"""

import argparse
import json
import logging
import os
import subprocess
from datetime import datetime

from geosite2acl import build_acl_rules
from gfwlist2acl import ACL_TEMPLATE, ChinaTimezone

__dirname__ = os.path.abspath(os.path.dirname(__file__))

MIN_BLACKLIST_RULES = 1000
MIN_WHITELIST_RULES = 100
MAX_RELEASE_DIFF_CHARS = 60000


def _file_path(*other):
    return os.path.join(__dirname__, *other)


def format_release_note(tag: str, diff: str, max_chars: int = MAX_RELEASE_DIFF_CHARS) -> str:
    """生成 GitHub Release 说明，超长 diff 时自动输出变更摘要并截断。"""
    if len(diff) <= max_chars:
        return f"{tag}\n\n```diff\n{diff}\n```"

    added = 0
    removed = 0
    for line in diff.splitlines():
        if line.startswith("+") and not line.startswith("+++"):
            added += 1
        elif line.startswith("-") and not line.startswith("---"):
            removed += 1

    truncated_diff = diff[:max_chars].rstrip("\n")
    return (
        f"{tag}\n\n"
        f"Summary: +{added} / -{removed} lines in `gfwlist.acl.json` "
        f"(full diff truncated to fit GitHub release limit).\n\n"
        f"```diff\n{truncated_diff}\n... (truncated)\n```"
    )


def write_acl_outputs(
    blacklist: list[str],
    whitelist: list[str],
    now: datetime,
) -> list[str]:
    """按既有格式契约输出 gfwlist.acl、gfwlist.white.acl 与 gfwlist.acl.json。"""
    if len(blacklist) < MIN_BLACKLIST_RULES or len(whitelist) < MIN_WHITELIST_RULES:
        raise RuntimeError(
            f"生成规则数量异常，中止写入: blacklist={len(blacklist)}, whitelist={len(whitelist)}"
        )

    filenames = []
    blacklist_text = "\n".join(blacklist)
    whitelist_text = "\n".join(whitelist)

    with open(_file_path("gfwlist.acl"), "w", encoding="utf-8", newline="\n") as f:
        f.write(
            ACL_TEMPLATE.format(
                date=now.isoformat(),
                filename="gfwlist.acl",
                default_action="bypass_all",
                blacklist=blacklist_text,
                whitelist=whitelist_text,
            )
        )
        filenames.append("gfwlist.acl")

    with open(
        _file_path("gfwlist.white.acl"), "w", encoding="utf-8", newline="\n"
    ) as f:
        f.write(
            ACL_TEMPLATE.format(
                date=now.isoformat(),
                filename="gfwlist.white.acl",
                default_action="proxy_all",
                blacklist=blacklist_text,
                whitelist=whitelist_text,
            )
        )
        filenames.append("gfwlist.white.acl")

    with open(_file_path("gfwlist.acl.json"), "w", encoding="utf-8", newline="\n") as f:
        json.dump(
            {"blacklist": blacklist, "whitelist": whitelist},
            f,
            indent=4,
        )
        filenames.append("gfwlist.acl.json")

    return filenames


def main():
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--release",
        action="store_true",
        help="create new release if repository data is not up to date",
    )
    parser.add_argument(
        "--full-direct",
        action="store_true",
        help="include full Loyalsoldier direct-list.txt in whitelist",
    )

    args = parser.parse_args()
    is_release = args.release

    now = datetime.now(ChinaTimezone())
    blacklist, whitelist = build_acl_rules(full_direct=args.full_direct)
    filenames = write_acl_outputs(blacklist, whitelist, now)
    logging.info("已更新 ACL 文件: blacklist=%d, whitelist=%d", len(blacklist), len(whitelist))

    if not is_release:
        print("Updated repository data, skip release since not specified `--release`")
        return

    subprocess.run(["git", "add", *filenames], check=True)
    diff = subprocess.run(
        ["git", "diff", "--cached", "gfwlist.acl.json"],
        encoding="utf-8",
        stdout=subprocess.PIPE,
        check=True,
    ).stdout
    if not diff:
        print("Already up to date")
        return
    subprocess.run(["git", "commit", "-m", "Update acl files [skip ci]"], check=True)
    subprocess.run(["git", "push"], check=True)

    tag = now.strftime("%Y.%m.%d")
    note = format_release_note(tag, diff)
    print("note length: ", len(note))
    subprocess.run(
        [
            "gh",
            "release",
            "create",
            tag,
            *filenames,
            "-F",
            "-",
        ],
        check=True,
        input=note,
        text=True,
    )


if __name__ == "__main__":
    main()
