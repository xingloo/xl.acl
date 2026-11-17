# ACL 规则格式与原版 `update.py` 生成规范（防跑偏基线）

> **定位**：本文档沉淀原版 [update.py](file:///g:/xingloo/codes/github/xl.acl/update.py)（Git `HEAD` 历史基线）与 [gfwlist2acl.py](file:///g:/xingloo/codes/github/xl.acl/gfwlist2acl.py) 的精确生成规则，以及下游 `tproxy` 代理程序与 Cloudflare Worker [main.js](file:///G:/xingloo/codes/xingloo-workers/acl/main.js) 所依赖的格式契约。  
> **约束**：今后任何替换数据源、优化清洗逻辑或重构脚本的改动，都**必须严格遵循本文档的格式红线**，禁止破坏向下兼容性。

---

## 1. 输出文件与物理格式契约

原版 `update.py` 固定产出仓库根目录下的 3 个文件，编码与换行规范如下：

| 文件名 | 编码与换行 | 默认动作 / JSON 结构 | 下游主要消费方 |
| :--- | :--- | :--- | :--- |
| [gfwlist.acl](file:///g:/xingloo/codes/github/xl.acl/gfwlist.acl) | UTF-8、LF (`\n`)、**末尾有 `\n`** | `[bypass_all]` + `[proxy_list]` (`blacklist`) + `[bypass_list]` (`whitelist`) | 黑名单模式 ACL 客户端（SSR / `shadowsocks-libev` / `shadowsocks-rust` 等） |
| [gfwlist.white.acl](file:///g:/xingloo/codes/github/xl.acl/gfwlist.white.acl) | UTF-8、LF (`\n`)、**末尾有 `\n`** | `[proxy_all]` + `[proxy_list]` (`blacklist`) + `[bypass_list]` (`whitelist`) | 白名单模式 ACL 客户端 |
| [gfwlist.acl.json](file:///g:/xingloo/codes/github/xl.acl/gfwlist.acl.json) | UTF-8、LF (`\n`)、**`json.dump(..., indent=4)` 无尾 `\n`** | `{"blacklist": [...], "whitelist": [...]}` | Cloudflare Worker [main.js](file:///G:/xingloo/codes/xingloo-workers/acl/main.js)（仅读取 `blacklist` 生成 `xingloo.acl` 给 `tproxy`）与 CI Diff |

### `.acl` 文件头部与区块模板（`ACL_TEMPLATE`）

严格保持 [gfwlist2acl.py](file:///g:/xingloo/codes/github/xl.acl/gfwlist2acl.py#L9-L25) 中定义的模板不变：

```ini
#
# Home: https://github.com/NateScarlet/gfwlist.acl
# Date: {date}
# URL: https://raw.githubusercontent.com/NateScarlet/gfwlist.acl/master/{filename}
#

[{default_action}]

[proxy_list]

{blacklist}

[bypass_list]

{whitelist}
```

- `{date}` 使用 `ChinaTimezone`（`UTC+8`）的 `datetime.now(ChinaTimezone()).isoformat()`。
- `{default_action}` 在 `gfwlist.acl` 中为 `bypass_all`，在 `gfwlist.white.acl` 中为 `proxy_all`。
- `[proxy_list]` 对应 `blacklist`，`[bypass_list]` 对应 `whitelist`，每条规则占一行，不夹杂行内注释。

---

## 2. 原版 `update.py` + `gfwlist2acl.py` 逐条生成规则

在 Git `HEAD` 版本中，原版脚本的完整处理链路如下：

### 2.1 输入下载与列表拆分
1. `update.py` 从 `https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt` 下载 Base64 编码文本并解码为 UTF-8 行流。
2. `gfwlist2acl.get_acl_rules()` 对每行执行 `strip()`：
   - 忽略空行，以及以 `!` 或 `[AutoProxy` 开头的注释/声明行。
   - 以 `@@` 开头的行剥除前缀 `@@` 后写入 **`whitelist`**；其余全部写入 **`blacklist`**。

### 2.2 单行规则转换规则（`convert_line` / `get_regexp` / `get_rules`）
1. **斜杠反转义**：先将 `\/` 替换为 `/`。
2. **IP / IP:Port 规则**：匹配 `^\|*(?:https?://)?(\d{,3}\.\d{,3}\.\d{,3}\.\d{,3}(?::\d{1,5})?)/*$` 的行，直接提取纯 `IP` 或 `IP:Port`（如 `85.17.73.31`）。
3. **原生正则规则**：以 `/` 开头且以 `/` 结尾的规则，剥去首尾 `/` 后直接交给 `get_rules()`。
4. **AdBlock 域名规则**：调用 `get_regexp(line)`：
   - **精确转义元字符**：仅转义 `[.*+?^${}()|[\]\\]`（**注意：不转义连字符 `-`**，例如 `x-berry.com` 转义后为 `x-berry\.com`，而非 `x\-berry\.com`）。
   - 通配符与分隔符：`*` → `.+`；`^` → `([^a-zA-Z0-9_-.%]|$)`。
   - 锚点映射：
     - 行首 `||`（可选带 `http://` 或 `https://` 或 `http?://`）→ **`(^|\.)`**（**注意：不自动追加末尾 `$`**）
     - 行首 `|`（可选带协议）→ **`^`**
     - 行尾 `|` → **`$`**
5. **后处理过滤（`get_rules`）**：
   - 将 `\^?https?\??://` 替换为 `^`，去掉末尾的 `(.*)+`，将末尾 `/` 替换为 `$`。
   - **剔除路径规则**：去掉 `[^.../ ...]` 字符类括号内部斜杠后，若仍包含 `/`，整条丢弃（ACL 仅支持主机名/IP 匹配）。
   - **超长分组拆行**：若长度 `> 80` 且命中 `(.*)\((.*)\)(.*)`，将 `|` 分隔项按每 10 个拆分成多条规则。
   - **单行长度限制**：原版过滤 `len(rule) < 500`（当前新引擎已进一步收紧至 `<= 254` 字节，以兼容 `shadowsocks-libev` 的 `MAX_HOSTNAME_LEN = 256`）。

---

## 3. 原版实际产物形态分布（`HEAD:gfwlist.acl.json` 实测）

对原版 `HEAD:gfwlist.acl.json`（`blacklist` **4,388 条**，`whitelist` **32 条**）做全量语法分类统计结果如下：

| 规则形态 | `blacklist` 条数 | `whitelist` 条数 | 原版真实样例 | 备注 |
| :--- | :---: | :---: | :--- | :--- |
| **`(^|\.)domain`（无末尾 `$`）** | **4,117** | **32** | `(^|\.)blogjav\.net`、`(^|\.)dl\.google\.com` | **占原版规则绝对主体** |
| **`^domain`（无末尾 `$`）** | **246** | 0 | `^secure\.hustler\.com`、`^radiko\.jp` | 来自 `\|http://domain` |
| **`^...$`（首尾均有锚点）** | **22** | 0 | `^img\.dlsite\.jp$`、`^sipml5\.org$`、`^.+\.pimg\.tw$` | 来自末尾带 `/` 或 `\|` 的规则 |
| **无锚点纯转义域名** | **2** | 0 | `www\.aolnews\.com`、`iipdigital\.usembassy\.gov` | 来自无 `\|` 前缀的纯域名行 |
| **纯 IP** | **1** | 0 | `85.17.73.31` | — |
| **`(^|\.)...$`（同时含 `(^|\.)` 与 `$`）** | **0** | **0** | — | **原版中 0 条** |

---

## 4. 防跑偏红线（新数据源与 `tproxy` 适配准则）

当前已使用 `Loyalsoldier/v2ray-rules-dat` + `v2fly/domain-list-community`（`dlc.dat_plain.yml`）替代 `gfwlist`，相关实现见 [geosite2acl.py](file:///g:/xingloo/codes/github/xl.acl/geosite2acl.py)。为确保下游 `tproxy` 代理程序及 Worker [main.js](file:///G:/xingloo/codes/xingloo-workers/acl/main.js) 永不踩坑，**必须严守以下 5 条红线**：

1. **多级根域名严禁追加末尾 `$`**
   - 统一编译为 **`(^|\.)example\.com`**（与原版 4,117 条规则及 `whitelist` 32 条完全一致），**不得擅自改为 `(^|\.)example\.com$`**。
   - 下游 `tproxy` 已针对无 `$` 的 `(^|\.)domain` 写法做好边界处理，额外加 `$` 反而可能导致解析不兼容。
2. **剪枝前必须剔除单标签 TLD**
   - 例如 `cn`、`google`、`apple`、`fox`、`mini` 等单标签顶级域必须在执行 `prune_ruleset` 之前剔除（见 `drop_single_label_tlds`）。
   - 原因：无末尾 `$` 时单标签 `(^|\.)fox` 或 `(^|\.)cn` 会误伤 `foxmail.com`、`cnpmjs.org`；同时在剪枝**前**剔除才能完整保留 `*.cn` 二级明细域（如 `(^|\.)gov\.cn`）。
3. **精确域名（`full:`）保持 `^exact\.domain\.com$`**
   - 与原版 `^img\.dlsite\.jp$` 等 22 条规则形态完全对齐。
4. **正则兼容与长度硬约束**
   - 上游 `regexp:` 中出现的 `\d`、`\w`、`\s`、`\S` 必须通过 `normalize_posix_ere` 展开为 `[0-9]`、`[0-9A-Za-z_]`、`[ ]`、`[^ ]`（防止 POSIX ERE 把 `\t\r\n` 解析成字面字母）。
   - 单条规则 UTF-8 字节数不得超过 `254` 字节，且必须通过 `re.compile` 校验。
5. **纯 `[proxy_list]`（无 `[bypass_list]`）场景的防误杀与体积红线**
   - 由于 `main.js` 生成 `xingloo.acl` 时仅读取 `blacklist`、没有 `[bypass_list]` 兜底，构建 `blacklist` 时必须用全量 `direct-list.txt` + 国内直连大厂 CDN 集合（`BYPASS_INFRA_CATEGORIES`）+ 非 `gfw.txt` 的 `.cn`/`.wang` 做净化过滤，并由 `gfw.txt` 保护真正被墙域名不被误删。
   - `whitelist` 保持精简高覆盖口径（不塞入 11 万条 `direct-list.txt`），保证 `gfwlist.acl.json` 体积维持在 ~1.1 MB 量级，避免拖慢 Worker 拉取与 `JSON.parse()`。

---

## 5. 变更回归检查清单（Checklist）

每次调整 [geosite2acl.py](file:///g:/xingloo/codes/github/xl.acl/geosite2acl.py) 或 [update.py](file:///g:/xingloo/codes/github/xl.acl/update.py) 后，必须依次核验：

- [ ] **单测全绿**：`python -m unittest discover -s tests -v` 与 [test_gfwlist2acl.py](file:///g:/xingloo/codes/github/xl.acl/tests/test_gfwlist2acl.py) 全部通过。
- [ ] **无多余 `$`**：抽检 `gfwlist.acl.json` 中多级根域均为 `(^|\.)domain`（不以 `$` 结尾），`whitelist` 保留 `(^|\.)*.cn` 二级域名。
- [ ] **无单标签 TLD 泄漏**：`blacklist` / `whitelist` 中不应出现仅含一个域名标签的 `(^|\.)tld` 规则。
- [ ] **旧 `gfwlist` 基本盘不丢失**：除纯 IP `85.17.73.31` 外，旧版所有多级域名与通配规则均能被新版 `blacklist` 匹配。
- [ ] **国内服务不被误杀**：`alicloud.com`、`alibabacloud.com`、`ctyun.online`、`cnpmjs.org`、`kimi.ai`、`apple.com`、`icloud.com`、`microsoft.com`、`cn.bing.com` 等均不命中 `blacklist`；`openai.com`、`claude.ai`、`google.com`、`github.com`、`copilot.microsoft.com`、`oklink.com` 等正常命中 `blacklist`。
- [ ] **格式与编码校验**：三份产物均为 UTF-8 + LF（无 `\r\n`），`blacklist` 与 `whitelist` 交集为 0，所有条目长度 `<= 254` 字节且全部可被 `re.compile()` 编译。

---

## 6. 上游异常自动阻断校验机制（CI 防污染门禁）

为防止任一上游数据源被截断、清空、损坏或结构突变后自动提交到仓库并影响下游 `main.js` / `tproxy`，[geosite2acl.py](file:///g:/xingloo/codes/github/xl.acl/geosite2acl.py) 与 [update.py](file:///g:/xingloo/codes/github/xl.acl/update.py) 在写入任何文件和执行 `git commit` 之前强制执行 4 层阻断校验（任一失败即以非零状态码中止，不污染仓库）：

1. **下载完整性校验（`fetch_verified_dlc_plain`）**：下载 `dlc.dat_plain.yml` 后同步比对 `dlc.dat_plain.yml.sha256sum`，不匹配则自动重试，仍不匹配直接中止。
2. **分源最小规模与分类存在性校验（`validate_source_counts`）**：逐一核验 `MIN_SOURCE_RULES`（如 `loyal_proxy >= 15000`、`loyal_gfw >= 2500`、`loyal_direct >= 50000`、`dlc_proxy >= 12000`、`dlc_cn >= 4000`、`infra_set >= 1000`）以及关键分类 `geolocation-!cn`、`cn`、`geolocation-cn`、`apple`、`microsoft` 非空。
3. **产物格式契约与金丝雀门禁（`validate_acl_rules`）**：
   - 校验规模下限（`blacklist >= 15000`、`whitelist >= 4000`）、交集为 0、单条 `<= 254` 字节、全部可 `re.compile()`、无多余 `$` 与单标签 TLD 泄漏。
   - **金丝雀实测**：必走代理域（`CANARY_PROXY_DOMAINS`，如 `google.com`、`openai.com`、`claude.ai`、`oklink.com`、`copilot.microsoft.com`）必须命中 `blacklist`；必直连国内/大厂域（`CANARY_DIRECT_DOMAINS`，如 `alicloud.com`、`kimi.ai`、`apple.com`、`microsoft.com`、`cn.bing.com`）不得命中 `blacklist`；核心直连域（`CANARY_WHITELIST_DOMAINS`）必须命中 `whitelist`。
4. **基线环比防抖（`validate_against_baseline`）**：读取仓库现有 [gfwlist.acl.json](file:///g:/xingloo/codes/github/xl.acl/gfwlist.acl.json)，若新版数量较基线缩水 `> 20%` 或暴涨 `> 50%`，直接拦截提交（仅人工确认后传 `--force` 可放行）。
