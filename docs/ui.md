# wrasse CLI 界面规范 v2

> 可视化对照：`docs/ui-mockup.html`
> 本文是实现规则，mockup 是它的样子。冲突时以本文为准。

---

## 0. v2 相对 v1 的三处变化

| 变化 | 理由 |
|---|---|
| 每条 finding 直接给 **红 `-` 问题行 / 绿 `+` 修复行** | 用户要的不是"哪里错了"，是"改成什么"。修复就是交付物 |
| "复制给 AI"给的是**预设提示词**，随规则版本化 | 不生成、不调模型、可审查；同一规则永远给同一段话 |
| 全界面**中英双语，默认英语** | 面向国际读者；`wrasse config set lang zh` 改为中文，`--lang` 只覆盖一次 |

---

## 1. 七条规则

1. **一条 finding = 一处修复。**红行是现状，绿行是改法；没有绿行的 finding 不合格。
2. **位置独占一段。**`path:line:col` 前后不能有别的字符，否则终端不识别为链接。
3. **颜色只表达含义。**红=问题、绿=修复、严重度色只用在徽章与计数上；去掉颜色仍可读。
4. **80 列可用。**默认按 80 列排；≥120 列才把规则 id 与位置拆成两列。
5. **机器输出干净。**`--format json|sarif` 时 stdout 只有结构化结果，其余走 stderr。
6. **空结果、失败、未完成，都要给下一步。**
7. **不生成文案。**所有面向用户的文字来自 i18n 字典或规则文件，运行时不做任何文本生成。

---

## 2. 条目结构

```
  ● CRITICAL   secret/frontend-env ············· 12:1
  11
  12  - export const STRIPE_KEY = "sk_live_51H••••••"
  12  + const stripe = new Stripe(process.env.STRIPE_SECRET_KEY)
  13  export default async function handler(req, res) {
    │ why  NEXT_PUBLIC_* is inlined into the browser bundle at build time.
      →    wrasse explain 1
```

结构：

| 部分 | 规则 |
|---|---|
| 标题 | 徽章 + 规则 id + 点线 + 位置；`needs_review` 在规则 id 前加 `?` |
| 边栏 | 最左一列放 `-` / `+`（像编辑器的改动标记）；行号单独一列，连续编号；上下文行的边栏留空 |
| 代码 | `-` / `+` 逐字来自源码，缩进跟随原行；上下文行不加符号 |
| why | **是标签，不是注释**——不写 `#` / `//`，避免被当成可粘贴代码 |
| 动作 | `wrasse explain 1`，用序号；id 只在 explain 页出现 |

上下文规则：

- 结果页默认**前后各 2 行**，`--context N` 可调（0 关闭，上限 20）；
- `explain` / `review` 默认各 5 行，`c` 键 ±5；
- `json` / `sarif` 为 0 行；
- **跨不过去就断开**：窗口内遇到文件首尾，或中间跳过超过 3 行才到修正点，直接不显示上下文——"看似连续"比没有更误导。

排版规则：

- **条目内部不空行**，靠缩进分层；只在**条目之间**空一行。
- **不用 `---` 分隔**——每条 finding 里已经有 `-` 开头的删除行，分隔线会和它读混。
- **缩进的空格必须在颜色范围之外打印**，否则背景色带会从行首铺到代码中间。
- `needs_review` 的 why 后多一行，写清**缺什么**而不是写"待确认"：
  `no owner_id constraint here; the check may live in a service or gateway.`

**修复行的写法约束**（这一条决定产品质感）：

- 密钥类：换成环境变量读取，并在 why 里提示**先轮换再改代码**；
- 路径类：换成 `resolve()` + `is_relative_to` 边界检查，不写"加个校验"这种空话；
- SQL 类：换成参数化写法，保留原变量名；
- 授权类：在查询上补约束（`owner_id=user.id`），不改成"加个 if"；
- 无法给出通用修复时：`+` 行写 `# manual review required`，并在 why 里说明为什么不能自动给。

---

## 3. 符号与颜色

| 符号 | 含义 | ASCII 降级 |
|---|---|---|
| `●` | 严重度 / 通过 | `*` |
| `-` / `+` | 问题行 / 修复行 | 不变 |
| `→` | 下一步 | `->` |
| `·` | 分隔 | `-` |
| `├ └ ─` | 树形与分组 | `+ \| -` |

| 用途 | 值 |
|---|---|
| critical | `#f85149` |
| high | `#f0883e` |
| medium | `#d29922` |
| low | `#58a6ff` |
| 通过 | `#3fb950` |
| 问题行 | 前景 `#ffa198`，背景 `#3d1d1d` |
| 修复行 | 前景 `#7ee787`，背景 `#12301f` |
| 路径 / 次要 | `#8b949e` / `#6e7681` |

只用 256 色；`NO_COLOR` 优先于一切；背景高亮只用于 `-` / `+` 两行，一屏不超过 6 组。

### 3.1 严重度与状态词表

| 级别 | en | zh | 进 `--fail-on high` | 界面标记 |
|---|---|---|---|:---:|
| 1 | CRITICAL | 严重 | 是 | — |
| 2 | HIGH | 高危 | 是 | — |
| 3 | MEDIUM | 中危 | 否（默认） | — |
| 4 | LOW | 低危 | 否 | — |
| 状态 | confirmed | 已确认 | 按级别 | 不标 |
| 状态 | needs_review | 待确认 | **永不拦** | `?` |

两条规则：

- **英文级别词不改**：Critical / High / Medium / Low 是 CVSS、GitHub、Snyk、Trivy 的通用语言，改了每次都要额外解释。
- **中文用"高 / 中 / 低危"**，不用单字——"高"在中文里不成词，且"严重"与"高"的层级关系不直观。

`confirmed` 是默认状态，标出来就是噪声；只标例外。这样"为什么这条 HIGH 没拦 CI"在界面上能自答。

---

## 4. 宽度适配

| 宽度 | 变化 |
|---|---|
| < 80 | 省规则 id 与点线；修复行过长时换行，不截断 |
| 80–119 | 标准 |
| ≥ 120 | 规则 id 与位置两列对齐；why 可与 `+` 行同行 |

分组标题的填充线用**固定长度**（`────` × 12），不计算到行尾——中文占 2 列，stdlib 没有 wcwidth，按列对齐必然错位。

---

## 5. 输出通道

| 场景 | stdout | stderr |
|---|---|---|
| 人读（默认） | 结果 | 进度、警告 |
| `--format json` / `sarif` | 只有结构化结果 | 其余全部 |
| 非 TTY / CI | 同上，无颜色、无进度、单行摘要 | 同上 |
| `--format html -o f` | 一行文件路径 | 进度 |

---

## 6. 交互：启动、命令面板与 review

### 6.0 启动（无参数）

`wrasse` 在 TTY 下启动 REPL；`wrasse <command>` 仍是一次性执行，供脚本与 CI 使用。

```
  ></>  wrasse 1.0.0
       Jiaming Shi · python 3.12 · rules 2026.11.1 (20)
       config .wrasse/config.json · lang zh · context 2
       ~/code/shop

  last scan 2h ago · 3 findings · 1 critical

  [1] ● CRITICAL  secret/frontend-env         billing.ts:12
  [2] ● HIGH      error/stack-to-client       billing.ts:88
  [3] ● HIGH ?    authz/query-without-owner   orders.py:44

  /audit rescans · `o 1` opens the first · ? help · q quit
  ────────────────────────────────────────────────────────────
  › ▏
  ────────────────────────────────────────────────────────────
  rules 2026.11.1 · standard · privacy+ai · fail-on high
```

五段各有分工：

| 段 | 内容 | 为什么 |
|---|---|---|
| 头部四行 | `></>` + 名称 / 版本 · 作者 · Python · **规则集版本** / 配置来源 / 当前路径 | 同一条 finding 在不同规则版本下结论可能不同；配置值要能追到出处 |
| 上次扫描 | 多久之前 · 几条 · 几条严重 | "数据的年龄"是安全工具最容易被忽略的状态 |
| 列表 | 编号 · 严重度 · 规则 · 位置 | 进去就有东西可做，不是一个空提示符 |
| 输入区 | 上下各一条横线，光标停在中间那行 | 提示语放在**上横线之上**；壳里直接接受完整命令（`audit . --offline`），不必先记简写 |
| 状态行 | rules · mode · focus · fail-on | 这些参数会改变结果，必须常驻可见，不能藏进 `--help` |

约束：

- 符号固定 `></>`，写成一行放在名称左侧；版本从 `1.0.0` 起（不玩 0.x）。
- **非 TTY / CI / `--quiet` / `WRASSE_QUIET=1` 下不显示横幅，也不进 REPL**，直接打印 help；
- 壳内命令可以短到两三个字母（`/au`、`/r`、`o 3`），因为它们不出这个命名空间；
- 启动时清屏（`WRASSE_NO_CLEAR=1` 可关）；`q`、`exit`、`Ctrl-C`、`Ctrl-D` 都是一次退出；
- 配置值来自默认值时标 `(default)`——消掉"我明明改了配置却没生效"这一整类困惑；
- 壳里输入自然语言时不猜，直说：`wrasse doesn't parse natural language. try /audit, or ? for commands.`

### 6.1 命令面板

`wrasse` 无参数启动时进入面板，而不是打印 help。这是唯一使用原始按键的地方。

```
$ wrasse

  ▸ audit .            scan the project — privacy + AI pitfalls
    preflight .        check agent config before opening a repo
    review             step through findings one by one
    open <n|id>        jump to a finding
    explain <n|id>     evidence and fix for one finding
    completion         print a shell completion script

  filter: au▏                                    ↑↓ enter esc
```

- **模糊匹配是子序列**，不是前缀：`apf` 能命中 `audit` / `preflight`；打分 = 连续命中长度 + 词首命中，同分按字母序。
- 每条带一行说明，说明来自 i18n 字典。
- 子命令缺少必填参数时也弹面板：`wrasse open` 直接列出 findings。

```bash
wrasse open
  ▸ [1] CRITICAL  secret/frontend-env        billing.ts:12
    [2] HIGH      authz/query-without-owner  orders.py:44
```

**降级**（三条，按顺序判断）：

1. `stdout` 不是 TTY → 打印普通 help，不进面板；
2. `--no-tui` 或 `WRASSE_NO_TUI=1` → 行模式：输入一行过滤词后回车，打印结果，再输入序号；
3. 面板只重绘**一列列表**，不做全屏布局——每行固定截断到显示宽度，绕开中文列宽问题。

**可测试性**：`filter(entries, query) -> list` 必须是纯函数，按键循环只是外壳。测试给它一串假按键，断言最终选中项。

### 6.2 `review`

review = 同一个面板 + 一个详情区（证据、修复、提示词）。

| 键 | 动作 |
|---|---|
| `↑↓` / 字母 | 移动 / 过滤列表 |
| `Enter` | 编辑器打开到该行 |
| `y` | 复制 `path:line` |
| `e` | 复制**预设提示词**（见 §7） |
| `esc` | 返回列表 / 退出 |
| `q` | 退出 |

`d`（忽略）是计划里的动作：它要把"改判"和"浏览"分开，当前版本尚未实现，也没有对应的 `wrasse dismiss`。

**人输序号，机器用 id**：`wrasse open 3` / `wrasse explain 3` 指向最近一次 `audit` 的第 3 条，编号与结果页一致。`WR-7f21a` 这种稳定 id 只用于日志、基线和脚本。

---

## 7. 预设提示词

存在规则文件里，20 条规则 = 20 条提示词，和规则同版本、同 review：

```toml
[[rule]]
id    = "authz/query-without-owner"
prompt = { en = """
Fix an authorization gap in {{file}}:{{line}}.
{{snippet}} loads an object by a caller-supplied id and never checks
ownership. Add an owner_id/tenant constraint and a regression test proving
another user's object returns 404. Keep the response model unchanged.
""" }
```

占位符只有三个：`{{file}}` `{{line}}` `{{snippet}}`。填充后原样复制，**不做改写、不调模型**。

---

## 8. 双语

| 内容 | 来源 | 缺省 |
|---|---|---|
| 界面文案 | `i18n/en.json` · `zh.json` | en |
| 规则标题 / 说明 | 规则文件 `title.en/zh` | en |
| 修复提示词 | 规则文件 `prompt.en/zh` | en |
| 证据、代码、路径 | 不翻译 | — |

切换：`wrasse config set lang zh` 写进 `.wrasse/config.json`，之后一直生效；`--lang zh` 只覆盖这一次。会话里用 `/config`（`↑↓` 选、`Enter` 换值）。

缺 key 时回退英文并打一条 warning，**不静默显示空字符串**。

---

## 9. 四种终态

| 终态 | 必须包含 |
|---|---|
| 有发现 | 计数、分组、五块条目、下一步 |
| 无发现 | 检查了什么、**没覆盖什么**、如何查深一点 |
| 未完成（码 4） | 完成了什么、断在哪、如何补上 |
| 出错（码 1/3） | 一行原因 + "这不代表没有问题" |

---

## 10. 不做

- 不做全屏 TUI、不做鼠标、不做动画；
- 不在终端渲染 Markdown/HTML；
- 不做"AI 解释"按钮——没有模型可调；
- 不为了对齐引入 wcwidth 类依赖；
- 不生成任何面向用户的文字。
