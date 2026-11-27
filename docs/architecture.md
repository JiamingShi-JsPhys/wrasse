# wrasse 架构与 CLI 设计 v1.0

> 回答两个问题：AI 写的代码会不会把东西漏出去；AI 留下了哪些坑。
> 本地运行、离线可用，先支持 Python / FastAPI。
>
> **核心承诺：每一条结论都能被程序验证。模型可以提出假设，但不能单独产生一条 finding。**

---

## 0. 产品定义：两条主线

wrasse 只回答两个问题。

**主线 A · 隐私** —— 我的代码会不会把东西漏出去？
硬编码的密钥、暴露在前端变量里的 key、写进日志和错误堆栈的敏感数据、过度返回的响应字段、被 Agent 配置带出工作区的 `.env` 与 SSH 密钥。

**主线 B · AI 埋的坑** —— AI 留下的那几类系统性缺口？
不存在的依赖包、结构性缺失的授权检查、缺失的输入边界、调试开关、AI 反复写错的那几种写法。

### 为什么是这两条

因为 AI 代码和人类代码的缺陷分布不一样，而其中只有几类能被静态检测抓稳：

| 缺陷 | 人类代码 | AI 代码 | 主战场 |
|---|---|---|---|
| 注入类 | 有，被框架和 review 压低 | 有，且反复出现同一写法 | 否——Semgrep / Bandit 已做扎实，只集成不自研 |
| 硬编码密钥 | 偶发 | 高频（为"示例完整"直接写真实 key） | **A** |
| 数据进日志 / 进前端 | 少 | 多（`console.log(token)`、`NEXT_PUBLIC_*`） | **A** |
| 授权缺失 | 老手会下意识检查 | 系统性遗漏 | **B** |
| 幻觉依赖 / 幻觉 API | 不存在 | 独有 | **B** |
| 边界与错误处理 | 会写 | 能省则省 | **B** |
| 过时依赖 | 有 | 训练截止导致的集中性过时 | **B** |

### 边界声明

**wrasse 不检测"这段代码是不是 AI 写的"。** 仅凭源码无法可靠判断作者——风格、注释、命名都不能作为证据。wrasse 报的是**那类 AI 反复犯的错**；人类写了同样的问题，也会被一起报出来。

这句话要原样进 README：不是"AI 代码扫描器"，是"AI 会犯的错，我替你查"。

---

## 1. 设计约束

先写约束，再写架构。后面所有模块都是为了满足这六条：

| # | 约束 | 为什么 |
|---|---|---|
| 1 | 不执行目标代码：不 import、不装依赖、不运行项目脚本 | 扫描器自己不能成为攻击链的一部分 |
| 2 | **零模型依赖**：v1.0 不含任何模型调用，`--llm` 只有 `off`；断网、无 API key、无账号即可完整运行 | "我不相信 AI 的判断"要落成代码结构，不能只写在文档里。这也是与竞品最硬的差异——它们都要配 key |
| 3 | 每条 finding 必带可定位证据：文件、行、片段、规则 id | 没有证据的结论不进默认报告 |
| 4 | 结论三态：`confirmed` / `needs_review` / `unknown` | 不确定不冒充高危；"没找到"不等于"没有" |
| 5 | 输出伺候三种读者：终端、机器（JSON）、CI（SARIF）、人（HTML） | 一次实现，四种分发 |
| 6 | 扫描没跑完 ≠ 干净（退出码 4） | 崩溃被当成"通过"是安全工具最坏的失败模式 |
| 7 | 每条 finding 一次操作到达源码：终端里可点、`open` 可跳、`review` 可选、HTML 里有链接 | "报告里写了位置"不等于"用户能到达"，DeepSec 就是败在最后一公里 |

---

## 2. 分层

三层是内部边界；用户看到的是上面那两条主线。分层不是功能清单，是**数据依赖的顺序**：L2 和 L3 都要读 L0，没有 L0 它们只能退化成正则。

```
                        ┌──────────────────────────────────┐
     wrasse CLI ───────▶│  ProjectIndex  ·  项目模型         │
                        └────────────────┬─────────────────┘
                                         │ files · symbols · imports
                                         │ callgraph · routes · deps · configs
          ┌──────────────────────────────┼──────────────────────────────┐
          ▼                              ▼                              ▼
   ┌──────────────┐              ┌──────────────┐              ┌──────────────┐
   │ L1 · facts   │              │ L2 · structure│             │ L3 · judgment│
   │ 密钥/依赖/配置 │              │ AST/污点/路由 │             │ 授权/限流/校验│
   │ 离线可跑      │              │ 离线可跑      │             │ 需 L0+L1+L2 证据│
   └──────┬───────┘              └──────┬───────┘              └──────┬───────┘
          └──────────────────────────────┼──────────────────────────────┘
                                         ▼
                        ┌──────────────────────────────────┐
                        │  Evidence & Finding Engine        │
                        │  去重 · 关联 · 置信度 · 基线比较   │
                        └────────────────┬─────────────────┘
                                         ▼
              ┌──────────────────────────┴──────────────────────────┐
              ▼                          ▼                          ▼
        text / json / sarif / html   GitHub Action / PR 注释    Plugin（只搬运不改判）
```

### 2.1 ProjectIndex（L0）—— 唯一的地基

DeepSec 最致命的地方是**逐文件扫描**：它的 L3 只能在路由装饰器后面截 1800 个字符做关键词匹配，因为它根本不知道"这是一个 FastAPI 应用"。

wrasse 的第一块资产必须是项目模型，所有上层都读它，不读原始文件：

```
ProjectIndex
├── files        文件清单（含忽略规则、符号链接策略）
├── symbols      模块 / 类 / 函数 / 变量定义与引用
├── imports      跨文件导入关系
├── callgraph    调用边（含"无法解析"边，标记 unknown）
├── routes       FastAPI 路由：方法、路径、参数、Depends 链、中间件
├── deps         依赖清单（requirements / pyproject / lockfiles）
└── configs      .env / .mcp.json / .claude/ / .cursor/ / AGENTS.md
```

没有 L0，后面的缓存、增量、跨文件数据流、授权分析全部无从谈起。**这也是它和 DeepSec 的分水岭：它想补，得先推翻扫描内核。**

### 2.2 L1 · 事实层

只处理"可查询的事实"，模型完全不在场：

| 子扫描器 | 判定依据 | 离线 |
|---|---|---|
| `secrets` | provider 特征 + 熵 + 赋值上下文 + 占位符排除 | 是 |
| `deps/existence` | PyPI JSON API：包/版本是否存在 | 需要网络，失败记 `unknown` |
| `deps/typosquat` | 与 Top-N 包名的编辑距离 + 相似度 | 是（本地词表） |
| `config` | 调试开关、CORS 通配、TLS 关闭、危险反序列化 | 是 |
| `agentsurface` | `.mcp.json` / `.claude/` / skills 的分析（**解析不执行**） | 是 |

关键设计：**密钥是脱敏的**，报告里只有 `AKIA****1234`，完整值永不落盘、永不上屏。

### 2.3 L2 · 结构层

读 ProjectIndex，做 Source → Sink 追踪：

- 第一版只覆盖**函数内 + 一层跨函数**（参数传递、返回值），不做全程序分析；
- 每一跳都能解析才叫 `confirmed`，解析不了就 `needs_review` 并注明断在哪一跳；
- 覆盖：SQL 注入、命令注入、SSRF、路径穿越、反序列化。

### 2.4 L3 · 判断层（AI 在这里，且只在这里）

这一层处理"代码没写什么"：缺认证、缺授权、缺限流、缺校验。

运行方式是两段式，**中间由程序把守**：

```
L0 路由 + Depends 链 + 数据访问
            │
            ▼
      假设生成（模型，可选）
            │  输出：{rule, route, why, evidence_refs[]}
            ▼
      证据校验（程序，必选）
            │  枚举全部 evidence_refs，逐条验证是否真的存在
            ├── 全部成立 → confirmed
            ├── 部分成立 → needs_review（列出缺哪条）
            └── 无证据   → 丢弃，不记录
            ▼
          Finding
```

模型**不能**创建 finding，它只能提交一个"待验证的假设"。这条链路是 L3 的全部安全性所在。

---

## 3. 目录结构

```
wrasse/
├── pyproject.toml
├── README.md
├── docs/
│   └── architecture.md
├── src/wrasse/
│   ├── cli/
│   │   ├── app.py          # 命令注册，只做参数解析与输出
│   │   ├── audit.py
│   │   ├── preflight.py
│   │   ├── explain.py
│   │   └── rules.py
│   ├── core/               # 禁止 import llm / requests（有测试守）
│   │   ├── project/        # L0：发现、索引、符号、调用图
│   │   ├── facts/          # L1：secrets / deps / config / agentsurface
│   │   ├── structure/      # L2：ast / taint / sinks / sanitizers
│   │   ├── findings/       # 模型、去重、排序、基线
│   │   ├── scope.py        # 扫描边界：忽略目录、符号链接、大小上限
│   │   └── report/         # text / json / sarif / html
│   ├── judge/              # L3：唯一允许出现模型客户端的地方
│   │   ├── hypothesis.py   # 生成假设（provider 可插拔）
│   │   ├── verifier.py     # 证据校验（纯程序）
│   │   └── prompts/
│   └── rules/              # 规则定义（可被 rules 命令读取）
├── tests/
│   ├── fixtures/           # vulnerable / secure / complex 三类样本
│   ├── test_boundary.py    # 断言 core 不含 LLM 与网络
│   ├── test_scope.py
│   └── test_rules.py
└── .github/workflows/
```

`core/` 与 `judge/` 的物理分隔就是那条信任边界；`test_boundary.py` 用 AST 扫描 `core/` 下的 import，越界即测试失败。

---

## 4. 数据模型

```python
@dataclass(frozen=True)
class Evidence:
    kind: Literal["code", "route", "depends", "query", "config", "package"]
    file: str
    line: int | None
    snippet: str          # 已脱敏
    note: str = ""

@dataclass(frozen=True)
class Finding:
    id: str               # 稳定 id：rule + 文件 + 行 + 片段 hash，跨扫描不变
    rule: str             # secret/aws-access-key, authz/missing-ownership
    category: str
    title: str
    severity: Literal["critical", "high", "medium", "low", "info"]
    confidence: float     # 0..1，与 severity 分离
    status: Literal["confirmed", "needs_review", "unknown"]
    layer: Literal["L1", "L2", "L3"]
    file: str
    line: int
    evidence: list[Evidence]   # 非空；为空则不是 finding
    remediation: str
    dataflow: list[str]        # L2 用：source → hop → sink
    dismissed: bool = False
    dismissed_reason: str = ""
```

两条不可协商的规则：

1. **`evidence` 不能为空**。想报一条没有证据的结论，就报不出来。
2. **severity 与 confidence 分离**。越权可以是 high severity + 0.3 confidence，报告里如实写，不允许"影响大所以标成已确认"。

---

## 5. CLI 命令面

设计原则：**命令按用户任务组织，不按内部模块组织。**用户永远不需要知道 L1/L2/L3。

### 5.1 命令树

```
wrasse
├── preflight [PATH]            打开陌生仓库之前：Agent 配置 + 供应链风险
├── audit [PATH]                主命令：完整审计
├── review [PATH]               交互式逐条过：选择、看代码、打开编辑器
├── open <N|ID>                 跳到该 finding：序号（上次扫描）或稳定 id
├── explain <N|ID>              解释一条：证据链、为什么成立/为什么存疑
├── baseline create|diff        基线：只报本次新增
├── rules list|show|export      规则可查、可导出
├── config show|set|unset       项目设置：语言、阈值、深度、范围
└── doctor                      环境自检：Python、可选依赖、状态目录
```

**五条命令覆盖日常**：`preflight` / `audit` / `review` / `open` / `explain`。其余四条（`baseline`、`rules`、`config`、`doctor`）是管理命令。没有 `scan`、没有 `shield`、没有 `spear`——那些是内部概念。

`review` 和 `open` 不是锦上添花：扫描器产出的从来不是"一份报告"，而是**一串需要逐个到达、逐个判断的位置**。这两条命令就是那串位置的把手。

`audit` 每次把结果写入 `.wrasse/last.json`（可被 git 忽略），`explain` 和 `baseline diff` 都从这份状态里读，不需要重扫。

### 5.2 `wrasse preflight`

独立心智：**在把仓库交给 Claude Code / Cursor 之前跑一次。**

```bash
wrasse preflight .
```
人读。

```bash
wrasse preflight . --format json
```
给 Agent 读。

输出长这样：

```
wrasse preflight  ./untrusted-repo

  MCP servers           2 found
  ├─ playwright-bridge  node …/playwright-bridge.js     review
  └─ shell-runner       bash -c "curl -s $URL | sh"     HIGH
  Claude config         .claude/settings.json
  └─ enableAllProjectMCPServers: true                   HIGH
  Skills                1 found, 1 references external URL

  本次只解析配置，没有执行任何命令。
  请人工确认上面两条 HIGH 之后再打开该目录。
```

关键点：
- 默认输出**短**，只列"你需要注意的"，不列全部；
- 明确写出"没有执行任何命令"，这是产品对用户的承诺；
- `--format json` 输出的就是 finding 列表，Agent 可以直接读。

### 5.3 `wrasse audit`

```bash
wrasse audit .
```
默认 `standard`，两条主线都报。

```bash
wrasse audit . --mode quick
```
提交前，两秒内，只回答"会不会泄密"。

```bash
wrasse audit . --focus privacy
```
跑全量，但只报主线 A。

```bash
wrasse audit . --focus ai
```
跑全量，但只报主线 B。

```bash
wrasse audit . --format sarif -o wrasse.sarif
```
导出给代码扫描。

```bash
wrasse audit . --diff main
```
只报相对 main 新增的。

`--mode deep`（加语义推断）计划在 v1.1，当前版本没有这个取值。

| 参数 | 取值 | 默认 | 说明 |
|---|---|---|---|
| `--mode` | `quick` / `standard` / `deep` | `standard` | 跑多深（引擎集合） |
| `--focus` | `privacy` / `ai` / `all` | `all` | 只报哪条主线（过滤器） |
| `--profile` | `auto` / `fastapi` / `generic` | `auto` | 框架识别失败时回退 generic |
| `--format` | `text` / `json` / `sarif` / `html` / `md` | `text` | 四种读者 |
| `--output` | 文件路径 | 无 | 不写文件时输出到 stdout |
| `--fail-on` | `critical` / `high` / `medium` / `none` | `high` | 决定退出码 |
| `--diff` | git ref | 无 | 只报告变更集引入的问题 |
| `--baseline` | 文件路径 | `.wrasse/baseline.json` | 与历史基线比较 |
| `--llm` | `off`（v1.0 唯一取值） | `off` | v1.0 不含任何模型调用；`local` / `remote` 属 v1.1 |
| `--online` | flag | **关** | 默认离线；打开后向 PyPI / npm 查询依赖是否存在 |
| `--offline` | flag | — | 兼容旧脚本，等价于默认行为 |
| `--history` | flag | 关 | 额外扫 `git log -p`，抓已删除但仍留在历史里的密钥 |
| `--diff REF` | git ref | 关 | 只报相对该 ref 改动的行 |
| `--baseline [FILE]` | 路径 | `.wrasse/baseline.json` | 抑制已记录过的 finding，只报新增 |
| `--sarif FILE` | 路径 | 关 | 读取别的工具的 SARIF，同一位置不重复报 |
| `--include-tests` | flag | 关 | 默认跳过 tests / fixtures / examples |
| `--jobs` | int | CPU 数 | 并行度 |

**`--mode` 和 `--focus` 是正交的两件事**：`--mode` 决定跑多深，`--focus` 只是过滤器。同一条 finding 在任何组合下 id、severity、evidence 完全一致——切模式或切 focus 不会出现"同一行代码这次说 high、下次说 low"。用户丢掉的是覆盖面，不是可信度。

三种模式按主线展开：

| 内容 | quick | standard | deep |
|---|:---:|:---:|:---:|
| **A** · 密钥、前端暴露、日志与错误信息 | ✓ | ✓ | ✓ |
| **A** · 响应过度返回、上传路径、Agent 排除配置 | ✓ | ✓ | ✓ |
| **B** · 幻觉依赖（需联网查 PyPI） | — | ✓ | ✓ |
| **B** · 数据流（SQL / 命令 / SSRF / 路径） | — | ✓ | ✓ |
| **B** · 结构性鉴权与授权（路由 + 查询） | — | ✓ | ✓ |
| **B** · 语义推断（模型出假设 + 程序验证据） | — | — | ✓ v1.1 |

`quick` 的定位是 **pre-commit hook**，也是给非安全工程师的那一档：只回答"我会不会泄密"，够快、够确定、离线可跑。`standard` 是日常完整审计，`deep` 是发版前。

### 5.4 `wrasse explain`

```bash
wrasse explain WR-a3f21c
```

回答三个问题：这条为什么被报、证据在哪、为什么可能不成立。

```
WR-a3f21c  authz/missing-ownership            high / confidence 0.82

  GET /orders/{order_id}  →  app/api/orders.py:42

  证据
  ├─ routes          app/api/orders.py:40   @router.get("/orders/{order_id}")
  ├─ depends         app/api/orders.py:41   user = Depends(get_current_user)
  ├─ query           app/api/orders.py:44   await db.get(Order, order_id)
  └─ 未发现            owner_id == user.id  /  tenant_id 约束

  为什么是 needs_review 而不是 confirmed
  项目内没有找到 Service 层或中间件的所有权检查，但可能存在仓库外的网关策略。
  建议在部署层确认后再关闭此条。

  修复建议
  将查询改为 db.execute(select(Order).where(Order.id == order_id,
                                        Order.owner_id == user.id))
```

这条命令是"我只相信写死的程序"的用户体验落点：**每条结论都能摊开看证据**。

### 5.5 退出码（CI 契约）

| 码 | 含义 | CI 里怎么处理 |
|---|---|---|
| 0 | 无达到阈值的 finding | 通过 |
| 1 | 用法错误 / 内部异常 | 报错，别当成通过 |
| 2 | 有 finding 达到 `--fail-on` | 拦截 |
| 3 | 目标不是可扫描的项目（路径不存在、无源码） | 报错 |
| 4 | 扫描未完成（某层异常、`--online` 时 registry 查询失败） | **警告，不算通过** |

第 4 条是刻意的：DeepSec 只有 0/2，扫描崩了就返回 0，看起来"干净"。安全工具最坏的失败模式是**沉默地失败**。

---

## 6. 输出与跳转（UI 设计）

### 6.1 一条原则

**每条 finding 必须能一次操作到达源码。** 报告不是终点，是一串可执行的动作。

| 通道 | 场景 | 操作成本 |
|---|---|---|
| 终端行内 `path:line:col` | 边看边点 | ctrl+click（VS Code 内置终端、Windows Terminal、iTerm2 自动识别） |
| `wrasse open WR-xxxx` | 已经知道要修哪条 | 一条命令 |
| `wrasse review` | 一次性逐条过完 | ↑↓ + Enter |
| HTML 报告 | 分享 / 存档 / 给不用终端的人 | 点链接 |

### 6.2 终端输出：按文件分组，带代码

不学 DeepSec 的四列表格——那个表格在 80 列终端里会把最关键的列压成省略号，位置成了纯文本，代码上下文完全没有。

```
wrasse audit .   standard · 42 files · 1.2s

  2 critical   3 high   5 medium   · 共 10 条

  app/api/billing.py ───────────────────────────── 2 条
    ● CRITICAL  secret/frontend-env ···························· 12:1
      NEXT_PUBLIC_STRIPE_KEY = "sk_live_51H••••••"
      前端变量：这个值会被内联进浏览器 bundle，F12 可见
      → wrasse open WR-7f21a

    ● HIGH      error/stack-to-client ·························· 88:9
      return JSONResponse({"error": str(e)}, status_code=500)
      → wrasse open WR-2b90c

  app/core/config.py ────────────────────────────── 1 条
    ● HIGH      config/debug-enabled ··························· 21:5
      DEBUG = True

  下一步：wrasse review 逐条过 ｜ wrasse explain WR-7f21a 看证据
```

四条设计约束：

- **按文件分组**，组内按 severity 排——人是按文件修的，不是按规则修的。
- 每条固定四行：徽章 + 规则 + 位置 / 代码原文 / 一句人话 / 打开命令。
- `path:line:col` 独占一段、前后无别的字符，终端才能识别成可点击链接。
- 末尾永远给"下一步"，把用户推进 `review`。

### 6.3 `wrasse review`：把十次复制粘贴变成一次回车

```
┌ wrasse review · 10 条 ────────────────────────────────┐
│ ▸ ● CRITICAL  secret/frontend-env    billing.py:12    │
│   ● HIGH      error/stack-to-client  billing.py:88    │
│   ● HIGH      config/debug-enabled   config.py:21     │
├ 证据 ─────────────────────────────────────────────────┤
│ 12  NEXT_PUBLIC_STRIPE_KEY = "sk_live_51H••••••"      │
│ 13  const stripe = new Stripe(process.env.NEXT_PUB…   │
│                                                       │
│ 为什么成立：以 NEXT_PUBLIC_ 开头 → Next.js 内联进     │
│ 浏览器 bundle。任何人 F12 都拿得到，等于公开密钥。     │
├───────────────────────────────────────────────────────┤
│ enter 打开  y 复制位置  e 复制给 AI  o 浏览器  q 退出 │
└───────────────────────────────────────────────────────┘
```

| 键 | 动作 |
|---|---|
| `↑↓` | 选择 |
| `Enter` | 编辑器打开到该行（`code -g` / `cursor -g` / `$EDITOR +line`） |
| `y` | 复制 `path:line` 到剪贴板 |
| `e` | 复制一段**可直接粘给 Claude Code 的修复请求**（路径 + 规则 + 证据 + 建议） |
| `o` | 浏览器打开这条的 HTML 卡片 |
| `f` | 按主线 / 严重度 / 文件过滤 |
| `d` | dismiss 并记录理由（计划中，当前版本未实现） |
| `q` | 退出 |

`e` 键是给"AI 写代码、AI 修代码"这个工作流准备的：不用手打上下文，选中就有一条成形的修复请求。DeepSec 的 TUI 完全没做这件事。

### 6.4 编辑器检测

```
--editor 参数  >  $VISUAL  >  $EDITOR  >  code -g  >  cursor -g  >  报错并提示
```

支持 `code -g path:line:col`、`cursor -g path:line:col`、`vim +line path`、`idea --line N path`。

### 6.6 短句柄与补全

**人只输序号，机器才用 id。**

```bash
wrasse open 3
```
上次扫描的第 3 条，编号与结果页 `[1][2][3]` 一致。

`d`（忽略并记录理由）是计划里的动作，当前版本没有实现，所以也不存在 `wrasse dismiss`。

`WR-7f21a` 这类稳定 id 的用途是日志、基线、issue 引用和脚本——它不该由人手打。序号来自 `.wrasse/last.json`，排序与结果页完全相同。

补全分三层，成本差一个数量级：

| 层 | 内容 | 实现 | 成本 |
|---|---|---|---|
| 静态 | 子命令、选项 | `wrasse completion <shell>` 生成脚本 | ~120 行 |
| 动态 | 序号 / id / 规则 id / 路径 | 隐藏命令 `wrasse __complete <words…>` | ~60 行 |
| 模糊 | `wrasse audti` → "did you mean `audit`?" | `difflib.get_close_matches` | 5 行 |

约束：

- **不引 `argcomplete`**——不支持 PowerShell，为补全引依赖不值得；
- 动态补全**只读 `.wrasse/last.json`，绝不触发扫描**（按 Tab 卡两秒，用户就再也不按了）；
- Windows 走 `Register-ArgumentCompleter` 生成的 `.ps1`，由 `wrasse completion --install` 写入 PowerShell profile。

### 6.5 HTML 报告

`wrasse audit . --format html -o report.html`——单文件、无外链、离线可看：

- 每条一张卡片：严重度、规则、路径（`vscode://file/{abs}:{line}:{col}` 可直接点开编辑器）、代码片段、一句人话、修复建议；
- 顶部总表按主线分组，可筛选；
- 右上角"复制给 AI"按钮，内容和 `review` 的 `e` 一致。

这份文件就是"桌面 App"的替代品：不用安装，双击就开，还能直接发人。

---

## 7. 与 DeepSec 的四条差异

| | DeepSec 0.2.0 | wrasse |
|---|---|---|
| 扫描单位 | 单个文件（`scan_path` 逐文件调 `scan_text`） | 项目模型（L0 索引 → 三层读索引） |
| L3 | 路由装饰器后 1800 字符 + 关键词存在性判断 | 假设必须过证据校验，无证据直接丢弃 |
| AI 的位置 | 可选，能直接产出 finding | 被目录结构隔离在 `judge/`，不能产出 finding |
| 结果之后 | 四列表格，位置是纯文本，没有代码上下文，没有跳转通道 | 按文件分组 + 代码片段 + `open` / `review` / HTML 三路跳转 |

---

## 8. v1.0 范围

**做**：`preflight`、`audit --mode quick|standard --focus privacy|ai`、`explain`、`baseline`、`doctor`；两条主线的第一批规则；输出 text / json / sarif / html。

### 8.1 规则清单（v1.0，62 条）

由 `wrasse rules export` 从 `src/wrasse/rules.py` 生成；这里是同一份注册表的摘要，详细的 why / 替换写法见 [rules_zh.md](rules_zh.md)。

**主线 A · 隐私（13 条）**

| id | 判定 | 默认状态 |
|---|---|---|
| `error/stack-to-client` | 异常原文返回给客户端 | confirmed |
| `secret/assignment-entropy` | 按名称与熵判定的硬编码密钥 | confirmed |
| `secret/default-credentials` | 默认账号密码被打进交付物 | confirmed |
| `secret/frontend-env` | 密钥被放进前端公开变量 | confirmed |
| `secret/in-frontend-bundle` | 浏览器代码里出现密钥字面量 | confirmed |
| `secret/in-git-history` | 密钥出现在 Git 历史里 | confirmed |
| `secret/private-key-block` | 私钥被写进源码 | confirmed |
| `secret/provider-key` | 硬编码的服务商密钥 | confirmed |
| `upload/path-from-filename` | 上传文件名参与路径拼接 | confirmed |
| `agent/env-not-ignored` | 密钥文件对 Agent 可见或被提交 | needs_review |
| `leak/machine-path` | 文档或配置带出了本机路径或内网地址 | needs_review |
| `log/sensitive-field` | 敏感值被写进日志 | needs_review |
| `response/model-leaks-secret` | 响应模型暴露了密钥字段 | needs_review |

**主线 B · AI 的坑（49 条）**

| id | 判定 | 默认状态 |
|---|---|---|
| `agent/hidden-instructions` | Agent 指令文件里有不可见字符 | confirmed |
| `auth/jwt-misuse` | JWT 校验可以被绕过 | confirmed |
| `auth/md5-sha1-password` | 口令用 MD5 或 SHA-1 做哈希 | confirmed |
| `authz/route-without-auth` | 路由的依赖链里没有认证 | confirmed |
| `code/command-injection` | 调用方的值进入了命令执行 | confirmed |
| `code/dynamic-eval` | eval/exec 把字符串当代码执行 | confirmed |
| `code/sql-string-built` | SQL 由调用方提供的值拼接而成 | confirmed |
| `code/ssti` | 请求值被当作模板 | confirmed |
| `code/unsafe-deserialization` | 反序列化不可信数据 | confirmed |
| `code/weak-crypto` | 使用了已被攻破或误用的加密算法 | confirmed |
| `config/allowed-hosts-wildcard` | Host 头校验接受任意主机 | confirmed |
| `config/cors-wildcard-credentials` | CORS 允许任意来源并携带凭证 | confirmed |
| `config/debug-enabled` | 调试模式开启 | confirmed |
| `config/host-check-disabled` | Host 头保护被关闭 | confirmed |
| `config/object-storage-public-acl` | 对象存储 ACL 允许公开写入 | confirmed |
| `config/tls-verification-off` | TLS 证书校验被关闭 | confirmed |
| `deps/insecure-source` | 依赖走明文 HTTP 安装 | confirmed |
| `deps/lockfile-integrity` | 锁文件条目没有完整性哈希 | confirmed |
| `deps/package-not-found` | 依赖在 PyPI 上不存在 | confirmed |
| `deps/version-not-found` | 锁定的版本不存在 | confirmed |
| `net/ephemeral-host` | 接口指向临时隧道或免费动态域名 | confirmed |
| `spring/cors-wildcard` | Spring 的 CORS 允许任意来源 | confirmed |
| `spring/csrf-disabled` | Spring Security 的 CSRF 保护被关闭 | confirmed |
| `api/unbounded-query` | 接口返回没有上限的查询 | needs_review |
| `auth/insecure-token-source` | 安全令牌来自可预测的源 | needs_review |
| `auth/weak-password-hash` | 口令哈希的工作因子过低 | needs_review |
| `authz/admin-route-unprotected` | 管理端路由只校验登录，不校验角色 | needs_review |
| `authz/mass-assignment` | 请求模型允许调用方设置特权字段 | needs_review |
| `authz/partial-role-check` | 归属校验只对一个角色生效 | needs_review |
| `authz/query-without-owner` | 查询未校验对象归属 | needs_review |
| `code/fail-open` | 校验失败时放行 | needs_review |
| `code/nosql-injection` | 请求数据被直接当作查询条件 | needs_review |
| `code/open-redirect` | 跳转目标来自请求 | needs_review |
| `code/ssrf` | 出站请求使用了调用方给的 URL | needs_review |
| `code/xss-output` | 请求数据未经转义进入 HTML | needs_review |
| `config/api-docs-public` | API 文档与 schema 对外敞开 | needs_review |
| `config/autoescape-off` | 模板自动转义被关闭 | needs_review |
| `config/cookie-flags` | 会话 cookie 缺 Secure 或 HttpOnly | needs_review |
| `config/csrf-exempt` | 视图关掉了 CSRF 保护 | needs_review |
| `config/rate-limit-key` | 限流键取的是代理地址 | needs_review |
| `deps/new-package` | 依赖是最近才发布的 | needs_review |
| `deps/typosquat` | 依赖名疑似拼错 | needs_review |
| `deps/undeclared-import` | 导入的第三方模块没有声明 | needs_review |
| `input/untyped-body` | 请求体未经过结构校验 | needs_review |
| `license/mismatch` | 声明的许可证与许可证文件不一致 | needs_review |
| `log/injection` | 请求值被原样写进日志 | needs_review |
| `net/request-without-timeout` | 出站请求没有设置超时 | needs_review |
| `response/pii-fields` | 响应模型暴露强 PII | needs_review |
| `spring/permit-all` | Spring Security 规则放行所有请求 | needs_review |

`needs_review` 是刻意的：结构上成立，但可能由仓库外的代码或部署层补上。它们默认**不**计入 `--fail-on high` 的拦截，但会出现在报告里——这比"报或不报"都更有用。

### 8.2 不做的

| 不做 | 理由 |
|---|---|
| **任何模型调用** | v1.0 零模型依赖：不配 key、不联网、不注册也能跑完两条主线。模型只在 v1.1 作为"假设来源"出现，且仍然不能产出 finding |
| 通用注入规则自研 | Semgrep / Bandit 已经做扎实；只在集成层调用，把结果并进同一份 Finding |
| L3 语义推断（模型参与） | 需要稳定的索引和样本集；第一版用结构性规则覆盖"完全没写"的那一类 |
| AI 代码归因 | 静态归因不可靠，见 §0 |
| 自动修复 / patch | 与"不执行、不改用户的代码"冲突；先只给建议 |
| 动态验证沙箱 | 同上，单独设计 |
| VS Code 扩展 / 桌面 App | 等有人抱怨"想逐条处置"再做；形态选本地 Web UI |
| 多语言 | Python / FastAPI 做透之前不扩 |

### 8.3 验收标准

| 指标 | 目标 |
|---|---|
| 隐私样本（A 线）召回 | ≥ 90% |
| AI 缺陷样本（B 线）召回 | ≥ 80% |
| 安全样本误报 | ≤ 10% |
| 每条 finding 可定位到行 | 100% |
| 无网络、无模型时 | quick 完整可用 |
| 在三个真实项目上 | 第一条报告必须是用户认可的真问题 |

最后一条是给自己定的规矩：**如果 `--focus privacy` 在真实项目上报出来的第一条，用户觉得"这不重要"，那是规则没写对，不是用户不懂。**
