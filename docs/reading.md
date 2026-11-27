# 怎么看 wrasse 的报告

> 本文用 `examples/playground` 的真实输出讲。你自己跑一遍对照着看最有效：
>
> ```powershell
> wrasse audit examples/playground --offline
> ```

---

## 一、一份完整输出

```
wrasse audit examples/playground   standard · 6 files · context 2 · 0.0s

  1 critical   8 high   2 medium   · 11 findings

  app/billing.ts ───────────────────────────────────────────────────── 1

    ● CRITICAL   secret/frontend-env ............................... 7:1
      5  export const publicConfig = {
      6    publishable: process.env.NEXT_PUBLIC_STRIPE_PUBLISHABLE,
      -   NEXT_PUBLIC_STRIPE_SECRET: "sk_l••••00",
      +   // server-side only — never expose this secret to the browser
      8  };
      9
    │ why  NEXT_PUBLIC_/VITE_/REACT_APP_ variables are inlined into the browser bundle.
        →    wrasse explain 1

  app/main.py ─────────────────────────────────────────────────────── 5

    ● HIGH   authz/route-without-auth ............................. 11:1
      ...
```

---

## 二、第一行：这次扫描是怎么跑的

```
wrasse audit examples/playground   standard · 6 files · context 2 · 0.0s
└──────────┬──────────────────┘   └───┬───┘  └──┬──┘   └───┬───┘  └─┬─┘
        你敲的命令                 模式    扫了几个文件  上下文行数  耗时
```

| 字段 | 含义 | 注意 |
|---|---|---|
| **standard** | 扫描深度。`quick` 只跑隐私线，`standard` 加数据流和授权 | 决定了 `.wrasse/last.json` 里存的是什么 |
| **6 files** | 实际读过的文件数，已排除 `.git` / `node_modules` / `.venv` / `tests` / 构建产物 | 加 `--include-tests` 会把测试目录算进来 |
| **context 2** | 每条 finding 上下各显示 2 行源码 | `--context 0` 关掉，`--context 5` 加宽 |
| **0.0s** | 解析 + 检测的总耗时，不含输出渲染 | 2500 文件的真实项目约 4 秒 |

---

## 三、第二行：一共多少、多严重

```
  1 critical   8 high   2 medium   · 11 findings
  └┬┘          └┬─┘   └──┬──┘     └──────┬──────┘
按严重度分组计数            总条数
```

四个级别，对应国际通用分类，**不自己发明**：

| 英文 | 中文（`--lang zh`） | 什么算这个级别 | 会不会拦 CI |
|---|---|---|:---:|
| `CRITICAL` | 严重 | 密钥已经暴露、任意代码执行 | 会 |
| `HIGH` | 高危 | 未授权访问、注入、路径穿越 | 会（默认阈值） |
| `MEDIUM` | 中危 | 需要更多条件才成立的泄露 | 不会 |
| `LOW` | 低危 | 信息性问题 | 不会 |

分组里只显示**实际出现过的级别**——全是 high 就不会出现 `0 critical` 这种噪声。

**总条数 ≠ 你打开文件要改的地方数**：同一个文件里 5 条就是 5 处，但同一个文件的同一行只会报一条（见第八节）。

---

## 四、文件名那一行

```
  app/billing.ts ───────────────────────────────────────────────────── 1
  └─────┬──────┘                                                    └┬┘
      相对路径                                               这个文件里有几条
```

- 路径相对于**你扫描的那个目录**，不是相对磁盘根——所以可以直接复制去打开。
- 条目**按文件分组、组内按严重度排序**。因为人是按文件改代码的，不是按规则改。
- 右边的数字是**这个文件里的条数**，和总数是两回事。

---

## 五、一条 finding：七个部分

```
    ● HIGH  ?  authz/query-without-owner ......................... 44:9
    │  │    │  └──────────┬───────────┘                          └┬─┘
    │  │    │         规则 id                                   行:列
    │  │    └─ 状态标记（只有 needs_review 才有）
    │  └────── 严重度
    └───────── 严重度圆点（颜色载体）
    42      """Return one order."""
    43
    -     order = await db.get(Order, order_id)
    +     order = await db.scalar(select(Order).where(Order.id == order_id, ...))
    45      return order
    │ why  A caller-supplied id reaches the database; no owner/tenant constraint …
        ?    no owner/tenant constraint in this function
        →    wrasse explain 3
```

| 部分 | 含义 |
|---|---|
| `●` + 级别 | 严重度，颜色只在 `●` 上，不影响可读性（`NO_COLOR=1` 也完整） |
| `?` | **needs_review**：结构上成立，但可能由仓库外的代码补上。默认不拦 CI |
| 规则 id | 形如 `类别/名称`。`wrasse rules show authz/query-without-owner` 看完整说明 |
| `·····` | 只是对齐用的填充，没有含义 |
| `44:9` | **第 44 行第 9 列**，不是字节偏移 |
| `42` `43` `45` | 上下文行的**真实行号**，灰色 |
| `-` 行 | 现在的问题代码，**逐字来自你的文件**（密钥已脱敏） |
| `+` 行 | **已验证的替换**：语法上能直接粘贴，不引入新标识符 |
| `~` 行 | **模板**：形状对，但要按你的上下文改（变量名、导入、框架） |
| `!` 行 | **没有自动修复**：这条要人判断，绿行只是说明 |
| `why` | 一句人话：为什么这是个问题、后果是什么 |
| `?` 行 | 只对 needs_review 出现：**缺了什么**，而不是只说"待确认" |
| `→` | 一条立即可跑的命令，不是提示 |

### 行号的三个细节

1. **`-` 和 `+` 用同一套行号**：替换首行同号；`+` 行若多于一行，后面的行号依次递增。
2. 上下文里如果**跳过了超过 3 行**才到问题点，就不显示上下文，避免"看似连续"。
3. `44:9` 里的 9 是**列**。多行调用被截断时，`-` 行末尾会有 `…`，表示源码还有下文。

---

## 六、严重度 vs 状态：两个不同的数字感

这是 wrasse 和多数扫描器最不一样的地方：

| | 回答的问题 | 例子 |
|---|---|---|
| **severity** | 如果这条成立，后果多严重 | 越权读别人的订单 = high |
| **status** | 我们有多大把握它真的成立 | 只看到静态结构，没看到别处的检查 = needs_review |

所以会出现 `HIGH ?` —— **"很严重，但我不能替你确认"**。这种条目：

- 会出现在报告里（你该看一眼）
- 默认**不**让 CI 失败（否则你迟早会关掉它）
- `wrasse explain N` 会写清"缺哪条证据"

反过来，`CRITICAL` 没有 `?`，意味着证据链完整、可以直接改。

---

## 七、尾部两行

```
────────────────────────────────────────────────────────────────────
  next  wrasse review   ·   --format html -o report.html
```

- `wrasse review`：逐条过（这是处理 findings 的主入口）
- `--format html`：生成一份可以发给别人的单文件报告

如果这次扫描有**无法判定的部分**，还会多一行：

```
  unknown: 2 package(s) could not be checked (offline?)
```

这时退出码是 **4**，不是 0 —— 见下节。

---

## 八、为什么条数会变

| 你看到的 | 原因 |
|---|---|
| `--focus privacy` 只有 4 条 | 那条主线只含 A 线规则（密钥、前端、日志、错误、上传、Agent 配置） |
| `--focus ai` 有 7 条 | B 线：授权、数据流、依赖、配置 |
| `--mode quick` 只有 3 条 | quick 不跑数据流，所以"上传路径"那条不出现 |
| 同一行只报一条 | 同一行命中多条规则时，保留最具体的那条（密钥泄露优先于通用规则） |
| 文件里明明有 `str(e)` 却没报 | 文档、示例、测试目录默认跳过；`.md` 里只查真实密钥格式 |

---

## 九、退出码：CI 用这个判断

| 码 | 含义 | CI 里怎么办 |
|---|---|---|
| `0` | 干净 | 通过 |
| `1` | 用法错误 / 内部异常 | 报错，别当通过 |
| `2` | 有 finding 达到 `--fail-on`（默认 high） | 拦截 |
| `3` | 不是可扫描的项目（路径不存在 / 没有源码） | 报错 |
| **`4`** | **扫描没跑完**（离线时依赖无法判定、某层异常） | **警告，不算通过** |

第 4 条是刻意的：安全工具最坏的失败方式是**沉默地失败**——扫崩了却看起来"干净"。

---

## 十、命令列表

### 日常四条

| 命令 | 作用 |
|---|---|
| `wrasse` | 进交互会话（清屏、显示上次扫描、输入框在两条横线之间） |
| `wrasse preflight .` | 打开陌生仓库之前：只看 Agent 配置，**不执行任何命令** |
| `wrasse audit .` | 扫描 |
| `wrasse review .` | 逐条过：数字选中、`enter` 打开、`y` 复制位置、`e` 复制提示词 |

### 跳转与解释

| 命令 | 作用 |
|---|---|
| `wrasse open 3` | 在编辑器打开第 3 条（也接受 `WR-7f21a` 这样的 id） |
| `wrasse explain 3` | 打印证据链、为什么成立/存疑、修复建议 |
| `wrasse rules` | 列出全部规则 |
| `wrasse rules show authz/query-without-owner` | 看某条规则的判定与提示词 |
| `wrasse doctor` | 环境自检（Python、规则数、编辑器） |

### `audit` 的全部参数

| 参数 | 取值 | 默认 | 说明 |
|---|---|---|---|
| `--mode` | `quick` / `standard` | `standard` | 跑多深 |
| `--focus` | `privacy` / `ai` / `all` | `all` | 只报哪条主线（过滤器，不改判定） |
| `--format` | `text` / `json` / `sarif` / `html` | `text` | 四种读者 |
| `--output` `-o` | 文件路径 | 无 | 不写就输出到终端 |
| `--context` | 整数 | `2` | 上下各几行；`0` 关闭 |
| `--lang` | `en` / `zh` | 见 `.wrasse/config.json` | 只覆盖这一次；长期设置用 `wrasse config set lang zh` |
| `--fail-on` | `critical` / `high` / `medium` / `low` / `none` | `high` | 决定退出码 2 |
| `--online` | 开关 | **关** | 默认离线；打开后向 PyPI / npm 发送依赖名做存在性校验 |
| `--diff` | git ref | 关 | 只报相对该 ref 改动的行 |
| `--baseline` | 路径 | `.wrasse/baseline.json` | 抑制基线里的 finding，只报新增 |
| `--sarif` | 路径 | 关 | 读别的工具的 SARIF，同位置不重复报 |
| `--history` | 开关 | 关 | 额外扫 Git 历史里的密钥 |
| `--include-tests` | 开关 | 关 | 连 `tests/` `fixtures/` 一起扫 |
| `--no-state` | 开关 | 关 | 不写 `.wrasse/last.json`（扫别人的仓库用） |
| `--no-color` | 开关 | 关 | 关掉颜色（`NO_COLOR=1` 等效） |

### 会话里的命令

| 输入 | 作用 |
|---|---|
| `audit . --online` | 等价于在终端跑 `wrasse audit . --online` |
| `/audit` `/review` | 简写 |
| `o 3` / `e 3` | 打开 / 复制提示词 |
| `1` | 直接打开第 1 条 |
| `/privacy` `/ai` `/all` | 切主线 |
| `?` | 命令列表 |
| `q` | 退出（`Ctrl-C`、`Ctrl-D` 同样） |

---

## 十一、术语

| 词 | 意思 |
|---|---|
| **finding** | 一条问题记录，带位置、证据、修复建议 |
| **A 线（privacy）** | "我的代码会不会把东西漏出去" |
| **B 线（ai）** | "AI 留下了哪些坑" |
| **confirmed** | 证据完整，可以直接改（界面上不标） |
| **needs_review** | 结构上成立，但可能需要仓库外的人确认（界面标 `?`，不拦 CI） |
| **unknown** | 这次没能判定（比如离线查不了 PyPI）——不是"没问题" |
| **`--fail-on`** | 达到这个严重度就让退出码变成 2 |

---

## 十二、这份报告**不能**告诉你的

- 运行时行为：值到底有没有真的写进日志、有没有真的发出去
- 仓库之外的防护：网关鉴权、WAF、部署层的限流
- 你以为的"AI 写的代码"：wrasse 不判断作者，只查那类 AI 反复犯的错——人写了同样的代码，一样会报

这三件事写进了每条 `needs_review` 的说明里。看到 `?`，就是让你去确认这三类东西。
