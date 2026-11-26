# 命令速查

wrasse 只有一类操作：扫描一个目录，把结论按行给你。下面的划分按**你打算拿它做什么**，不按功能多少。

---

## 一般使用者：四条命令够用

日常只有两个时刻会用到它——写完一批代码想确认一遍；看到一条结论想知道怎么办。

| 命令 | 作用 | 什么时候用 |
|---|---|---|
| `wrasse` | 进入会话：先显示上次扫描的结果，再给一个提示符 | 不确定该敲什么的时候 |
| `wrasse audit .` | 扫描当前目录，输出红/绿行 | 提交前、交接前、上线前 |
| `wrasse review` | 逐条过一遍，`n` 下一条、`o` 打开文件、`e` 解释、`q` 退出 | 想认真处理，而不是只看数量 |
| `wrasse explain 3` | 第 3 条的完整说明（含触发证据与替换写法） | 看不懂某一条为什么被报 |
| `wrasse open 3` | 在编辑器里打开第 3 条所在的行 | 准备动手改 |

会话里也可以直接敲完整命令，例如 `audit . --focus privacy`。

会话本身是带补全的：

- 敲 `/` 列出全部命令，继续输入就是过滤；`Tab` 补全到选中的那条，`↑↓` 换选中，`Esc` 关掉菜单，`Enter` 直接执行选中的那条。窗口放不下时列表自己滚动（`↑ n more` / `↓ n more`），不会把命令藏起来。
- `/config` 打开设置面板：`↑↓` 选行，`Enter` 或空格换值，`Esc` 返回，改动立刻写进 `.wrasse/config.json`。
- 光标键移动、退格、`Home`/`End` 都能用；没有 TTY 时（例如脚本里）自动退回普通输入。

**怎么读结果**：`●` 后面是严重度，规则 id 前的 `?` 表示 `needs_review`——结构上成立，但可能由仓库外的东西补上，所以不计入 `--fail-on`。红行是现有代码，绿行是替换内容；绿行如果是注释，说明正确的通用写法无法证明，需要人判断。

**退出码**：`0` 干净，`1` 内部错误，`2` 有 finding 达到阈值，`3` 路径不是项目，`4` 扫描没跑完（**不能当成通过**）。

---

## 高级使用者

### 只看这次改了什么

```bash
wrasse audit . --diff main          # 只报 main 之后新增行上的问题
```

配合 hook 使用：

```bash
wrasse audit . --mode quick --diff HEAD   # quick 只跑 L1，秒级
```

### 存量问题先冻结，只盯新增

```bash
wrasse baseline create              # 把当前 58 条记进 .wrasse/baseline.json
wrasse audit . --baseline           # 之后只显示新增的
wrasse baseline diff                # 看这次和基线差在哪
```

### 接进 CI / 代码扫描

```bash
wrasse audit . --format sarif -o wrasse.sarif --fail-on high
```

SARIF 可直接上传 GitHub Code Scanning。`--fail-on` 有 `critical|high|medium|low|none`，默认 `high`；`needs_review` 永远不参与拦截。

第三方已经报过的问题可以去重：

```bash
wrasse audit . --sarif existing.sarif   # 与已有 SARIF 重复的不再输出
```

### 控制扫描范围与深度

| 参数 | 作用 |
|---|---|
| `--focus privacy` / `ai` | 只报一条主线 |
| `--mode quick` | 只跑 L1 行级规则，不建 AST（适合 pre-commit） |
| `--mode standard` | 默认，含数据流与结构性授权检查 |
| `--include-tests` | 连 `tests/` `examples/` 一起扫（默认跳过） |
| `--context 5` | 每条 finding 显示前后 5 行（默认 2） |
| `--lang zh` | 这一次用中文（长期设置写进 config） |

### 联网与历史

```bash
wrasse audit . --online     # 到 PyPI / npm 核对包是否存在、版本是否存在（默认离线）
wrasse audit . --history    # 扫 git 历史里已删除但仍可提取的密钥
```

`--online` 是唯一会让数据离开本机的东西，运行时会明说查了哪些包。`--history` 需要目录是 git 仓库。

### 设置：语言、阈值、模式

设置存在项目里的 `.wrasse/config.json`，可以提交进仓库，让团队和 CI 用同一套：

```bash
wrasse config                       # 当前值与来源（默认值会标出来）
wrasse config set lang zh           # 这个项目以后都出中文
wrasse config set fail_on critical  # CI 只拦 critical
wrasse config set mode quick        # 默认只跑 L1
wrasse config unset lang
```

可设的键：`lang`（`en`/`zh`）、`fail_on`（`critical`/`high`/`medium`/`low`/`none`）、`mode`（`quick`/`standard`）、`focus`（`privacy`/`ai`/`all`）。文件本体就是一串键值：

```json
{"lang": "zh", "fail_on": "high"}
```

优先级只有两层：**命令行参数覆盖这一次，其余看 `.wrasse/config.json`，都没有就用内置默认**。语言没有单独的命令，也没有环境变量——它只是面板里的第一行。

`.wrasse/` 下只有 `last.json`（扫描状态，记下不带版本库）被忽略；`config.json` 和 `baseline.json` 可以提交，让团队与 CI 对齐。

### 输出与机器消费

```bash
wrasse audit . --format json              # 完整结构，含证据与 id
wrasse audit . --format html -o r.html    # 单文件，离线可看
wrasse audit . --no-state                 # 不写 .wrasse/last.json（CI 里用）
```

### 规则本身

```bash
wrasse rules list                    # 62 条，按主线分组
wrasse rules show authz/route-without-auth   # 单条：判定、状态、为什么、怎么改
wrasse rules export --format md --lang zh -o rules.md   # 导出整份清单
```

### 把仓库交给 AI 之前

```bash
wrasse preflight .        # 只看"这个仓库能不能放心让 Agent 打开"
```

专查：`.env` 是否被忽略、Agent 配置里有没有可疑命令、配置里有没有密钥、有没有对外隧道。

### 环境

```bash
wrasse doctor             # Python 版本、可选依赖（javalang）、状态目录、网络开关
```

---

## 一张表：哪个场景用哪条

| 场景 | 命令 |
|---|---|
| 提交前快速过一遍 | `wrasse audit . --mode quick` |
| 认真处理现有问题 | `wrasse review` |
| PR 里只审新增 | `wrasse audit . --diff origin/main` |
| 存量太多，先冻结 | `wrasse baseline create` |
| CI 卡口 | `--format sarif --fail-on high` |
| 只关心隐私泄露 | `wrasse audit . --focus privacy` |
| 交接/开源前 | `wrasse audit . --online --history` |
| 固定语言/阈值/模式 | `wrasse config set lang zh` |
| 交给 Agent 前 | `wrasse preflight .` |
| 想加规则 | `wrasse rules show <id>`，再看 [CONTRIBUTING.md](../CONTRIBUTING.md) |
