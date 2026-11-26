# wrasse 1.0.0 开发计划

> 范围：本地 CLI，**零 AI 依赖**（不配 key、不联网也能跑完两条主线）。
> 本表是估算，不是承诺；每周结束以"验收条件"判定是否推进。

---

## 1. 范围

**做（1.0.0 的全部交付）**

| 类 | 内容 |
|---|---|
| 项目模型 | 文件发现 · Python AST 索引 · 符号 / 导入 / 基础调用图 · FastAPI 路由与 Depends · 依赖清单 · 配置发现 |
| 主线 A · 隐私 | 10 条规则：provider key、熵赋值、私钥块、前端变量、前端 bundle、日志字段、错误堆栈、响应模型、上传路径、Agent 排除配置 |
| 主线 B · AI 的坑 | 12 条规则：幻觉包、版本不存在、拼写仿冒、无认证路由、无所有权查询、无类型请求体、debug、CORS 通配、危险反序列化、SQL 拼接 |
| 数据流 | SQL / 命令 / 路径 / SSRF，函数内 + 一层跨函数 |
| 输出 | text · json · sarif · html；红绿修复行、行号、上下文 2/5 行、四种终态 |
| 交互 | `wrasse` 启动屏 + REPL；`review` 面板；`open` / `explain` 跳转；序号句柄 |
| 双语 | 界面文案 + 规则标题/说明/提示词，en 为默认 |
| 工程 | 零第三方依赖、pip 安装、pytest、样本集、GitHub Actions、README(en/zh) |

**不做（写明的边界）**

模型调用 · 自动修复 · 动态验证 · VS Code / 桌面 App · 多语言 · shell 补全脚本（推迟到 1.0.1）· 全屏 TUI

---

## 2. 里程碑

| # | 周 | 交付物 | 验收条件 |
|---|---|---|---|
| **M0** 骨架与约束 | 1 | 仓库结构、`pyproject.toml`、CLI 骨架、`Finding`/`Evidence` 模型、`scope.py`、i18n 骨架、`test_boundary.py` | `pip install -e .` 后 `wrasse --help` 可用；边界测试通过（`core/` 不含模型与网络调用） |
| **M1** 项目模型 | 2–3 | 文件发现、Python 索引、符号、导入、基础调用图、FastAPI 路由 + Depends 解析、依赖清单、配置发现、`.wrasse/last.json` | 在 3 个真实 FastAPI 项目上：路由发现率 ≥ 95%，Depends 链解析正确 |
| **M2** 隐私线 | 3–4 | 10 条 A 线规则（含修复模板与提示词）、终端渲染（五段式、红绿、行号、上下文）、三种终态 | 3 个真实项目上至少各命中 1 条用户认可的问题；安全样本误报 ≤ 1 条 |
| **M3** 数据流 | 5–6 | source / sink / sanitizer 定义，SQL / 命令 / 路径 / SSRF，函数内 + 一层跨函数 | 漏洞样本召回 ≥ 80%；跨文件样本能给出完整路径 |
| **M4** 交互层 | 7 | 启动屏、REPL、命令面板、`review`、`open`、`explain`、序号句柄、`--lang` | 从启动到打开某条 finding 的源码 ≤ 3 次操作；面板可被单元测试（假按键驱动） |
| **M5** 结构性授权 | 8 | `authz/route-without-auth`、`authz/query-without-owner`、`input/untyped-body`，以及 `needs_review` 的"缺什么"文案 | 在自有样本上区分"完全没写"与"写在别处"；后者一律 `needs_review` |
| **M6** 报告与发行 | 9 | HTML 报告、SARIF、JSON schema、README(en/zh)、CI、样本集整理、`wrasse doctor` | 三条发行门槛全部满足（见 §5） |

**内容写作与代码并行**：规则文案（title / desc / prompt / fix 的中英四份）从 M1 开始，每天写 2 条，M5 前完成 24 条。

---

## 3. 任务分解（工作量估算）

| 模块 | 主要文件 | 人日 | 依赖 |
|---|---|---:|---|
| CLI 骨架 + 参数 | `cli/app.py`、`cli/*.py` | 3 | — |
| Finding / Evidence 模型 | `core/findings/models.py` | 2 | — |
| 文件发现与边界 | `core/scope.py` | 2 | — |
| Python 索引 | `core/project/index.py`、`symbols.py` | 5 | 文件发现 |
| FastAPI 解析（路由 / Depends / router 前缀 / include_router） | `core/project/fastapi.py` | 6 | Python 索引 |
| 依赖与配置发现 | `core/project/deps.py`、`configs.py` | 3 | 文件发现 |
| A 线 10 条规则 | `core/facts/*` | 8 | 文件发现 |
| 依赖核验（PyPI + 缓存） | `core/facts/registry.py` | 3 | deps |
| 数据流（AST + taint） | `core/structure/*` | 8 | Python 索引 |
| 结构性授权规则 | `core/structure/authz.py` | 4 | FastAPI 解析 |
| 终端渲染（五段式 / 红绿 / 上下文） | `core/report/text.py` | 5 | 模型 |
| JSON / SARIF / HTML | `core/report/*` | 4 | 模型 |
| i18n | `i18n/*.json`、`core/i18n.py` | 2 | — |
| 面板 / REPL / 按键 | `tui/*` | 5 | 渲染 |
| 规则文案 24 条（中英四份） | `src/wrasse/rules.py` | 10 | 规则实现 |
| 样本集（vulnerable / secure / complex） | `tests/fixtures/*` | 5 | — |
| 测试与回归 | `tests/*` | 6 | 全部 |
| 打包、CI、文档 | `pyproject.toml`、`.github/`、`README.md` | 4 | 全部 |

合计约 **85 人日**；按每周 5 天、单人投入计约 **17 周**，若按每周 10 天投入（含 AI 辅助）约 **9 周**。

---

## 4. 关键路径

```
M0 骨架 ─▶ M1 项目模型 ─┬─▶ M2 隐私线 ──┐
                        ├─▶ M3 数据流 ──┼─▶ M5 结构性授权 ─▶ M6 发行
                        └─▶ M4 交互层 ──┘
```

- **M1 是唯一的关键路径**：FastAPI 解析没做好，M3 和 M5 都得返工。
- M2 与 M4 可以并行——它们只共享渲染层。
- 样本集应该在 M2 之前就开始建，否则规则只能靠"看着像对"来判断。

---

## 5. 发行门槛（1.0.0 的硬条件）

| # | 条件 | 判定方式 |
|---|---|---|
| 1 | 在 **3 个真实项目**上各至少命中 1 条用户认可的问题 | 自己用，记录每条是否"确实要改" |
| 2 | 每个项目的误报 ≤ 1 条 | 逐条人工判定 |
| 3 | 断网、无模型、无配置文件时可完整跑 `quick` | 拔网线执行 |

达不到 → 版本号停在 0.9.x，不硬发 1.0.0。

---

## 6. 风险

| 风险 | 影响 | 对策 |
|---|---|---|
| FastAPI 解析比预期复杂（`include_router` 前缀、依赖覆盖、`APIRouter` 嵌套） | 拖 M1，连带拖 M3/M5 | M1 只支持"路由 + Depends 链"，前缀与嵌套放进 1.0.1 |
| 规则文案写不动（24 条 × 4 份） | 1.0.0 缺内容 | 先只写 A 线 10 条，B 线可延后到 1.0.1 |
| Windows 终端差异（按键、CJK 宽度） | 面板体验差 | 面板与渲染解耦，非 TTY 自动降级；分组线用固定长度 |
| PyPI 查询限流 | 依赖核验失败 | 本地缓存 + 串行限速，失败记 `unknown` 而不是报错 |
| 误报率控制不住 | 用户关掉工具 | `needs_review` 不进 CI 拦截；每条规则先过安全样本再上线 |

---

## 7. 版本节奏

| 版本 | 内容 |
|---|---|
| **1.0.0** | 上表全部（零 AI） |
| 1.0.1 | shell 补全脚本、`include_router` 前缀、更多 FastAPI 边界 |
| 1.1.0 | L3 语义推断（可选 `--llm`，模型只出假设）、增量扫描 |
| 1.2.0 | GitHub Action、SARIF 上传、基线对比增强 |
