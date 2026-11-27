# 给审阅者的说明

这个包是一份可以直接跑的代码，不是演示稿。你有 10 分钟的话，按下面的顺序看最省时间。

## 先跑起来（约 1 分钟）

```bash
cd wrasse-1.0.0
```

```bash
python -m pip install -e . --no-deps
```

```bash
wrasse audit examples/playground --offline
```

应当看到 **13 条**（1 critical / 8 high / 4 medium），每条带红/绿两行代码。

```bash
python -m unittest discover -s tests
```

应当看到 `Ran 268 tests ... OK`，约 5 秒。

## 我们最想要的反馈，按重要性排

**1. 绿行到底对不对（最重要）**

每条 finding 的 `+` 行声称是"粘进去就能用的修复"。找两三条你认为自己会真的采用的，判断：

- 它保留了原有语义吗？（变量名、赋值、缩进、`with` 结构）
- 有没有"看起来对、实际改坏"的？

已知最弱的一处：SSRF 的判断是结构性的——它认得 `hostname not in ALLOWED` 和 `urlsplit(url)` 这类写法，但认不出隔了两层函数调用才发生的校验，那种写法会被报出来。如果你在自己的代码里遇到，直接说是哪个 rule id。

**2. 误报边界**

`tests/corpus/secure/` 里有 16 个"看起来有问题、其实没问题"的样本（内部路径 helper、文档里提到 `pickle.loads`、`yaml.load` 带 SafeLoader 等）。跑：

```bash
wrasse audit tests/corpus/secure --offline
```

应当是 `no findings`。如果你能构造出一条我们也误报的写法，那比找到漏洞更有价值。

**3. `needs_review` 的分寸**

带 `?` 的条目不拦 CI。我们靠这个避免"误报堵死流水线"。请判断：这个边界划得对不对？哪些宁愿它别报？

**4. 信任边界**

`SECURITY.md` 里列了四条"wrasse 对自己的保证"。其中两条由测试强制：

- `BoundaryTests`：`core.py` / `facts.py` / `structure.py` 不许 import 模型或 HTTP 库
- `test_no_raw_secret_in_any_output`：密钥脱敏后不许出现在终端/JSON 里

请重点看 `src/wrasse/facts.py` 里的 `mask_text` 和 `_emit`，以及 `src/wrasse/core.py` 的文件遍历（有没有越界读、符号链接、超大文件）。**这里出错比漏报严重得多。**

**5. 代码结构**

11 个模块、约 5300 行、零第三方依赖。`core.py` 是项目模型（L0），`facts.py` 是行级规则（L1），`structure.py` 是 AST 规则（L2），`report.py` 是输出。看目录就能猜到职责，如果猜不到，说明结构有问题。

## 已知的、不用报的

- 只支持 Python / FastAPI
- 授权分析以结构性判断为主：能抓"完全没写"和"只在一个角色分支里写"，抓不到更复杂的业务逻辑
- 没有增量扫描（1.4 万文件的语料要跑一分钟）
- `include_router` 只解析静态 prefix
- 62 条规则，覆盖面远小于 Semgrep

## 这个包是什么状态

功能完整、测试齐全、能装能跑，但**没有任何外部用户**。所以"会不会误报"这件事，目前只有作者自己机器上的 7 个真实项目作为证据——这正是需要你看的原因。
