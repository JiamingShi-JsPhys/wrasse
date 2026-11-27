# wrasse 规则清单

共 62 条。由 `wrasse rules export` 从 `src/wrasse/rules.py` 生成，请勿手改。

标 `待确认` 的条目会报出来，但不计入 `--fail-on`。

## A · 隐私

*这段代码会不会把东西漏出去？*

### `agent/env-not-ignored` — 密钥文件对 Agent 可见或被提交

**高危** · 待确认 · 隐私

.env 存在，且未被版本控制或助手索引排除。

```diff
- <这行代码>
+ .gitignore:  .env
```

<sub>预设提示词: <file> 存在但未被排除。把它加进 .gitignore，以及 .cursorignore / .claude 配置，避免 Agent 把它读进上下文。</sub>

### `error/stack-to-client` — 异常原文返回给客户端

**高危** · 已确认 · 隐私

堆栈信息会向任何触发异常者披露文件路径、SQL 语句与依赖版本。

```diff
- <这行代码>
+ {"error": "internal_error"}
```

<sub>预设提示词: <file>:<line> 把异常返回给了调用方。改成服务端记录（带 request id），只返回固定文案和这个 id。</sub>

### `leak/machine-path` — 文档或配置带出了本机路径或内网地址

**中危** · 待确认 · 隐私

用户名、家目录或内网地址会向仓库读者披露主机布局。

```diff
- <这行代码>
+ {fix_machine}
```

<sub>预设提示词: <file>:<line> 里是某台机器的路径或地址。换成占位符（<user>、<project-root>）或环境变量。</sub>

### `log/sensitive-field` — 敏感值被写进日志

**中危** · 待确认 · 隐私

日志会持久化并被采集，留存时间远长于产生它的请求。

```diff
- <这行代码>
+ "[redacted]"
```

<sub>预设提示词: <file>:<line> 记录了一个像密钥的值。改成记录标识符（user id、request id），或只保留后四位。</sub>

### `response/model-leaks-secret` — 响应模型暴露了密钥字段

**中危** · 待确认 · 隐私

响应模型默认会序列化这些字段。

```diff
- <这行代码>
+ # remove this field from the response schema
```

<sub>预设提示词: <file>:<line> 的响应模型包含密钥字段。从响应模型里移除，只保留在 ORM 模型上。</sub>

### `secret/assignment-entropy` — 按名称与熵判定的硬编码密钥

**高危** · 已确认 · 隐私

标识符表明其为密钥，字面量熵值足以排除占位符。

```diff
- <这行代码>
+ os.environ["API_KEY"]
```

<sub>预设提示词: 把 <file>:<line> 的值移到环境变量；如果文件被 git 跟踪，还要轮换这个值。占位符只保留在文档里。</sub>

### `secret/default-credentials` — 默认账号密码被打进交付物

**严重** · 已确认 · 隐私

默认口令是自动化登录攻击最先尝试的组合。

```diff
- <这行代码>
+ # provision the first user from an environment secret
```

<sub>预设提示词: 默认口令是自动化登录攻击最先尝试的组合。</sub>

### `secret/frontend-env` — 密钥被放进前端公开变量

**严重** · 已确认 · 隐私

NEXT_PUBLIC_、VITE_、REACT_APP_ 变量在构建时被内联进客户端产物。

```diff
- <这行代码>
+ // server-side only — never expose this value to the browser
```

<sub>预设提示词: <file>:<line> 把一个密钥赋给了前端公开变量。把调用移到服务端路由，从服务端环境变量读取密钥，只向前端返回公开可用的 token（例如 publishable key）。当前值应当视为已泄露。</sub>

### `secret/in-frontend-bundle` — 浏览器代码里出现密钥字面量

**严重** · 已确认 · 隐私

服务商密钥字面量出现在浏览器可下载的文件中。

```diff
- <这行代码>
+ // server-side only — never expose this value to the browser
```

<sub>预设提示词: <file>:<line> 的浏览器代码里有密钥字面量。移到服务端并轮换；任何发到浏览器的内容都应视为已公开。</sub>

### `secret/in-git-history` — 密钥出现在 Git 历史里

**严重** · 已确认 · 隐私

删除该行不会清除已有克隆、fork 与 CI 缓存中的副本。

```diff
- <这行代码>
+ # rotate this credential — deleting the line is not enough
```

<sub>预设提示词: 提交 <commit> 在 <file> 里仍然带着密钥。先轮换这个密钥，如果仓库是公开的，再用 git filter-repo 重写历史。</sub>

### `secret/private-key-block` — 私钥被写进源码

**严重** · 已确认 · 隐私

可在被追踪的文件中读取到 PEM 私钥内容。

```diff
- <这行代码>
+ # load the key from a secret manager or a path outside the repo
```

<sub>预设提示词: 私钥被提交在 <file>:<line>。删除它、轮换密钥对，改成从仓库外的路径或密钥管理服务加载。</sub>

### `secret/provider-key` — 硬编码的服务商密钥

**严重** · 已确认 · 隐私

该值符合公开服务商的凭证格式，并以明文形式存放在源码树中。

```diff
- <这行代码>
+ os.environ["API_KEY"]
```

<sub>预设提示词: 把 <file>:<line> 里硬编码的密钥改成从环境变量读取，保持变量名不变；如果它在被追踪的文件里，同时把该文件加入 .gitignore。不要在日志里打印这个值。</sub>

### `upload/path-from-filename` — 上传文件名参与路径拼接

**高危** · 已确认 · 隐私

含路径分隔符或 .. 的文件名会解析到上传目录之外。

```diff
- <这行代码>
+ target = (Path(BASE) / name).resolve()
```

<sub>预设提示词: <file>:<line> 把调用方提供的文件名拼进了路径。先 resolve，再拒绝落在基准目录之外的路径。</sub>

## B · AI 的坑

*AI 少写了什么？*

### `agent/hidden-instructions` — Agent 指令文件里有不可见字符

**高危** · 已确认 · AI 的坑

零宽与双向控制字符可承载在人工审查中不可见的指令。

```diff
- <这行代码>
+ # delete every invisible character; retype the file from a trusted source
```

<sub>预设提示词: 零宽与双向控制字符可承载在人工审查中不可见的指令。</sub>

### `api/unbounded-query` — 接口返回没有上限的查询

**中危** · 待确认 · AI 的坑

处理函数返回查询命中的全部行，结果集随表增长。

```diff
- <这行代码>
+ .limit(page_size).offset(page * page_size)
```

<sub>预设提示词: 处理函数返回查询命中的全部行，结果集随表增长。</sub>

### `auth/insecure-token-source` — 安全令牌来自可预测的源

**高危** · 待确认 · AI 的坑

Math.random 与 random.random 不是密码学安全随机，后续值可预测。

```diff
- <这行代码>
+ secrets.token_urlsafe(32)  /  crypto.randomBytes(32)
```

<sub>预设提示词: Math.random 与 random.random 不是密码学安全随机，后续值可预测。</sub>

### `auth/jwt-misuse` — JWT 校验可以被绕过

**高危** · 已确认 · AI 的坑

alg:none 接受未签名令牌；密钥字面量对任何持有源码者可见。

```diff
- <这行代码>
+ jwt.decode(token, key, algorithms=["RS256"])
```

<sub>预设提示词: alg:none 接受未签名令牌；密钥字面量对任何持有源码者可见。</sub>

### `auth/md5-sha1-password` — 口令用 MD5 或 SHA-1 做哈希

**高危** · 已确认 · AI 的坑

两种摘要算法在通用 GPU 上可达每秒数十亿次尝试。

```diff
- <这行代码>
+ # use bcrypt/argon2: bcrypt.hashpw(pw, bcrypt.gensalt(12))
```

<sub>预设提示词: 两种摘要算法在通用 GPU 上可达每秒数十亿次尝试。</sub>

### `auth/weak-password-hash` — 口令哈希的工作因子过低

**中危** · 待确认 · AI 的坑

cost 为 4 时，离线攻击可在数秒内穷举完毕。

```diff
- <这行代码>
+ bcrypt.hash(pw, 12)
```

<sub>预设提示词: cost 为 4 时，离线攻击可在数秒内穷举完毕。</sub>

### `authz/admin-route-unprotected` — 管理端路由只校验登录，不校验角色

**高危** · 待确认 · AI 的坑

该路由要求认证但不要求角色，任何已登录账户均可访问管理路径。

```diff
- <这行代码>
+ Depends(require_admin)
```

<sub>预设提示词: 该路由要求认证但不要求角色，任何已登录账户均可访问管理路径。</sub>

### `authz/mass-assignment` — 请求模型允许调用方设置特权字段

**高危** · 待确认 · AI 的坑

请求体直接绑定到模型，包含表示权限的字段。

```diff
- <这行代码>
+ # keep is_admin out of the input model; set it server-side
```

<sub>预设提示词: 请求体直接绑定到模型，包含表示权限的字段。</sub>

### `authz/partial-role-check` — 归属校验只对一个角色生效

**高危** · 待确认 · AI 的坑

归属校验位于单一角色分支内，其他角色不经过该检查。

```diff
- <这行代码>
+ owner_id=user.id
```

<sub>预设提示词: <file>:<line> 的归属校验只在某个角色分支里执行。把约束挪进查询，让所有角色共用，或给每个分支补上检查。</sub>

### `authz/query-without-owner` — 查询未校验对象归属

**高危** · 待确认 · AI 的坑

调用方提供的标识符直接进入数据库，本函数内无 owner/tenant 约束。

```diff
- <这行代码>
+ owner_id=user.id
```

<sub>预设提示词: <file>:<line> 用调用方给的 id 直接取对象，没有归属约束。在查询里加上 owner_id/tenant_id，或确认服务层已有检查；并补一个测试证明别人的对象会返回 404。</sub>

### `authz/route-without-auth` — 路由的依赖链里没有认证

**高危** · 已确认 · AI 的坑

该路由没有通过 Depends、路由级依赖或中间件绑定身份。

```diff
- <这行代码>
+ user=Depends(get_current_user)
```

<sub>预设提示词: <file>:<line> 的路由依赖链里没有认证。加上 Depends(get_current_user) 或路由级依赖，除非这个接口本来就该公开。</sub>

### `code/command-injection` — 调用方的值进入了命令执行

**高危** · 已确认 · AI 的坑

shell 会解释值中的元字符，; 或 $() 可启动第二条命令。

```diff
- <这行代码>
+ subprocess.run([cmd, *args], shell=False)
```

<sub>预设提示词: <file>:<line> 的值流进了命令执行。改成传参数列表并设 shell=False，同时用白名单校验。</sub>

### `code/dynamic-eval` — eval/exec 把字符串当代码执行

**高危** · 已确认 · AI 的坑

该值被作为源码执行。

```diff
- <这行代码>
+ json.loads(value)  # or an explicit dispatch table
```

<sub>预设提示词: 该值被作为源码执行。</sub>

### `code/fail-open` — 校验失败时放行

**高危** · 待确认 · AI 的坑

except 分支返回 True，校验过程中的异常被当作通过。

```diff
- <这行代码>
+ except Exception: return False
```

<sub>预设提示词: except 分支返回 True，校验过程中的异常被当作通过。</sub>

### `code/nosql-injection` — 请求数据被直接当作查询条件

**高危** · 待确认 · AI 的坑

查询条件由请求数据构成，可携带 $gt、$where 等操作符。

```diff
- <这行代码>
+ collection.find({'user_id': user.id})
```

<sub>预设提示词: 查询条件由请求数据构成，可携带 $gt、$where 等操作符。</sub>

### `code/open-redirect` — 跳转目标来自请求

**中危** · 待确认 · AI 的坑

跳转目标取自请求，本域名下的链接可被导向其他站点。

```diff
- <这行代码>
+ redirect(next_path if next_path.startswith("/") else "/")
```

<sub>预设提示词: 跳转目标取自请求，本域名下的链接可被导向其他站点。</sub>

### `code/sql-string-built` — SQL 由调用方提供的值拼接而成

**高危** · 已确认 · AI 的坑

该值以 SQL 文本形式而非绑定参数进入数据库。

```diff
- <这行代码>
+ execute("... WHERE id = ?", (value,))
```

<sub>预设提示词: <file>:<line> 把值插进了 SQL。改成绑定参数，把值单独传进去。</sub>

### `code/ssrf` — 出站请求使用了调用方给的 URL

**中危** · 待确认 · AI 的坑

URL 未经主机白名单即进入 HTTP 客户端，可指向内网服务。

```diff
- <这行代码>
+ requests.get(url, allow_redirects=False)  # after host allowlist check
```

<sub>预设提示词: <file>:<line> 调用方给的 URL 进了 HTTP 客户端。解析 URL，用白名单校验 scheme 与主机，并关闭自动重定向。</sub>

### `code/ssti` — 请求值被当作模板

**高危** · 已确认 · AI 的坑

请求值被当作模板编译，模板语法因而被执行。

```diff
- <这行代码>
+ render_template("page.html", value=user)
```

<sub>预设提示词: 请求值被当作模板编译，模板语法因而被执行。</sub>

### `code/unsafe-deserialization` — 反序列化不可信数据

**高危** · 已确认 · AI 的坑

pickle 与 yaml.load 在解析过程中调用构造器。

```diff
- <这行代码>
+ json.loads(payload)
```

<sub>预设提示词: <file>:<line> 把不可信数据交给了不安全的反序列化。改用 JSON、yaml.safe_load，或签名过的载荷。</sub>

### `code/weak-crypto` — 使用了已被攻破或误用的加密算法

**高危** · 已确认 · AI 的坑

所用算法或模式已废弃或泄露结构；密钥以字面量存于源码。

```diff
- <这行代码>
+ # AES-GCM with a key from the environment
```

<sub>预设提示词: 所用算法或模式已废弃或泄露结构；密钥以字面量存于源码。</sub>

### `code/xss-output` — 请求数据未经转义进入 HTML

**高危** · 待确认 · AI 的坑

该值以标记形式输出，其中的标签会作为脚本执行。

```diff
- <这行代码>
+ {fix_escape}
```

<sub>预设提示词: <file>:<line> 的请求值进入了 HTML 响应。用框架自带的转义（Jinja 的 {{ }}、DOM 的 textContent），或者干脆不把它放进标记里。</sub>

### `config/allowed-hosts-wildcard` — Host 头校验接受任意主机

**高危** · 已确认 · AI 的坑

主机名通配时接受任意 Host 头，包括攻击者控制的值。

```diff
- <这行代码>
+ + ALLOWED_HOSTS = ["app.example.com"]
```

<sub>预设提示词: 主机名通配时接受任意 Host 头，包括攻击者控制的值。</sub>

### `config/api-docs-public` — API 文档与 schema 对外敞开

**中危** · 待确认 · AI 的坑

OpenAPI 文档与文档界面在无认证的情况下对外提供。

```diff
- <这行代码>
+ FastAPI(docs_url=None, openapi_url=None)
```

<sub>预设提示词: OpenAPI 文档与文档界面在无认证的情况下对外提供。</sub>

### `config/autoescape-off` — 模板自动转义被关闭

**高危** · 待确认 · AI 的坑

自动转义被关闭，所有插值均按标记输出。

```diff
- <这行代码>
+ autoescape=True
```

<sub>预设提示词: 自动转义被关闭，所有插值均按标记输出。</sub>

### `config/cookie-flags` — 会话 cookie 缺 Secure 或 HttpOnly

**中危** · 待确认 · AI 的坑

缺少 HttpOnly 时脚本可读取该 cookie；缺少 Secure 时会经明文 HTTP 传输。

```diff
- <这行代码>
+ secure: true, httpOnly: true
```

<sub>预设提示词: 缺少 HttpOnly 时脚本可读取该 cookie；缺少 Secure 时会经明文 HTTP 传输。</sub>

### `config/cors-wildcard-credentials` — CORS 允许任意来源并携带凭证

**高危** · 已确认 · AI 的坑

通配来源与凭证同时开启时，任意站点可读取带身份的响应。

```diff
- <这行代码>
+ allow_origins=["https://app.example.com"]
```

<sub>预设提示词: <file>:<line> 的 CORS 同时允许通配来源和凭证。改成列出确切的来源。</sub>

### `config/csrf-exempt` — 视图关掉了 CSRF 保护

**中危** · 待确认 · AI 的坑

持有会话 cookie 的浏览器可被任意站点驱使提交该请求。

```diff
- <这行代码>
+ # remove @csrf_exempt, or add a narrow, reviewed control
```

<sub>预设提示词: 持有会话 cookie 的浏览器可被任意站点驱使提交该请求。</sub>

### `config/debug-enabled` — 调试模式开启

**高危** · 已确认 · AI 的坑

调试模式会暴露交互式堆栈，部分框架还暴露控制台。

```diff
- <这行代码>
+ DEBUG = os.getenv("DEBUG", "false") == "true"
```

<sub>预设提示词: <file>:<line> 开启了调试模式。改成从环境变量读取，生产环境为 false。</sub>

### `config/host-check-disabled` — Host 头保护被关闭

**高危** · 已确认 · AI 的坑

Host 头校验被关闭，任意主机名均被接受。

```diff
- <这行代码>
+ # list the hosts you serve: ALLOWED_HOSTS = ['app.example.com']
```

<sub>预设提示词: Host 头校验被关闭，任意主机名均被接受。</sub>

### `config/object-storage-public-acl` — 对象存储 ACL 允许公开写入

**严重** · 已确认 · AI 的坑

存储桶 ACL 允许公开写入，任何持有 URL 者可修改或删除对象。

```diff
- <这行代码>
+ ACL: "private"
```

<sub>预设提示词: 存储桶 ACL 允许公开写入，任何持有 URL 者可修改或删除对象。</sub>

### `config/rate-limit-key` — 限流键取的是代理地址

**中危** · 待确认 · AI 的坑

以代理地址为键时，所有客户端共用同一配额。

```diff
- <这行代码>
+ # key on the authenticated identity, or the first X-Forwarded-For hop you trust
```

<sub>预设提示词: <file>:<line> 用连接地址做限流键。在反向代理或隧道后面，所有人共用一个地址。</sub>

### `config/tls-verification-off` — TLS 证书校验被关闭

**高危** · 已确认 · AI 的坑

证书校验被关闭，任何中间人都被信任。

```diff
- <这行代码>
+ verify=True  # or point at a trusted CA bundle
```

<sub>预设提示词: 证书校验被关闭，任何中间人都被信任。</sub>

### `deps/insecure-source` — 依赖走明文 HTTP 安装

**高危** · 已确认 · AI 的坑

依赖通过明文 HTTP 获取，中间人可替换该归档。

```diff
- <这行代码>
+ git+https://... or https://...
```

<sub>预设提示词: 依赖通过明文 HTTP 获取，中间人可替换该归档。</sub>

### `deps/lockfile-integrity` — 锁文件条目没有完整性哈希

**中危** · 已确认 · AI 的坑

缺少完整性哈希时，注册表或镜像可替换包内容而不被发现。

```diff
- <这行代码>
+ npm install --package-lock-only   # regenerate with integrity hashes
```

<sub>预设提示词: <file> 里有 <count> 条缺 integrity 或 resolved。重新生成锁文件，不要手改；并且要提交到版本库。</sub>

### `deps/new-package` — 依赖是最近才发布的

**中危** · 待确认 · AI 的坑

该包首次发布时间很近；抢注投毒会提前注册被臆造的包名。

```diff
- <这行代码>
+ # check the maintainer and download count before installing
```

<sub>预设提示词: 该包首次发布时间很近；抢注投毒会提前注册被臆造的包名。</sub>

### `deps/package-not-found` — 依赖在 PyPI 上不存在

**高危** · 已确认 · AI 的坑

该名称在注册表中不存在；安装它等同于执行抢注者的代码。

```diff
- <这行代码>
+ - {name}
```

<sub>预设提示词: <file>:<line> 的依赖在 PyPI 上查不到。确认原本想装的包名，不要对猜测出来的名字执行 pip install。</sub>

### `deps/typosquat` — 依赖名疑似拼错

**中危** · 待确认 · AI 的坑

名称与流行包编辑距离为 1，属仿冒包的典型特征。

```diff
- <这行代码>
+ - {name}
```

<sub>预设提示词: <file>:<line> 的依赖与一个流行包只差一个字符。安装前确认到底想装哪个。</sub>

### `deps/undeclared-import` — 导入的第三方模块没有声明

**中危** · 待确认 · AI 的坑

该模块被导入，但没有任何清单声明它；干净环境安装后导入失败。

```diff
- <这行代码>
+ # add {module} to requirements / pyproject
```

<sub>预设提示词: <file>:<line> 导入了 <module>，但没有任何清单声明它。加上版本范围，否则干净环境里装不上。</sub>

### `deps/version-not-found` — 锁定的版本不存在

**中危** · 已确认 · AI 的坑

包存在，但指定版本从未发布。

```diff
- <这行代码>
+ - {name}{spec}
```

<sub>预设提示词: <file>:<line> 锁定的版本不存在。查一下该包的发布页，改成一个存在的版本。</sub>

### `input/untyped-body` — 请求体未经过结构校验

**中危** · 待确认 · AI 的坑

字段直接从请求读取，绕过了模型对类型与范围的校验。

```diff
- <这行代码>
+ payload: UpdateUser
```

<sub>预设提示词: <file>:<line> 的处理函数直接读原始请求字段。定义一个 Pydantic 模型作为参数，从模型上取属性。</sub>

### `license/mismatch` — 声明的许可证与许可证文件不一致

**中危** · 待确认 · AI 的坑

声明与 LICENSE 文件不一致，而下游据此判断是否可用。

```diff
- <这行代码>
+ # make the declaration and LICENSE agree
```

<sub>预设提示词: <file>:<line> 声明的许可证和 LICENSE 文件对不上。两者统一；如果本来就不是开源的，写 UNLICENSED。</sub>

### `log/injection` — 请求值被原样写进日志

**中危** · 待确认 · AI 的坑

值中的换行会在用于事件复盘的日志中伪造一条记录。

```diff
- <这行代码>
+ # logger.info("login %s", clean(user))
```

<sub>预设提示词: 值中的换行会在用于事件复盘的日志中伪造一条记录。</sub>

### `net/ephemeral-host` — 接口指向临时隧道或免费动态域名

**高危** · 已确认 · AI 的坑

该域名到期后会被他人回收，后续注册者将收到同一流量。

```diff
- <这行代码>
+ # use a domain you own and control
```

<sub>预设提示词: <file>:<line> 用的是一次性隧道或免费动态域名。改成你自己控制的域名；已经发过去的凭证都要轮换。</sub>

### `net/request-without-timeout` — 出站请求没有设置超时

**中危** · 待确认 · AI 的坑

未设置超时的请求会一直占用 worker，直至对端关闭连接。

```diff
- <这行代码>
+ requests.get(url, timeout=10)
```

<sub>预设提示词: 未设置超时的请求会一直占用 worker，直至对端关闭连接。</sub>

### `response/pii-fields` — 响应模型暴露强 PII

**中危** · 待确认 · AI 的坑

响应携带身份或支付标识符，其留存范围超出该请求。

```diff
- <这行代码>
+ # return a masked value: '****1234'
```

<sub>预设提示词: 响应携带身份或支付标识符，其留存范围超出该请求。</sub>

### `spring/cors-wildcard` — Spring 的 CORS 允许任意来源

**高危** · 已确认 · AI 的坑

未限定来源的 @CrossOrigin 接受任意站点；配合凭证即泄露已认证会话。

```diff
- <这行代码>
+ @CrossOrigin(origins = "https://app.example.com")
```

<sub>预设提示词: 未限定来源的 @CrossOrigin 接受任意站点；配合凭证即泄露已认证会话。</sub>

### `spring/csrf-disabled` — Spring Security 的 CSRF 保护被关闭

**高危** · 已确认 · AI 的坑

CSRF 保护被关闭，持有会话 cookie 的浏览器可被驱使提交状态变更请求。

```diff
- <这行代码>
+ # http.csrf(Customizer.withDefaults())
```

<sub>预设提示词: CSRF 保护被关闭，持有会话 cookie 的浏览器可被驱使提交状态变更请求。</sub>

### `spring/permit-all` — Spring Security 规则放行所有请求

**高危** · 待确认 · AI 的坑

permitAll() 使该匹配器覆盖的所有路径不需要认证。

```diff
- <这行代码>
+ .requestMatchers("/public/**").permitAll()  # and authenticated() elsewhere
```

<sub>预设提示词: permitAll() 使该匹配器覆盖的所有路径不需要认证。</sub>
