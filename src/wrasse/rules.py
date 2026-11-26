"""Rule registry — 24 rules for 1.0.0, with bilingual copy and fix templates.

A rule carries everything needed to explain itself without a model:
title, why, the red/green fix lines, and the preset prompt copied by `e`.
"""

from __future__ import annotations

from dataclasses import dataclass

from .core import Mainline, Severity, Status


@dataclass(frozen=True, slots=True)
class Rule:
    id: str
    mainline: Mainline
    severity: Severity
    status: Status
    title: dict
    why: dict
    minus: dict
    plus: dict
    prompt: dict

    def t(self, lang: str) -> dict:
        return {
            "title": self.title.get(lang) or self.title["en"],
            "why": self.why.get(lang) or self.why["en"],
            "minus": self.minus.get(lang) or self.minus["en"],
            "plus": self.plus.get(lang) or self.plus["en"],
            "prompt": self.prompt.get(lang) or self.prompt["en"],
        }


def _r(id, mainline, severity, status, title_en, title_zh, why_en, why_zh, minus, plus, prompt_en, prompt_zh) -> Rule:
    return Rule(
        id=id, mainline=mainline, severity=severity, status=status,
        title={"en": title_en, "zh": title_zh},
        why={"en": why_en, "zh": why_zh},
        minus={"en": minus, "zh": minus}, plus={"en": plus, "zh": plus},
        prompt={"en": prompt_en, "zh": prompt_zh},
    )


P = Mainline.PRIVACY
B = Mainline.AI
C, H, M, L = Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW
OK, NR = Status.CONFIRMED, Status.NEEDS_REVIEW

RULES: dict[str, Rule] = {r.id: r for r in [
    # ---------------------------------------------------------- mainline A
    _r("secret/provider-key", P, C, OK,
       "Hard-coded provider key", "硬编码的服务商密钥",
       "The value matches a published credential format for a cloud provider and is stored in the source tree.",
       "该值符合公开服务商的凭证格式，并以明文形式存放在源码树中。",
       '{line}', '{fix_env}',
       "Replace the hard-coded key in {{file}}:{{line}} with an environment variable lookup, "
       "keep the variable name, and add the key to .gitignore if it is in a tracked file. "
       "Do not print the key anywhere in logs.",
       "把 {{file}}:{{line}} 里硬编码的密钥改成从环境变量读取，保持变量名不变；"
       "如果它在被追踪的文件里，同时把该文件加入 .gitignore。不要在日志里打印这个值。"),

    _r("secret/assignment-entropy", P, H, OK,
       "Hard-coded secret by name and entropy", "按名称与熵判定的硬编码密钥",
       "The identifier denotes a secret and the literal has enough entropy to be a real value rather than a placeholder.",
       "标识符表明其为密钥，字面量熵值足以排除占位符。",
       '{line}', '{fix_env}',
       "Move the value at {{file}}:{{line}} to an environment variable and rotate it if the "
       "file is tracked by git. Keep the placeholder in documentation only.",
       "把 {{file}}:{{line}} 的值移到环境变量；如果文件被 git 跟踪，还要轮换这个值。"
       "占位符只保留在文档里。"),

    _r("secret/private-key-block", P, C, OK,
       "Private key committed to source", "私钥被写进源码",
       "PEM private-key material is readable in a tracked file.",
       "可在被追踪的文件中读取到 PEM 私钥内容。",
       '{line}', '# load the key from a secret manager or a path outside the repo',
       "A private key is committed at {{file}}:{{line}}. Remove it, rotate the key pair, "
       "and load it from a file path outside the repository or a secret manager.",
       "私钥被提交在 {{file}}:{{line}}。删除它、轮换密钥对，改成从仓库外的路径或密钥管理服务加载。"),

    _r("secret/frontend-env", P, C, OK,
       "Secret exposed through a public frontend variable", "密钥被放进前端公开变量",
       "NEXT_PUBLIC_, VITE_ and REACT_APP_ variables are inlined into the client bundle at build time.",
       "NEXT_PUBLIC_、VITE_、REACT_APP_ 变量在构建时被内联进客户端产物。",
       '{line}', '{fix_server}',
       "In {{file}}:{{line}} a secret is assigned to a public frontend variable. Move the call "
       "to a server route, read the key from the server environment, and return only the "
       "client-safe token (e.g. a publishable key). Assume the current value is already public.",
       "{{file}}:{{line}} 把一个密钥赋给了前端公开变量。把调用移到服务端路由，"
       "从服务端环境变量读取密钥，只向前端返回公开可用的 token（例如 publishable key）。"
       "当前值应当视为已泄露。"),

    _r("secret/in-frontend-bundle", P, C, OK,
       "Secret literal inside browser code", "浏览器代码里出现密钥字面量",
       "A provider key literal is present in a file the browser downloads.",
       "服务商密钥字面量出现在浏览器可下载的文件中。",
       '{line}', '{fix_server}',
       "A key literal is in browser code at {{file}}:{{line}}. Move it server-side and rotate it; "
       "anything that ships to the browser must be treated as published.",
       "{{file}}:{{line}} 的浏览器代码里有密钥字面量。移到服务端并轮换；"
       "任何发到浏览器的内容都应视为已公开。"),

    _r("log/sensitive-field", P, M, NR,
       "Sensitive value written to logs", "敏感值被写进日志",
       "Log records are persisted, collected and retained far longer than the request that produced them.",
       "日志会持久化并被采集，留存时间远长于产生它的请求。",
       '{line}', '{fix_log}',
       "In {{file}}:{{line}} a secret-looking value is logged. Log an identifier instead "
       "(user id, request id) or mask all but the last four characters.",
       "{{file}}:{{line}} 记录了一个像密钥的值。改成记录标识符（user id、request id），"
       "或只保留后四位。"),

    _r("error/stack-to-client", P, H, OK,
       "Exception text returned to the client", "异常原文返回给客户端",
       "A traceback discloses file paths, SQL statements and dependency versions to whoever triggers an error.",
       "堆栈信息会向任何触发异常者披露文件路径、SQL 语句与依赖版本。",
       '{line}', '{fix_error}',
       "At {{file}}:{{line}} an exception is returned to the caller. Log it server-side with "
       "the request id and return a fixed message plus that id.",
       "{{file}}:{{line}} 把异常返回给了调用方。改成服务端记录（带 request id），"
       "只返回固定文案和这个 id。"),

    _r("response/model-leaks-secret", P, M, NR,
       "Response model exposes a secret field", "响应模型暴露了密钥字段",
       "The response schema serializes these fields by default.",
       "响应模型默认会序列化这些字段。",
       '{line}', '{fix_model}',
       "The response model at {{file}}:{{line}} contains a secret field. Remove it from the "
       "response schema and keep it only on the ORM model.",
       "{{file}}:{{line}} 的响应模型包含密钥字段。从响应模型里移除，只保留在 ORM 模型上。"),

    _r("upload/path-from-filename", P, H, OK,
       "Uploaded filename used in a path", "上传文件名参与路径拼接",
       "A filename containing path separators or .. resolves outside the upload directory.",
       "含路径分隔符或 .. 的文件名会解析到上传目录之外。",
       '{line}', '{fix_path}',
       "At {{file}}:{{line}} a caller-supplied filename is joined into a path. Resolve the "
       "final path and reject anything outside the base directory.",
       "{{file}}:{{line}} 把调用方提供的文件名拼进了路径。先 resolve，再拒绝落在基准目录之外的路径。"),

    _r("agent/env-not-ignored", P, H, NR,
       "Secrets readable by an agent or committed", "密钥文件对 Agent 可见或被提交",
       "A .env file is present and is not excluded from version control or from the assistant's file index.",
       ".env 存在，且未被版本控制或助手索引排除。",
       '{line}', '{fix_ignore}',
       "{{file}} exists but is not excluded. Add it to .gitignore and to .cursorignore / "
       ".claude settings so the agent never reads it into context.",
       "{{file}} 存在但未被排除。把它加进 .gitignore，以及 .cursorignore / .claude 配置，"
       "避免 Agent 把它读进上下文。"),

    # ---------------------------------------------------------- mainline B
    _r("deps/package-not-found", B, H, OK,
       "Dependency does not exist on PyPI", "依赖在 PyPI 上不存在",
       "The name does not exist on the registry; installing it executes whoever registered it first.",
       "该名称在注册表中不存在；安装它等同于执行抢注者的代码。",
       '{line}', '- {name}',
       "The dependency at {{file}}:{{line}} could not be found on PyPI. Confirm the intended "
       "package name before installing; do not run pip install against a guessed name.",
       "{{file}}:{{line}} 的依赖在 PyPI 上查不到。确认原本想装的包名，"
       "不要对猜测出来的名字执行 pip install。"),

    _r("deps/version-not-found", B, M, OK,
       "Pinned version does not exist", "锁定的版本不存在",
       "The package exists but the requested version was never published.",
       "包存在，但指定版本从未发布。",
       '{line}', '- {name}{spec}',
       "The version pinned at {{file}}:{{line}} does not exist. Check the package's release "
       "page and pin an existing version.",
       "{{file}}:{{line}} 锁定的版本不存在。查一下该包的发布页，改成一个存在的版本。"),

    _r("deps/typosquat", B, M, NR,
       "Dependency name looks misspelled", "依赖名疑似拼错",
       "The name is one edit distance from a popular package, the shape used for impersonation.",
       "名称与流行包编辑距离为 1，属仿冒包的典型特征。",
       '{line}', '- {name}',
       "The dependency at {{file}}:{{line}} is one edit away from a popular package. Confirm "
       "which one was intended before installing.",
       "{{file}}:{{line}} 的依赖与一个流行包只差一个字符。安装前确认到底想装哪个。"),

    _r("authz/route-without-auth", B, H, OK,
       "Route has no authentication in its dependency chain", "路由的依赖链里没有认证",
       "No Depends, router-level dependency or middleware attaches an identity to this route.",
       "该路由没有通过 Depends、路由级依赖或中间件绑定身份。",
       '{line}', '{fix_auth}',
       "The route at {{file}}:{{line}} has no authentication in its dependency chain. Add "
       "Depends(get_current_user) or a router-level dependency, unless it is intentionally public.",
       "{{file}}:{{line}} 的路由依赖链里没有认证。加上 Depends(get_current_user) 或路由级依赖，"
       "除非这个接口本来就该公开。"),

    _r("authz/query-without-owner", B, H, NR,
       "Query loads an object without an ownership check", "查询未校验对象归属",
       "A caller-supplied identifier reaches the database with no owner or tenant constraint in this function.",
       "调用方提供的标识符直接进入数据库，本函数内无 owner/tenant 约束。",
       '{line}', '{fix_owner}',
       "At {{file}}:{{line}} an object is loaded by a caller-supplied id with no ownership "
       "constraint. Add owner_id/tenant_id to the query, or confirm the check exists in a "
       "service layer, and add a test proving another user's object returns 404.",
       "{{file}}:{{line}} 用调用方给的 id 直接取对象，没有归属约束。在查询里加上 owner_id/tenant_id，"
       "或确认服务层已有检查；并补一个测试证明别人的对象会返回 404。"),

    _r("input/untyped-body", B, M, NR,
       "Request body read without a schema", "请求体未经过结构校验",
       "Fields are read directly from the request, bypassing model validation of type and range.",
       "字段直接从请求读取，绕过了模型对类型与范围的校验。",
       '{line}', '{fix_schema}',
       "At {{file}}:{{line}} the handler reads raw request fields. Define a Pydantic model, "
       "declare it as the parameter, and read attributes from it.",
       "{{file}}:{{line}} 的处理函数直接读原始请求字段。定义一个 Pydantic 模型作为参数，"
       "从模型上取属性。"),

    _r("config/debug-enabled", B, H, OK,
       "Debug mode enabled", "调试模式开启",
       "Debug mode exposes an interactive traceback and, depending on the framework, a console.",
       "调试模式会暴露交互式堆栈，部分框架还暴露控制台。",
       '{line}', '{fix_debug}',
       "Debug mode is enabled at {{file}}:{{line}}. Read it from an environment variable that "
       "is false in production.",
       "{{file}}:{{line}} 开启了调试模式。改成从环境变量读取，生产环境为 false。"),

    _r("config/cors-wildcard-credentials", B, H, OK,
       "CORS allows any origin with credentials", "CORS 允许任意来源并携带凭证",
       "Wildcard origins combined with credentials allow any site to read authenticated responses.",
       "通配来源与凭证同时开启时，任意站点可读取带身份的响应。",
       '{line}', '{fix_cors}',
       "CORS at {{file}}:{{line}} combines wildcard origins with credentials. List the exact "
       "origins that need access.",
       "{{file}}:{{line}} 的 CORS 同时允许通配来源和凭证。改成列出确切的来源。"),

    _r("code/unsafe-deserialization", B, H, OK,
       "Unsafe deserialization of untrusted data", "反序列化不可信数据",
       "pickle and yaml.load invoke constructors during parsing.",
       "pickle 与 yaml.load 在解析过程中调用构造器。",
       '{line}', '{fix_deser}',
       "At {{file}}:{{line}} untrusted bytes reach an unsafe deserializer. Use JSON, or "
       "yaml.safe_load, or a signed payload.",
       "{{file}}:{{line}} 把不可信数据交给了不安全的反序列化。改用 JSON、yaml.safe_load，或签名过的载荷。"),

    _r("code/sql-string-built", B, H, OK,
       "SQL string built from a caller-supplied value", "SQL 由调用方提供的值拼接而成",
       "The value reaches the database as SQL text rather than as a bound parameter.",
       "该值以 SQL 文本形式而非绑定参数进入数据库。",
       '{line}', '{fix_sql}',
       "The query at {{file}}:{{line}} interpolates a value into SQL. Use a bound parameter "
       "and pass the value separately.",
       "{{file}}:{{line}} 把值插进了 SQL。改成绑定参数，把值单独传进去。"),
]}


def rule_ids() -> list[str]:
    return list(RULES)


def by_mainline(mainline: Mainline) -> list[Rule]:
    return [r for r in RULES.values() if r.mainline == mainline]


# Two data-flow rules that land with the L2 engine (total 22 for 1.0.0).
for _extra in [
    _r("code/command-injection", B, H, OK,
       "Caller-supplied value reaches a command", "调用方的值进入了命令执行",
       "The shell interprets metacharacters in the value, so ; or $() starts a second command.",
       "shell 会解释值中的元字符，; 或 $() 可启动第二条命令。",
       '{line}', 'subprocess.run([cmd, *args], shell=False)',
       "At {{file}}:{{line}} a value reaches a command sink. Pass an argument list with "
       "shell=False and validate it against an allowlist.",
       "{{file}}:{{line}} 的值流进了命令执行。改成传参数列表并设 shell=False，同时用白名单校验。"),
    _r("code/ssrf", B, M, NR,
       "Outbound request uses a caller-supplied URL", "出站请求使用了调用方给的 URL",
       "The URL reaches the HTTP client without a host allowlist, so it can address internal services.",
       "URL 未经主机白名单即进入 HTTP 客户端，可指向内网服务。",
       '{line}', 'requests.get(url, allow_redirects=False)  # after host allowlist check',
       "At {{file}}:{{line}} a caller-supplied URL reaches an HTTP client. Parse the URL, "
       "check the scheme and host against an allowlist, and disable redirects.",
       "{{file}}:{{line}} 调用方给的 URL 进了 HTTP 客户端。解析 URL，"
       "用白名单校验 scheme 与主机，并关闭自动重定向。"),
]:
    RULES[_extra.id] = _extra

RULES["authz/partial-role-check"] = _r(
    "authz/partial-role-check", B, H, NR,
    "Ownership check only applies to one role", "归属校验只对一个角色生效",
    "The ownership check is inside one role branch; other roles do not pass through it.",
    "归属校验位于单一角色分支内，其他角色不经过该检查。",
    '{line}', '{fix_owner}',
    "At {{file}}:{{line}} the ownership check only runs inside a role branch. "
    "Move the constraint into the query so every role shares it, or add the check "
    "to each branch.",
    "{{file}}:{{line}} 的归属校验只在某个角色分支里执行。把约束挪进查询，"
    "让所有角色共用，或给每个分支补上检查。")

RULES["secret/in-git-history"] = _r(
    "secret/in-git-history", P, C, OK,
    "Secret committed in git history", "密钥出现在 Git 历史里",
    "Removing the line does not remove it from existing clones, forks or CI caches.",
    "删除该行不会清除已有克隆、fork 与 CI 缓存中的副本。",
    '{line}', '# rotate this credential — deleting the line is not enough',
    "Commit {{commit}} still contains a credential in {{file}}. Rotate the key first, "
    "then rewrite history (git filter-repo) if the repository is public.",
    "提交 {{commit}} 在 {{file}} 里仍然带着密钥。先轮换这个密钥，"
    "如果仓库是公开的，再用 git filter-repo 重写历史。")

RULES["code/xss-output"] = _r(
    "code/xss-output", B, H, NR,
    "Request data rendered into HTML without escaping", "请求数据未经转义进入 HTML",
    "The value is emitted as markup, so a tag in it becomes script.",
    "该值以标记形式输出，其中的标签会作为脚本执行。",
    '{line}', '{fix_escape}',
    "At {{file}}:{{line}} a request value reaches an HTML response. Escape it with the "
    "framework's own filter ({{ }} in Jinja, textContent in the DOM), or keep it out of "
    "the markup entirely.",
    "{{file}}:{{line}} 的请求值进入了 HTML 响应。用框架自带的转义（Jinja 的 {{ }}、"
    "DOM 的 textContent），或者干脆不把它放进标记里。")

RULES["net/ephemeral-host"] = _r(
    "net/ephemeral-host", B, H, OK,
    "Endpoint points at a temporary tunnel or free dynamic domain", "接口指向临时隧道或免费动态域名",
    "The hostname is reclaimed after expiry; the next registrant receives the same traffic.",
    "该域名到期后会被他人回收，后续注册者将收到同一流量。",
    '{line}', '# use a domain you own and control',
    "At {{file}}:{{line}} a host is a disposable tunnel or free dynamic DNS name. Point the "
    "client at a domain you control, and rotate any credential that has already been sent there.",
    "{{file}}:{{line}} 用的是一次性隧道或免费动态域名。改成你自己控制的域名；"
    "已经发过去的凭证都要轮换。")

RULES["leak/machine-path"] = _r(
    "leak/machine-path", P, M, NR,
    "Document or config leaks a machine path or private address", "文档或配置带出了本机路径或内网地址",
    "A username, home directory or internal address discloses host layout to readers of the repository.",
    "用户名、家目录或内网地址会向仓库读者披露主机布局。",
    '{line}', '{fix_machine}',
    "{{file}}:{{line}} contains a path or address from someone's machine. Replace it with a "
    "placeholder (<user>, <project-root>) or an environment variable.",
    "{{file}}:{{line}} 里是某台机器的路径或地址。换成占位符（<user>、<project-root>）"
    "或环境变量。")

RULES["deps/undeclared-import"] = _r(
    "deps/undeclared-import", B, M, NR,
    "Third-party module imported but not declared", "导入的第三方模块没有声明",
    "The module is imported but no manifest declares it, so a clean install fails.",
    "该模块被导入，但没有任何清单声明它；干净环境安装后导入失败。",
    '{line}', '# add {module} to requirements / pyproject',
    "{{file}}:{{line}} imports {{module}}, which no manifest declares. Add it with a version "
    "range, or it will be missing in a clean install.",
    "{{file}}:{{line}} 导入了 {{module}}，但没有任何清单声明它。加上版本范围，"
    "否则干净环境里装不上。")

RULES["license/mismatch"] = _r(
    "license/mismatch", B, M, NR,
    "Declared licence does not match the licence file", "声明的许可证与许可证文件不一致",
    "The declaration and the LICENSE file disagree, which determines whether downstream use is permitted.",
    "声明与 LICENSE 文件不一致，而下游据此判断是否可用。",
    '{line}', '# make the declaration and LICENSE agree',
    "{{file}}:{{line}} declares a licence that the LICENSE file does not support. Align them, or "
    "mark the code UNLICENSED if it is not open source.",
    "{{file}}:{{line}} 声明的许可证和 LICENSE 文件对不上。两者统一；"
    "如果本来就不是开源的，写 UNLICENSED。")

RULES["deps/lockfile-integrity"] = _r(
    "deps/lockfile-integrity", B, M, OK,
    "Lockfile entries carry no integrity hash", "锁文件条目没有完整性哈希",
    "Without an integrity hash, a registry or mirror can substitute the package undetected.",
    "缺少完整性哈希时，注册表或镜像可替换包内容而不被发现。",
    '{line}', 'npm install --package-lock-only   # regenerate with integrity hashes',
    "{{file}} has {{count}} entry(ies) without an integrity or resolved field. Regenerate the "
    "lockfile rather than editing it, and keep it in version control.",
    "{{file}} 里有 {{count}} 条缺 integrity 或 resolved。重新生成锁文件，不要手改；"
    "并且要提交到版本库。")

RULES["config/rate-limit-key"] = _r(
    "config/rate-limit-key", B, M, NR,
    "Rate limit keyed on the proxy address", "限流键取的是代理地址",
    "Keyed on the proxy address, all clients share one quota.",
    "以代理地址为键时，所有客户端共用同一配额。",
    '{line}', '# key on the authenticated identity, or the first X-Forwarded-For hop you trust',
    "{{file}}:{{line}} builds the rate-limit key from the connection address. Behind a proxy or "
    "tunnel that is the proxy's address for every user.",
    "{{file}}:{{line}} 用连接地址做限流键。在反向代理或隧道后面，所有人共用一个地址。")

# ---------------------------------------------------------------- batch 2
_EXTRA = [
    ("config/allowed-hosts-wildcard", B, H, OK,
     "Host header check accepts any host", "Host 头校验接受任意主机",
     "With a wildcard any Host header is accepted, including one controlled by an attacker.",
     "主机名通配时接受任意 Host 头，包括攻击者控制的值。",
     '+ ALLOWED_HOSTS = ["app.example.com"]'),
    ("config/host-check-disabled", B, H, OK,
     "Host header protection disabled", "Host 头保护被关闭",
     "The Host header check is disabled, so any hostname is accepted.",
     "Host 头校验被关闭，任意主机名均被接受。",
     "# list the hosts you serve: ALLOWED_HOSTS = ['app.example.com']"),
    ("config/csrf-exempt", B, M, NR,
     "CSRF protection turned off for a view", "视图关掉了 CSRF 保护",
     "A browser holding the session cookie can be made to submit this request from any site.",
     "持有会话 cookie 的浏览器可被任意站点驱使提交该请求。",
     "# remove @csrf_exempt, or add a narrow, reviewed control"),
    ("code/dynamic-eval", B, H, OK,
     "eval/exec runs a string as code", "eval/exec 把字符串当代码执行",
     "The value is evaluated as source code.",
     "该值被作为源码执行。",
     "json.loads(value)  # or an explicit dispatch table"),
    ("config/cookie-flags", B, M, NR,
     "Session cookie missing Secure or HttpOnly", "会话 cookie 缺 Secure 或 HttpOnly",
     "Without HttpOnly the cookie is readable by script; without Secure it is sent over plain HTTP.",
     "缺少 HttpOnly 时脚本可读取该 cookie；缺少 Secure 时会经明文 HTTP 传输。",
     "secure: true, httpOnly: true"),
    ("config/tls-verification-off", B, H, OK,
     "TLS certificate verification disabled", "TLS 证书校验被关闭",
     "Certificate verification is disabled, so any intermediary is trusted.",
     "证书校验被关闭，任何中间人都被信任。",
     "verify=True  # or point at a trusted CA bundle"),
    ("config/autoescape-off", B, H, NR,
     "Template autoescaping disabled", "模板自动转义被关闭",
     "Autoescaping is disabled, so every interpolated value is emitted as markup.",
     "自动转义被关闭，所有插值均按标记输出。",
     "autoescape=True"),
    ("config/object-storage-public-acl", B, C, OK,
     "Object storage ACL allows public writes", "对象存储 ACL 允许公开写入",
     "The bucket ACL permits public write, so any holder of the URL can modify or delete objects.",
     "存储桶 ACL 允许公开写入，任何持有 URL 者可修改或删除对象。",
     'ACL: "private"'),
    ("secret/default-credentials", P, C, OK,
     "Default credentials shipped", "默认账号密码被打进交付物",
     "Default credentials are the first combination attempted in automated login attacks.",
     "默认口令是自动化登录攻击最先尝试的组合。",
     "# provision the first user from an environment secret"),
    ("auth/jwt-misuse", B, H, OK,
     "JWT verification can be bypassed", "JWT 校验可以被绕过",
     "alg:none accepts an unsigned token; a key literal is readable by anyone with the source.",
     "alg:none 接受未签名令牌；密钥字面量对任何持有源码者可见。",
     "jwt.decode(token, key, algorithms=[\"RS256\"])"),
    ("auth/insecure-token-source", B, H, NR,
     "Security token built from a predictable source", "安全令牌来自可预测的源",
     "Math.random and random.random are not cryptographically secure; the next value is predictable.",
     "Math.random 与 random.random 不是密码学安全随机，后续值可预测。",
     "secrets.token_urlsafe(32)  /  crypto.randomBytes(32)"),
    ("auth/weak-password-hash", B, M, NR,
     "Password hash with a very low work factor", "口令哈希的工作因子过低",
     "A cost factor of 4 is exhausted in seconds by an offline attack.",
     "cost 为 4 时，离线攻击可在数秒内穷举完毕。",
     "bcrypt.hash(pw, 12)"),
    ("code/open-redirect", B, M, NR,
     "Redirect target comes from the request", "跳转目标来自请求",
     "The redirect target comes from the request, so a link on this domain can land on another.",
     "跳转目标取自请求，本域名下的链接可被导向其他站点。",
     "redirect(next_path if next_path.startswith(\"/\") else \"/\")"),
]
for _spec in _EXTRA:
    _id, _m, _sev, _st, _ten, _tzh, _wen, _wzh, _plus = _spec
    RULES[_id] = _r(_id, _m, _sev, _st, _ten, _tzh, _wen, _wzh,
                    '{line}', _plus, _wen, _wzh)

# ---------------------------------------------------------------- Java / Spring (optional)
for _spec in [
    ("spring/csrf-disabled", B, H, OK,
     "Spring Security CSRF protection disabled", "Spring Security 的 CSRF 保护被关闭",
     "CSRF protection is disabled, so a browser holding the session cookie can be made to submit state-changing requests.",
     "CSRF 保护被关闭，持有会话 cookie 的浏览器可被驱使提交状态变更请求。",
     "# http.csrf(Customizer.withDefaults())"),
    ("spring/permit-all", B, H, NR,
     "Spring Security rule permits every request", "Spring Security 规则放行所有请求",
     "permitAll() removes authentication for every path the matcher covers.",
     "permitAll() 使该匹配器覆盖的所有路径不需要认证。",
     '.requestMatchers("/public/**").permitAll()  # and authenticated() elsewhere'),
    ("spring/cors-wildcard", B, H, OK,
     "Spring CORS allows every origin", "Spring 的 CORS 允许任意来源",
     "A bare @CrossOrigin accepts any origin; with credentials it discloses authenticated sessions.",
     "未限定来源的 @CrossOrigin 接受任意站点；配合凭证即泄露已认证会话。",
     '@CrossOrigin(origins = "https://app.example.com")'),
]:
    _id, _m, _sev, _st, _ten, _tzh, _wen, _wzh, _plus = _spec
    RULES[_id] = _r(_id, _m, _sev, _st, _ten, _tzh, _wen, _wzh, "{line}", _plus, _wen, _wzh)

# ---------------------------------------------------------------- OWASP 2025 gaps
for _spec in [
    ("authz/mass-assignment", B, H, NR,
     "Request model lets the caller set a privileged field", "请求模型允许调用方设置特权字段",
     "The request body binds directly onto the model, including fields that carry privilege.",
     "请求体直接绑定到模型，包含表示权限的字段。",
     "# keep is_admin out of the input model; set it server-side"),
    ("auth/md5-sha1-password", B, H, OK,
     "Password hashed with MD5 or SHA-1", "口令用 MD5 或 SHA-1 做哈希",
     "Both digest functions are fast enough for billions of candidates per second on commodity GPUs.",
     "两种摘要算法在通用 GPU 上可达每秒数十亿次尝试。",
     "# use bcrypt/argon2: bcrypt.hashpw(pw, bcrypt.gensalt(12))"),
    ("net/request-without-timeout", B, M, NR,
     "Outbound request has no timeout", "出站请求没有设置超时",
     "A request without a timeout holds its worker until the peer closes the connection.",
     "未设置超时的请求会一直占用 worker，直至对端关闭连接。",
     "requests.get(url, timeout=10)"),
]:
    _id, _m, _sev, _st, _ten, _tzh, _wen, _wzh, _plus = _spec
    RULES[_id] = _r(_id, _m, _sev, _st, _ten, _tzh, _wen, _wzh, "{line}", _plus, _wen, _wzh)

# ---------------------------------------------------------------- 2026 report gaps
for _spec in [
    ("agent/hidden-instructions", B, H, OK,
     "Invisible characters in an agent instruction file",
     "Agent 指令文件里有不可见字符",
     "Zero-width and bidirectional control characters can encode instructions that are invisible in review.",
     "零宽与双向控制字符可承载在人工审查中不可见的指令。",
     "# delete every invisible character; retype the file from a trusted source"),
    ("log/injection", B, M, NR,
     "Request value written into a log line",
     "请求值被原样写进日志",
     "A newline in the value produces a forged entry in the log used for incident review.",
     "值中的换行会在用于事件复盘的日志中伪造一条记录。",
     '# logger.info("login %s", clean(user))'),
    ("code/weak-crypto", B, H, OK,
     "Broken or misused cipher", "使用了已被攻破或误用的加密算法",
     "The algorithm or mode is deprecated or leaks structure; a key literal is stored in the source.",
     "所用算法或模式已废弃或泄露结构；密钥以字面量存于源码。",
     "# AES-GCM with a key from the environment"),
    ("deps/new-package", B, M, NR,
     "Dependency published very recently", "依赖是最近才发布的",
     "The package first appeared recently; slopsquatting registers an invented name ahead of its use.",
     "该包首次发布时间很近；抢注投毒会提前注册被臆造的包名。",
     "# check the maintainer and download count before installing"),
]:
    _id, _m, _sev, _st, _ten, _tzh, _wen, _wzh, _plus = _spec
    RULES[_id] = _r(_id, _m, _sev, _st, _ten, _tzh, _wen, _wzh, "{line}", _plus, _wen, _wzh)

# ---------------------------------------------------------------- OWASP API gaps
for _spec in [
    ("code/ssti", B, H, OK,
     "Request value used as a template", "请求值被当作模板",
     "The request value is compiled as a template, so template syntax is evaluated.",
     "请求值被当作模板编译，模板语法因而被执行。",
     'render_template("page.html", value=user)'),
    ("code/nosql-injection", B, H, NR,
     "Request data used as a query filter", "请求数据被直接当作查询条件",
     "The query filter is built from request data and can carry operators such as $gt or $where.",
     "查询条件由请求数据构成，可携带 $gt、$where 等操作符。",
     "collection.find({'user_id': user.id})"),
    ("authz/admin-route-unprotected", B, H, NR,
     "Admin route checks login but not role", "管理端路由只校验登录，不校验角色",
     "The route requires authentication but no role, so any authenticated account reaches an administrative path.",
     "该路由要求认证但不要求角色，任何已登录账户均可访问管理路径。",
     "Depends(require_admin)"),
    ("api/unbounded-query", B, M, NR,
     "Route returns an unbounded query", "接口返回没有上限的查询",
     "The handler returns every row matching the query; the result set grows with the table.",
     "处理函数返回查询命中的全部行，结果集随表增长。",
     ".limit(page_size).offset(page * page_size)"),
    ("config/api-docs-public", B, M, NR,
     "API docs and schema left open", "API 文档与 schema 对外敞开",
     "The OpenAPI document and the documentation UI are served without authentication.",
     "OpenAPI 文档与文档界面在无认证的情况下对外提供。",
     "FastAPI(docs_url=None, openapi_url=None)"),
    ("deps/insecure-source", B, H, OK,
     "Dependency installed over plain HTTP", "依赖走明文 HTTP 安装",
     "The dependency is fetched over plain HTTP, where any intermediary can replace the archive.",
     "依赖通过明文 HTTP 获取，中间人可替换该归档。",
     "git+https://... or https://..."),
    ("code/fail-open", B, H, NR,
     "Verification fails open", "校验失败时放行",
     "The except branch returns True, so an error inside the check is treated as a pass.",
     "except 分支返回 True，校验过程中的异常被当作通过。",
     "except Exception: return False"),
    ("response/pii-fields", B, M, NR,
     "Response model exposes strong PII", "响应模型暴露强 PII",
     "The response carries identity or payment identifiers, which are retained outside the request.",
     "响应携带身份或支付标识符，其留存范围超出该请求。",
     "# return a masked value: '****1234'"),
]:
    _id, _m, _sev, _st, _ten, _tzh, _wen, _wzh, _plus = _spec
    RULES[_id] = _r(_id, _m, _sev, _st, _ten, _tzh, _wen, _wzh, "{line}", _plus, _wen, _wzh)
