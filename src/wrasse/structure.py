"""L2 structure — data flow (SQL / command / path / SSRF) and structural authorization."""

from __future__ import annotations

import ast
import re

from .core import Evidence, Finding, ProjectIndex, Status, line_at
from .facts import _emit, _path_alias

FUNC = (ast.FunctionDef, ast.AsyncFunctionDef)
SQL_SINKS = {"execute", "executemany", "executescript"}
SHELL_SINKS = {"os.system", "os.popen", "subprocess.run", "subprocess.call", "subprocess.check_output",
               "subprocess.check_call", "subprocess.Popen", "subprocess.getoutput",
               "subprocess.getstatusoutput", "child_process.exec", "child_process.execSync"}
PATH_SINKS = {"open", "send_file", "read_text", "read_bytes", "write_text"}
SSRF_SINKS = {"get", "post", "put", "patch", "delete", "request", "urlopen"}
REQUEST_SRC = re.compile(r"\brequest\b|\breq\.|\bquery_params\b|\bpayload\b|\bform\b")
# A value read *through* the request object, not a variable that happens to be
# named `request` — `urllib.request.Request(...)` is one of those.
REQUEST_READ = re.compile(
    r"\brequest[.](?:args|query_params|json|form|body|params|GET|POST|data)\b"
    r"|\breq[.](?:args|query_params|json|body|params|form)\b")
SQL_KW = re.compile(r"\b(SELECT|INSERT|UPDATE|DELETE)\b", re.I)


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def _names(node: ast.AST) -> set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def _priv_paths(func) -> dict[str, tuple[str, str]]:
    """name -> (base dir, joined tail) for paths built from a caller filename."""
    out: dict[str, tuple[str, str]] = {}
    from_attr: set[str] = set()
    for node in ast.walk(func):
        if (isinstance(node, ast.Assign) and isinstance(node.value, ast.Attribute)
                and node.value.attr in ("filename", "name")):
            from_attr.update(t.id for t in node.targets if isinstance(t, ast.Name))
    for node in ast.walk(func):
        if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.Call):
            continue
        call = node.value
        if not _call_name(call.func).endswith("join"):
            continue
        # An upload object's filename, or a name copied from one. A plain
        # parameter called `filename` is the helper's own contract, not traversal.
        touched = any(
            (isinstance(a, ast.Attribute) and a.attr in ("filename", "name"))
            or (isinstance(a, ast.Name) and a.id in from_attr)
            for a in call.args
        )
        parts = [ast.unparse(a) for a in call.args]
        if touched and len(parts) >= 2:
            base, head = parts[0], " / ".join(parts[1:])
            for t in node.targets:
                if isinstance(t, ast.Name):
                    out[t.id] = (base, head)
    return out


# A bare `args` or `payload` is an argparse namespace or a queue message as
# often as it is request data; only these two mean a web request.
REQUEST_NAMES = {"request", "req"}


def _rooted(node: ast.AST, roots: set[str] | None = None) -> bool:
    """True only when the expression's own value comes from the request.

    `request.query_params["x"]` yes; `len(request.query_params)` no — a count is
    not attacker text. `p = request.query_params` makes `p` a root too, so
    `p["name"]` is still request text.
    """
    if roots is None:
        roots = REQUEST_NAMES
    if isinstance(node, ast.Await):
        return _rooted(node.value, roots)
    if isinstance(node, ast.Name):
        return node.id in roots
    if isinstance(node, (ast.Subscript, ast.Attribute, ast.Call)):
        inner = node.value if not isinstance(node, ast.Call) else node.func
        return _rooted(inner, roots)
    return False


def _taint_of(func) -> tuple[set[str], set[str]]:
    """All untrusted names, plus the subset that came straight from the request.

    Assignment is followed transitively: `p = request.query_params` makes `p`
    a root, so `n = p["x"]` is request text as well.
    """
    # `from flask import request` puts the request in a module-level name, so a
    # zero-argument handler is still tainted.
    tainted = {a.arg for a in func.args.args + func.args.kwonlyargs if a.arg not in ("self", "cls")}
    tainted |= set(REQUEST_NAMES)
    derived: set[str] = set()
    roots = set(REQUEST_NAMES)
    for _ in range(3):                     # two aliases deep is enough for real code
        added = False
        for node in ast.walk(func):
            value = getattr(node, "value", None)
            if value is None or not isinstance(node, (ast.Assign, ast.AnnAssign)):
                continue
            if not _rooted(value, roots):
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if not isinstance(target, ast.Name):
                    continue
                tainted.add(target.id)
                derived.add(target.id)
                if target.id not in roots:
                    roots.add(target.id)
                    added = True
        for node in ast.walk(func):
            # `cmd += request.args["d"]`, `if (n := request.args["x"])`
            if isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name):
                if _rooted(node.value, roots) or (_names(node.value) & roots):
                    tainted.add(node.target.id)
                    derived.add(node.target.id)
                    if node.target.id not in roots:
                        roots.add(node.target.id)
                        added = True
            if isinstance(node, ast.NamedExpr) and isinstance(node.target, ast.Name):
                if _rooted(node.value, roots):
                    tainted.add(node.target.id)
                    derived.add(node.target.id)
                    if node.target.id not in roots:
                        roots.add(node.target.id)
                        added = True
        if not added:
            break
    return tainted, derived


SINK_RULES = {"sql": "code/sql-string-built", "shell": "code/command-injection",
              "path": "upload/path-from-filename", "ssrf": "code/ssrf", "xss": "code/xss-output"}


def _sink_kind(call: ast.Call) -> str | None:
    name = _call_name(call.func)
    short = name.rsplit(".", 1)[-1]
    if short in SQL_SINKS:
        return "sql"
    if name in SHELL_SINKS:
        return "shell"
    if short in PATH_SINKS:
        return "path"
    if short in SSRF_SINKS and name.split(".")[0] in ("requests", "httpx", "urllib"):
        return "ssrf"
    if short in {"HTMLResponse", "Markup"}:
        return "xss"
    return None


# Escaping is context-specific. `shlex.quote` protects a shell argument and
# `urllib.parse.quote` protects a URL; neither one stops `<script>` in HTML.
# Only an HTML-aware escaper may silence the XSS rule, and it has to be named
# as one.
HTML_ESCAPERS = re.compile(
    r"^(?:html|markupsafe|flask|jinja2|django[.]utils[.]html|webhelpers|cgi)[.]escape$"
    r"|^(?:html|xss)[_.](?:escape|sanitize|clean)$"
    r"|^(?:escape|sanitize|clean)[_.](?:html|xss)$"
    r"|^Markup[.]escape$"
    r"|^bleach[.]clean$",
    re.I)

_ESCAPER_CACHE: dict[int, tuple[set[str], dict[str, str], set[str]]] = {}


def _escaper_context(tree: ast.Module | None) -> tuple[set[str], dict[str, str], set[str]]:
    """Bare names imported from an HTML module, `import x as y` aliases, and the
    modules the file rebinds for itself.

    `def escape(value): return value` in the same file is not HTML escaping, and
    neither is `html.escape` after `html = fake_module`.
    """
    if tree is None:
        return set(), {}, set()
    key = id(tree)
    hit = _ESCAPER_CACHE.get(key)
    if hit is not None:
        return hit
    names: set[str] = set()
    aliases: dict[str, str] = {}
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported.add(alias.asname or alias.name.split(".")[0])
                if alias.asname:
                    aliases[alias.asname] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                if alias.name != "*" and _is_html_escaper(f"{node.module}.{alias.name}"):
                    names.add(alias.asname or alias.name)
    shadowed = {n.name for n in ast.walk(tree)
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))}
    for node in ast.walk(tree):
        # `from html import escape` followed by `escape = lambda v: v` at module
        # level: the binding that runs last is the one the call uses.
        if isinstance(node, ast.Assign):
            shadowed.update(t.id for t in node.targets if isinstance(t, ast.Name))
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign)) and isinstance(node.target, ast.Name):
            shadowed.add(node.target.id)
        elif isinstance(node, (ast.For, ast.AsyncFor)) and isinstance(node.target, ast.Name):
            shadowed.add(node.target.id)
    names -= shadowed
    dead = imported & shadowed            # `import html` then `html = fake`
    _ESCAPER_CACHE[key] = (names, aliases, dead)
    return names, aliases, dead


def _is_html_escaper(name: str) -> bool:
    return bool(HTML_ESCAPERS.match(name))


def _is_html_escaper_call(name: str, ctx: tuple[set[str], dict[str, str], set[str]]) -> bool:
    names, aliases, dead = ctx
    if "." in name:
        head, _, rest = name.partition(".")
        if head in dead:                 # the module object was replaced
            return False
        return _is_html_escaper(f"{aliases.get(head, head)}.{rest}")
    return name in names


def _rebound_in(func) -> set[str]:
    """Names this function binds itself: parameters, assignments, loops, nested defs.

    `escape = lambda v: v` inside the handler is not the imported escaper even
    though the import is still there at module level.
    """
    out = {a.arg for a in list(func.args.posonlyargs) + list(func.args.args) + list(func.args.kwonlyargs)}
    if func.args.vararg:
        out.add(func.args.vararg.arg)
    if func.args.kwarg:
        out.add(func.args.kwarg.arg)
    for node in ast.walk(func):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node is not func:
            out.add(node.name)
        elif isinstance(node, ast.Assign):
            out.update(t.id for t in node.targets if isinstance(t, ast.Name))
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign)) and isinstance(node.target, ast.Name):
            out.add(node.target.id)
        elif isinstance(node, (ast.For, ast.AsyncFor)) and isinstance(node.target, ast.Name):
            out.add(node.target.id)
        elif isinstance(node, ast.withitem) and isinstance(node.optional_vars, ast.Name):
            out.add(node.optional_vars.id)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            out.add(node.name)
    return out


def _already_escaped(node: ast.AST, ctx: tuple[set[str], dict[str, str], set[str]] | None = None,
                     rebound: set[str] | None = None) -> bool:
    """Every interpolated value is the result of a call to an escaper.

    A variable *named* `raw_escape` is not escaped; only a call to something
    that looks like one counts.
    """
    if not isinstance(node, ast.JoinedStr):
        return False
    values = [v for v in node.values if isinstance(v, ast.FormattedValue)]
    if not values:
        return False
    names, aliases, dead = ctx or (set(), {}, set())
    ctx = (names - (rebound or set()), aliases, dead | (rebound or set()))
    return all(isinstance(v.value, ast.Call) and _is_html_escaper_call(_call_name(v.value.func), ctx)
               for v in values)


def _sql_vars(func, tainted: set[str]) -> dict[str, int]:
    """Local names that already hold SQL text, so the sink may receive a name.

    The text is interpolated where it is assigned; by the time it reaches
    `execute` it is a plain variable.
    """
    out: dict[str, int] = {}
    for node in ast.walk(func):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)) or node.value is None:
            continue
        value = node.value
        if not isinstance(value, (ast.JoinedStr, ast.BinOp, ast.Call)):
            continue
        rendered = ast.unparse(value)
        if not SQL_KW.search(rendered):
            continue
        if not (_names(value) & tainted or REQUEST_SRC.search(rendered)):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        for target in targets:
            if isinstance(target, ast.Name):
                out[target.id] = node.lineno
    for _ in range(20):                    # `a = query; b = a; c = b`
        added = False
        for node in ast.walk(func):
            if not isinstance(node, (ast.Assign, ast.AnnAssign)) or node.value is None:
                continue
            if not isinstance(node.value, ast.Name) or node.value.id not in out:
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Name) and target.id not in out:
                    out[target.id] = node.lineno
                    added = True
        if not added:
            break
    return out


COMMENT = re.compile(r"#[^'\"`\n]*")


def _text_vars(func, derived: set[str]) -> set[str]:
    """`cmd = "ls " + d` → {"cmd"}: the string a shell will parse.

    Only a value that came from the request counts. A command assembled from
    the tool's own configuration is the tool's design, not an injection.
    """
    out: set[str] = set()
    roots = derived | REQUEST_NAMES
    for node in ast.walk(func):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)) or node.value is None:
            continue
        value = node.value
        if not isinstance(value, (ast.JoinedStr, ast.BinOp, ast.Call)):
            continue
        if not _names(value) & roots:
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        out |= {t.id for t in targets if isinstance(t, ast.Name)}
    for node in ast.walk(func):
        if (isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name)
                and isinstance(node.value, (ast.JoinedStr, ast.BinOp, ast.Call))
                and _names(node.value) & roots):
            out.add(node.target.id)
    return out


def _interproc(index: ProjectIndex, lang: str) -> list[Finding]:
    """One hop: a helper that puts its parameter into a sink, called with request data.

    The article's `api.py -> service.py -> db.execute` shape. One hop only: a
    second helper in between is not followed, and that limit is in the README.
    """
    params_of: dict[str, list[str]] = {}      # positional only: kwonly cannot be passed by position
    home_of: dict[str, str] = {}
    sinks_of: dict[str, list[tuple[str, str]]] = {}
    for _path, tree in index.trees.items():
        for func in [n for n in ast.walk(tree) if isinstance(n, FUNC)]:
            params = [a.arg for a in func.args.args if a.arg not in ("self", "cls")]
            params_of[func.name] = params
            home_of[func.name] = _path
            for call in [n for n in ast.walk(func) if isinstance(n, ast.Call)]:
                kind = _sink_kind(call)
                if not kind or not call.args:
                    continue
                touched = _names(call.args[0]) & set(params)
                if touched:
                    sinks_of.setdefault(func.name, []).append((kind, sorted(touched)[0]))

    out: list[Finding] = []
    for path, tree in index.trees.items():
        for func in [n for n in ast.walk(tree) if isinstance(n, FUNC)]:
            _tainted, derived = _taint_of(func)
            for call in [n for n in ast.walk(func) if isinstance(n, ast.Call)]:
                callee = _call_name(call.func).rsplit(".", 1)[-1]
                if callee == func.name:               # a function calling itself proves nothing
                    continue
                if callee not in sinks_of:
                    continue
                if home_of.get(callee) == path:        # same file: the local pass already saw it
                    continue
                for kind, param in sinks_of[callee]:
                    positional = params_of.get(callee, [])
                    if param in positional:
                        position = positional.index(param)
                        if position >= len(call.args):
                            continue
                        argument = call.args[position]
                    else:
                        keyword = next((k for k in call.keywords if k.arg == param), None)
                        if keyword is None:
                            continue
                        argument = keyword.value
                    # A request value, not just any parameter of the caller, and
                    # not a local that merely happens to be named `request`
                    # (`urllib.request.Request(...)` is not a web request).
                    if not (_names(argument) & derived
                            or REQUEST_READ.search(ast.unparse(argument))):
                        continue
                    line = call.lineno
                    src = line_at(index.texts.get(path, ""), line).rstrip()
                    out.append(_emit(SINK_RULES[kind], index, path, line, lang=lang, minus=[src],
                                     plus=[f"# {param} reaches the {kind} sink inside {callee}()"],
                                     evidence=[Evidence("dataflow", path, line,
                                                        f"request -> {callee}({param}) -> {kind}")]))
    return out


PRIVILEGED_FIELD = re.compile(r"^(?:is_admin|is_staff|is_superuser|role|roles|permissions?|scopes?)$", re.I)
INPUT_SUFFIX = re.compile(r"(?:Update|Create|In|Input|Request|Payload|Body)$")
HTTP_CALL = ("requests.get", "requests.post", "requests.put", "requests.patch", "requests.request",
             "httpx.get", "httpx.post", "httpx.put", "httpx.patch", "httpx.request")


def _mass_assignment(index: ProjectIndex, lang: str) -> list[Finding]:
    """A request-shaped Pydantic model that carries a privileged field."""
    out: list[Finding] = []
    for path, tree in index.trees.items():
        text = index.texts.get(path, "")
        for node in [n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]:
            bases = {ast.unparse(b) for b in node.bases}
            if not any(b.endswith(("BaseModel", "Schema")) for b in bases):
                continue
            if not INPUT_SUFFIX.search(node.name):
                continue
            for stmt in node.body:
                target = None
                if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
                    target = stmt.target.id
                elif isinstance(stmt, ast.Assign) and stmt.targets and isinstance(stmt.targets[0], ast.Name):
                    target = stmt.targets[0].id
                if target and PRIVILEGED_FIELD.match(target):
                    line = stmt.lineno
                    out.append(_emit("authz/mass-assignment", index, path, line, lang=lang,
                                     minus=[line_at(text, line).rstrip()],
                                     plus=["# drop this field from the input model"]))
                    break
    return out


def _no_timeout(index: ProjectIndex, lang: str) -> list[Finding]:
    """An outbound HTTP call that can wait forever."""
    out: list[Finding] = []
    for path, tree in index.trees.items():
        text = index.texts.get(path, "")
        for call in [n for n in ast.walk(tree) if isinstance(n, ast.Call)]:
            name = _call_name(call.func)
            if name not in HTTP_CALL:
                continue
            if any(k.arg == "timeout" for k in call.keywords):
                continue
            line = call.lineno
            out.append(_emit("net/request-without-timeout", index, path, line, lang=lang,
                             minus=[line_at(text, line).rstrip()]))
    return out


def scan(index: ProjectIndex, lang: str = "en") -> list[Finding]:
    out: list[Finding] = []
    _ESCAPER_CACHE.clear()          # ids are reused once a tree is collected
    _ALIAS_CACHE.clear()
    for path, tree in index.trees.items():
        for func in [n for n in ast.walk(tree) if isinstance(n, FUNC)]:
            tainted, derived = _taint_of(func)
            joined = _priv_paths(func)
            tainted |= set(joined)
            sql_names = _sql_vars(func, tainted)
            text_names = _text_vars(func, derived)
            for call in [n for n in ast.walk(func) if isinstance(n, ast.Call)]:
                out.extend(_check(index, path, func, call, tainted, lang, joined, derived, sql_names,
                                  text_names))
    out.extend(_authz(index, lang))
    out.extend(_log_calls(index, lang))
    out.extend(_log_injection(index, lang))
    out.extend(_deser(index, lang))
    out.extend(_interproc(index, lang))
    out.extend(_mass_assignment(index, lang))
    out.extend(_no_timeout(index, lang))
    out.extend(_ssti(index, lang))
    out.extend(_nosql(index, lang))
    out.extend(_admin_route(index, lang))
    out.extend(_unbounded(index, lang))
    out.extend(_fail_open(index, lang))
    return out


LOG_FUNC = re.compile(r"(?:^|\.)(?:log|logger|logging|console)\.?\w*$|^print$")
SENSITIVE = re.compile(r"password|passwd|token|secret|api_?key|cookie|credential", re.I)
_NOISE = re.compile(
    r"(?:^|_)(?:count|len|size|ttl|expiry|expires|age|id|name|path|url|type|header)$", re.I)
_COUNTISH = re.compile(
    r"^(?:before|after|num|max|min|total|input|output|prompt|completion|new|estimate|count|budget|window)_"
    r".*_?tokens?$", re.I)


def _noise(name: str) -> bool:
    return bool(_NOISE.search(name) or _COUNTISH.search(name))


DESER_FUNCS = {"pickle.loads", "pickle.load", "cPickle.loads", "marshal.loads", "yaml.load"}


def _deser(index: ProjectIndex, lang: str) -> list[Finding]:
    """Real calls only — a docstring that names pickle.loads is not a finding."""
    out: list[Finding] = []
    for path, tree in index.trees.items():
        text = index.texts.get(path, "")
        for call in [n for n in ast.walk(tree) if isinstance(n, ast.Call)]:
            name = _call_name(call.func)
            if name not in DESER_FUNCS:
                continue
            if name.startswith("yaml") and any(
                    k.arg == "Loader" and "Safe" in ast.unparse(k.value) for k in call.keywords):
                continue
            line = call.lineno
            src = line_at(text, line).rstrip()
            fixed = src.replace("pickle.loads", "json.loads").replace("pickle.load", "json.load")
            fixed = fixed.replace("yaml.load", "yaml.safe_load").replace("marshal.loads", "json.loads")
            out.append(_emit("code/unsafe-deserialization", index, path, line, lang=lang,
                             minus=[src], plus=[fixed] if fixed != src else []))
    return out


def _log_calls(index: ProjectIndex, lang: str) -> list[Finding]:
    """Only a *reference* to a secret is a finding — the word inside a message is not."""
    out: list[Finding] = []
    for path, tree in index.trees.items():
        text = index.texts.get(path, "")
        for call in [n for n in ast.walk(tree) if isinstance(n, ast.Call)]:
            name = _call_name(call.func)
            if not re.search(r"(?:^|\.)(?:log|logger|logging|console)\.", name) and name not in ("print", "console.log"):
                continue
            for arg in list(call.args) + [k.value for k in call.keywords]:
                if isinstance(arg, ast.Constant):
                    continue
                identifiers = [n.id for n in ast.walk(arg) if isinstance(n, ast.Name)]
                identifiers += [n.attr for n in ast.walk(arg) if isinstance(n, ast.Attribute)]
                identifiers = [x for x in identifiers if not _noise(x)]
                if not any(SENSITIVE.search(x) for x in identifiers):
                    continue
                line = getattr(arg, "lineno", call.lineno)
                src = line_at(text, line).rstrip()
                segment = ast.get_source_segment(text, arg) or ""
                plus = [src.replace(segment, '"[redacted]"')] if segment else []
                out.append(_emit("log/sensitive-field", index, path, line, lang=lang, minus=[src],
                                 plus=plus, fix_kind="verified" if plus else None))
                break
    return out


LOG_CLEAN = re.compile(r"replace[(]|strip[(]|sanitize|escape|clean|quote|bleach", re.I)
NUMERIC_WRAP = ("int", "float", "bool", "len", "round")
NUMERIC_NAME = re.compile(r"(?:^|_)(?:id|ids|count|index|status|code|type)$", re.I)


def _log_injection(index: ProjectIndex, lang: str) -> list[Finding]:
    """CWE-117: an untrusted value written straight into a log line.

    The id/count filter is what keeps this usable: a numeric field cannot forge
    a second entry, a free-text one can.
    """
    out: list[Finding] = []
    for path, tree in index.trees.items():
        text = index.texts.get(path, "")
        for func in [n for n in ast.walk(tree) if isinstance(n, FUNC)]:
            tainted, derived = _taint_of(func)
            tainted -= {a.arg for a in func.args.args + func.args.kwonlyargs if len(a.arg) < 3}
            # Every parameter is "tainted" for the sink rules; for a log line that is
            # too loose — a CLI's `args` is not a request. Keep the ones that came
            # from the request, plus any handler in a file that imports a web framework.
            web = bool(WEB_FRAMEWORK.search(text))
            if not web:
                tainted &= derived
            # Sanitising at the assignment is the usual shape; follow it.
            for node in ast.walk(func):
                if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
                    if LOG_CLEAN.search(ast.get_source_segment(text, node.value) or ""):
                        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                        tainted -= {t_.id for t_ in targets if isinstance(t_, ast.Name)}
            if not tainted:
                continue
            for call in [n for n in ast.walk(func) if isinstance(n, ast.Call)]:
                # Only a logging call: `print` on a CLI writes to a terminal, which
                # is not the artifact an incident review reads back.
                if not LOG_SINK.search(_call_name(call.func)):
                    continue
                numeric = _numeric_args(call)
                for pos, arg in enumerate(call.args):
                    if pos in numeric:
                        continue
                    if isinstance(arg, ast.Constant):
                        continue
                    if isinstance(arg, ast.Call) and _call_name(arg.func).rsplit(".", 1)[-1] in NUMERIC_WRAP:
                        continue
                    segment = ast.get_source_segment(text, arg) or ""
                    if LOG_CLEAN.search(segment):
                        continue
                    names = {n.id for n in ast.walk(arg) if isinstance(n, ast.Name)}
                    names |= {n.attr for n in ast.walk(arg) if isinstance(n, ast.Attribute)}
                    free = [n for n in names & tainted if not NUMERIC_NAME.search(n)]
                    if not free:
                        continue
                    line = getattr(arg, "lineno", call.lineno)
                    out.append(_emit("log/injection", index, path, line, lang=lang,
                                     minus=[line_at(text, line).rstrip()]))
                    break
    return out


WEB_FRAMEWORK = re.compile(r"fastapi|flask|starlette|django|quart|sanic|aiohttp", re.I)
LOG_SINK = re.compile(r"(?:^|[.])(?:log|logger|logging)[.]"
                      r"(?:debug|info|warning|warn|error|exception|critical|fatal)$")
SPEC = re.compile(r"%[-+ #0]*[0-9.*]*(?:hh|h|ll|l|L|z|j|t)?([diouxXeEfFgGcrsa])")


def _numeric_args(call: ast.Call) -> set[int]:
    """Indexes of positional args bound to a numeric specifier: %d cannot carry a newline."""
    if not call.args or not isinstance(call.args[0], ast.Constant) or not isinstance(call.args[0].value, str):
        return set()
    kinds = [m.group(1) for m in SPEC.finditer(call.args[0].value)]
    numeric = {"d", "i", "o", "u", "x", "X", "e", "E", "f", "F", "g", "G"}
    return {i + 1 for i, kind in enumerate(kinds) if kind in numeric}   # args[0] is the format


def index_text(index: ProjectIndex, path: str) -> str:
    return index.texts.get(path, "")


SCHEME = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")


def _host_fixed(node: ast.AST) -> bool:
    """True when scheme *and* host are literals.

    `f"https://api.example.com/{id}"` fixes the host; `f"https://{host}/"` does
    not, even though its first literal contains `://`.
    """
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return bool(SCHEME.match(node.value))
    if isinstance(node, ast.JoinedStr) and node.values:
        head = node.values[0]
        if not (isinstance(head, ast.Constant) and isinstance(head.value, str)):
            return False
        m = SCHEME.match(head.value)
        if not m:
            return False
        rest = head.value[m.end():]
        return "/" in rest and bool(rest.split("/", 1)[0])
    return False


def _upload_shaped(arg: ast.AST, tainted: set[str]) -> bool:
    """An upload object's filename — not a helper's own `filename` parameter."""
    for a in ast.walk(arg):
        if isinstance(a, ast.Attribute) and a.attr in ("filename", "name"):
            return True
    return bool(_names(arg) & tainted & {n for n in _names(arg) if re.search(r"^upload", n, re.I)})


def _path_fix(src: str, base: str, tail: str, arg_name: str | None, is_python: bool,
              alias: str = "path") -> list[str]:
    indent = src[: len(src) - len(src.lstrip())]
    if is_python:
        lines = [f"{indent}target = (Path({base}) / {tail}).resolve()",
                 f"{indent}if not target.is_relative_to({base}): raise HTTPException(400)"]
        if arg_name:
            lines.append(src.replace(arg_name, "target", 1))
        return lines
    lines = [f"{indent}const target = {alias}.resolve({base}, {tail});",
             f"{indent}const rel = {alias}.relative({alias}.resolve({base}), target);",
             f"{indent}if (rel.startsWith('..') || {alias}.isAbsolute(rel)) return res.status(400).end();"]
    return lines


# A prefix test is not a host check: `https://api.example.com.attacker.example`
# starts with `https://api.example.com`. Only a parsed host, or a membership
# test on the URL itself, counts as evidence.
SSRF_HOST = re.compile(r"netloc|hostname|\bhost\b|urlparse|urlsplit", re.I)
SSRF_REJECT = re.compile(
    r"\braise\b|\bassert\b|\babort\b|HTTPException|sys[.]exit|not_found|forbidden|"
    r"\breturn\s+None\b", re.I)


def _rejects_when_not_allowed(test: ast.AST, is_host) -> bool:
    """The refusing branch has to refuse *every* request to a non-allowed host.

    `if host not in ALLOWED: raise` refuses outsiders; `if host in ALLOWED:
    raise` refuses the allowlist itself. The shape of an `and`/`or` matters:
    `host not in A or scheme != "https"` still refuses every non-allowed host,
    but `host not in A and role == "guest"` refuses only guests.
    """
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        inner = test.operand
        if not isinstance(inner, ast.Compare):
            return False                 # `not (a and b)`: too much to prove
        return _compare_rejects(inner, is_host, negated=True)
    if isinstance(test, ast.BoolOp):
        results = [_rejects_when_not_allowed(value, is_host) for value in test.values]
        # Or: any disjunct that refuses outsiders is enough (it fires either way).
        # And: every conjunct has to be a host refusal, or the branch can be skipped.
        return any(results) if isinstance(test.op, ast.Or) else all(results)
    if isinstance(test, ast.Compare):
        return _compare_rejects(test, is_host, negated=False)
    return False


def _compare_rejects(cmp_node: ast.Compare, is_host, negated: bool) -> bool:
    sides = [cmp_node.left, *cmp_node.comparators]
    if not any(is_host(side) for side in sides):
        return False                     # a check on something else is not a guard
    for op in cmp_node.ops:
        if isinstance(op, (ast.In, ast.Eq)):
            refuses_insiders = not negated
        elif isinstance(op, (ast.NotIn, ast.NotEq)):
            refuses_insiders = negated
        else:
            return False
        if refuses_insiders:             # `not (host not in A)` is `host in A`
            return False
    return True


def _url_family(func, seeds: set[str]) -> set[str]:
    """Every name that carries the same URL, in either direction.

    `request = Request(url)` and `parts = urlsplit(url)` are the same URL, so a
    check on either one is a check on the request that reaches the sink.
    """
    out = set(seeds)
    for _ in range(4):
        added = False
        for node in ast.walk(func):
            if not isinstance(node, (ast.Assign, ast.AnnAssign)) or node.value is None:
                continue
            value = node.value
            if isinstance(value, ast.Await):
                value = value.value
            if not isinstance(value, (ast.Call, ast.Name)):
                continue
            names = set(_names(value))
            targets = {t.id for t in (node.targets if isinstance(node, ast.Assign) else [node.target])
                       if isinstance(t, ast.Name)}
            new: set[str] = set()
            if names & out:                    # `parts = urlsplit(url)`
                new = targets - out
            elif targets & out:                # `request = Request(url)`
                new = names - out
            if new:
                out |= new
                added = True
        if not added:
            break
    return out


def _returns_value(stmts: list[ast.stmt]) -> bool:
    """Can any path through these statements hand a value back?"""
    for stmt in stmts:
        if isinstance(stmt, ast.Return):
            if not (stmt.value is None or (
                    isinstance(stmt.value, ast.Constant) and stmt.value.value is None)):
                return True
        elif isinstance(stmt, ast.If):
            if _returns_value(stmt.body) or _returns_value(stmt.orelse):
                return True
        elif isinstance(stmt, (ast.For, ast.AsyncFor, ast.While)):
            # `for ... else:` runs when the loop finishes without a break.
            if _returns_value(stmt.body) or _returns_value(stmt.orelse):
                return True
        elif isinstance(stmt, (ast.With, ast.AsyncWith)):
            if _returns_value(stmt.body):
                return True
        elif isinstance(stmt, ast.Match):
            if any(_returns_value(case.body) for case in stmt.cases):
                return True
        elif isinstance(stmt, (ast.Try,)):
            if (_returns_value(stmt.body) or _returns_value(stmt.orelse)
                    or _returns_value(stmt.finalbody)
                    or any(_returns_value(handler.body) for handler in stmt.handlers)):
                return True
        elif hasattr(ast, "TryStar") and isinstance(stmt, ast.TryStar):
            if (_returns_value(stmt.body) or _returns_value(stmt.orelse)
                    or _returns_value(stmt.finalbody)
                    or any(_returns_value(handler.body) for handler in stmt.handlers)):
                return True
    return False


def _block_refuses(stmts: list[ast.stmt]) -> bool:
    """Does every path through these statements refuse the request?

    Raising refuses, and so does returning nothing. `return doc` in an
    `except` handler hands the protected row back — that is not a refusal,
    whatever the handler was catching. A branch that might return a value is a
    leak even when a later statement refuses.
    """
    if _returns_value(stmts):
        return False
    for stmt in stmts:
        if isinstance(stmt, ast.Raise):
            return True
        if isinstance(stmt, ast.Return):
            return True                  # only bare returns reach here
        if isinstance(stmt, ast.If) and stmt.orelse:
            if _block_refuses(stmt.body) and _block_refuses(stmt.orelse):
                return True
    return False


def _line_in(stmts: list[ast.stmt], line: int) -> bool:
    """Is this line inside one of these statements (not a handler or finally)?"""
    for stmt in stmts:
        start = getattr(stmt, "lineno", 0)
        end = getattr(stmt, "end_lineno", None) or start
        if start <= line <= end:
            return True
    return False


def _dominates(func, target: ast.AST, sink_line: int, sink: ast.AST | None = None,
               tree=None) -> bool:
    """Does this guard run before the sink, on every path that reaches it?

    The same path analysis the ownership check uses: no enclosing branch, a
    `try` whose handlers all refuse, and a sink inside the same block — checked
    on the AST, so a nested `finally:` inside the body does not count as body.
    """
    if getattr(target, "lineno", 0) >= sink_line:
        return False
    return _guarded_path(func, target, sink_line, sink, tree)


def _ssrf_guarded(index, path: str, func, url_names: set[str], sink_line: int,
                  sink: ast.AST | None = None, tree=None) -> bool:
    """A guard has to compare *this* URL's host, in the direction that refuses outsiders.

    `if ALLOWED_HOSTS:` proves nothing, and neither does a prefix test:
    `https://api.example.com.attacker.example` passes `startswith()`. What counts
    is `if urlparse(url).netloc not in ALLOWED:` or `if url not in ALLOWED:`.
    The URL may be parsed into a local first: `parts = urlsplit(url)`.
    """
    if not url_names:
        return False
    known = _url_family(func, url_names)

    def is_host(expr: ast.AST) -> bool:
        """`url`, `parts.hostname` or `urlparse(url).netloc` — not `role`."""
        if not (_names(expr) & known):
            return False
        if isinstance(expr, ast.Name):
            return expr.id in known
        if isinstance(expr, ast.Attribute):
            return expr.attr in ("hostname", "netloc", "host")
        return False

    src = index_text(index, path)
    for node in ast.walk(func):
        if not isinstance(node, ast.If):
            continue
        if not _dominates(func, node, sink_line, sink, tree):
            continue                  # a guard that can be skipped is not a guard
        test = node.test
        test_src = ast.get_source_segment(src, test) or ""
        if not (set(_names(test)) & known):
            continue
        membership = isinstance(test, ast.Compare) and any(
            isinstance(op, (ast.In, ast.NotIn)) for op in test.ops)
        if not (SSRF_HOST.search(test_src) or membership):
            continue
        if not _rejects_when_not_allowed(test, is_host):
            continue
        body_src = "\n".join(ast.get_source_segment(src, s) or "" for s in node.body)
        if SSRF_REJECT.search(body_src) or _rejects(node.body):
            return True
    return False


def _check(index, path, func, call, tainted, lang, joined: dict | None = None,
           derived: set[str] | None = None, sql_names: dict[str, int] | None = None,
           text_names: set[str] | None = None) -> list[Finding]:
    out: list[Finding] = []
    name = _call_name(call.func)
    short = name.rsplit(".", 1)[-1]
    line = getattr(call, "lineno", func.lineno)
    src = line_at(index.texts.get(path, ""), line).rstrip()
    if getattr(call, "end_lineno", line) and call.end_lineno > line:
        src += " …"
    args = list(call.args)
    if not args:
        return out
    first = args[0]

    if short in SQL_SINKS:
        rendered = ast.unparse(first)
        inline = (isinstance(first, (ast.JoinedStr, ast.BinOp, ast.Call))
                  and bool(SQL_KW.search(rendered)) and bool(_names(first) & tainted))
        carried = isinstance(first, ast.Name) and first.id in (sql_names or {})
        if inline or carried:
            prefix = src[: src.find(name)] if name in src else ""
            out.append(_emit("code/sql-string-built", index, path, line, lang=lang, minus=[src],
                             plus=[f'{prefix}{name}("SELECT ... WHERE id = ?", (value,))']))

    elif name in SHELL_SINKS:
        shell_kw = next((k for k in call.keywords if k.arg == "shell"), None)
        uses_shell = bool(shell_kw and isinstance(shell_kw.value, ast.Constant) and shell_kw.value.value is True)
        argv_form = isinstance(first, (ast.List, ast.Tuple)) and not uses_shell
        # A call result (our own helper returning argv) and a bare constant are
        # both fine; only interpolated text or a tainted name is a real risk.
        # A bare name is the caller's argv; only text the shell would re-parse
        # (f-string / concatenation) or an explicit shell=True is ours to report.
        dynamic = isinstance(first, ast.JoinedStr) or (
            isinstance(first, ast.BinOp) and isinstance(first.op, ast.Add)
            and (isinstance(first.left, ast.Constant) or isinstance(first.right, ast.Constant))) \
            or (isinstance(first, ast.Name) and first.id in (text_names or set()))
        carries = bool(_names(first) & tainted) or (
            isinstance(first, ast.Name) and first.id in (text_names or set()))
        everything_constant = isinstance(first, ast.Constant) and all(
            isinstance(a, ast.Constant) for a in call.args[1:])
        # shell=True on a command assembled from config is the tool's own design;
        # what matters is whether request data reaches it.
        if not argv_form and not everything_constant and (uses_shell or dynamic) and carries:
            out.append(_emit("code/command-injection", index, path, line, lang=lang, minus=[src],
                             plus=["subprocess.run([cmd, *args], shell=False)"]))

    elif short in PATH_SINKS:
        arg = first
        uploadish = _upload_shaped(arg, tainted) or (
            isinstance(arg, ast.Name) and bool(joined) and arg.id in joined)
        # A value read through the request, not any local called `payload` and
        # not `urllib.request.Request` handed to an opener.
        from_request = bool(REQUEST_READ.search(ast.unparse(arg))) or bool(
            _names(arg) & (derived or set()))
        if not (uploadish or from_request):
            return out
        py = path.endswith(".py")
        alias = _path_alias(index.texts.get(path, ""))
        if isinstance(arg, ast.Name) and joined and arg.id in joined:
            base, tail = joined[arg.id]
            out.append(_emit("upload/path-from-filename", index, path, line, lang=lang, minus=[src],
                             plus=_path_fix(src, base, tail, arg.id, py, alias)))
        elif isinstance(arg, ast.Call) and _call_name(arg.func).endswith("join") and (uploadish or from_request):
            parts = [ast.unparse(a) for a in arg.args]
            fix = _path_fix(src, parts[0], " / ".join(parts[1:]), None, py, alias) if len(parts) >= 2 else []
            seg = ast.get_source_segment(index.texts.get(path, ""), arg) or ""
            if seg:
                fix.append(src.replace(seg, "target", 1))   # the sink must use the checked path
            out.append(_emit("upload/path-from-filename", index, path, line, lang=lang, minus=[src], plus=fix or None))
        elif isinstance(arg, ast.BinOp) and (_names(arg.right) & tainted):
            out.append(_emit("upload/path-from-filename", index, path, line, lang=lang, minus=[src]))
        else:
            # A value read from the request that passed the checks above: report
            # it even though there is no tailored fix for this shape.
            out.append(_emit("upload/path-from-filename", index, path, line, lang=lang, minus=[src]))

    elif (short in {"HTMLResponse", "Markup"} and (_names(first) & tainted)
          and not _already_escaped(first, _escaper_context(index.trees.get(path)),
                                   _rebound_in(func))):
        out.append(_emit("code/xss-output", index, path, line, lang=lang, minus=[src],
                         plus=["# escape every interpolated value before it reaches the response"]))

    elif short in SSRF_SINKS and name.split(".")[0] in ("requests", "httpx", "urllib"):
        # A URL whose scheme and host are literals cannot be redirected inward;
        # only the path is attacker-controlled there.
        if _host_fixed(first):
            return out
        tainted_names = _names(first) & tainted
        url_ish = any(re.search(r"url|uri|link|endpoint|target|host|dest", n, re.I) for n in tainted_names)
        if _ssrf_guarded(index, path, func, tainted_names, line, call,
                         index.trees.get(path)):
            return out
        if tainted_names and (url_ish or REQUEST_SRC.search(ast.unparse(first))):
            out.append(_emit("code/ssrf", index, path, line, lang=lang, minus=[src],
                             plus=["requests.get(url, allow_redirects=False)  # after host allowlist check"]))
    return out


_DB_GET = re.compile(r"\bdb\.get\(|\bsession\.get\(|\bquery\.get\(|\.filter_by\(|\.filter\(")
_OWNER = re.compile(r"owner|tenant|user_id|account_id|belongs", re.I)
_ID_PARAM = re.compile(r"^(?:\w+_)?id$", re.I)
ROLE_WORD = re.compile(r"role|is_seller|is_admin|is_staff|has_role", re.I)
OWNER_WORD = re.compile(r"owner|tenant|belongs", re.I)
CALLER_WORD = re.compile(r"current_user|request|principal|auth|session|user", re.I)
PUBLIC_PREFIX = re.compile(r"^/(?:health|healthz|ping|metrics|docs|openapi|redoc|static|favicon)(?:/|$)", re.I)


def _names_like(node: ast.AST, pattern) -> bool:
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name) and pattern.search(sub.id):
            return True
        if isinstance(sub, ast.Attribute) and pattern.search(sub.attr):
            return True
    return False


def _rejects(body: list[ast.stmt]) -> bool:
    """Does this run of statements refuse the request (raise, or return nothing)?"""
    for stmt in body:
        if isinstance(stmt, ast.Raise):
            continue
        if isinstance(stmt, ast.Return) and (
                stmt.value is None
                or (isinstance(stmt.value, ast.Constant) and stmt.value.value is None)):
            continue
        return False
    return bool(body)


def _owner_compare(test: ast.Compare) -> bool:
    """A comparison whose sides are the row's owner and the caller, in one direction.

    Only `==` / `in` count here: inside a query filter, `!=` selects the rows
    that belong to somebody else.
    """
    if not test.ops or type(test.ops[0]) not in (ast.Eq, ast.In):
        return False
    sides = [test.left, *test.comparators]
    owner_only = [s for s in sides if _names_like(s, OWNER_WORD) and not _names_like(s, CALLER_WORD)]
    caller_only = [s for s in sides if _names_like(s, CALLER_WORD) and not _names_like(s, OWNER_WORD)]
    return bool(owner_only and caller_only)


def _positive_role(test: ast.AST) -> bool:
    """`user.is_admin` gates an alternative path; `not user.is_admin` does not."""
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        return False
    if isinstance(test, ast.Compare) and any(
            isinstance(op, (ast.NotEq, ast.NotIn)) for op in test.ops):
        return False
    return bool(ROLE_WORD.search(ast.unparse(test)))


def _else_refuses(orelse: list[ast.stmt]) -> bool:
    """Every path through the else branch has to refuse.

    `else: raise` does; `else: return order` does not; a nested conditional is
    followed branch by branch, so `else: if admin: raise; else: return order` is
    not a refusal either. `elif user.is_admin: return order` is an authorised
    alternative and is allowed.
    """
    for stmt in orelse:
        if isinstance(stmt, ast.Raise):
            continue
        if isinstance(stmt, ast.Return):
            if stmt.value is None or (isinstance(stmt.value, ast.Constant) and stmt.value.value is None):
                continue
            return False
        if isinstance(stmt, ast.If):
            if _positive_role(stmt.test) and _returns_value(stmt.body):
                if not stmt.orelse or _else_refuses(stmt.orelse):
                    continue
                return False
            if _else_refuses(stmt.body) and (not stmt.orelse or _else_refuses(stmt.orelse)):
                continue
            return False
        if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
            if re.search(r"abort|forbidden|not_found", _call_name(stmt.value.func), re.I):
                continue
        return False
    return True


def _later_rejects(func, target: ast.If) -> bool:
    """After this `if` on a match, does the non-match path still refuse?

    `if owner == user: return order` followed by `return order` returns the row
    either way. Nothing after the `if` means the function falls off and returns
    None, which does refuse.
    """
    for node in ast.walk(func):
        for field_name in ("body", "orelse", "finalbody"):
            body = getattr(node, field_name, None)
            if not isinstance(body, list) or target not in body:
                continue
            if target.orelse and not _else_refuses(target.orelse):
                return False                  # `else: return order`
            rest = body[body.index(target) + 1:]
            return True if not rest else _rejects(rest)
    return False


_OWNER_OPS = {ast.Eq: True, ast.In: True, ast.NotEq: False, ast.NotIn: False}


def _assigned_at(func, line: int) -> str | None:
    """The name a database load on this line is assigned to.

    `audit.query(...); order = db.get(Order, id)` puts two calls on one line; the
    resource is still the one whose result is bound, not the one beside it.
    """
    for node in ast.walk(func):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)) or node.value is None:
            continue
        if getattr(node, "lineno", None) != line:
            continue
        value = node.value
        if isinstance(value, ast.Await):
            value = value.value
        if not isinstance(value, ast.Call) or not _DB_GET.search(ast.unparse(value)):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        for target in targets:
            if isinstance(target, ast.Name):
                return target.id
    return None


_ALIAS_CACHE: dict[int, dict[str, str]] = {}


def _scope_aliases(body: list[ast.stmt]) -> dict[str, str]:
    """Local name -> dotted source, for one scope only.

    A function's own `import` shadows the module's, and a nested function has
    its own names — two functions may import different things as `ignore`.
    """
    aliases: dict[str, str] = {}

    def bind(name: str, source: str) -> None:
        current = aliases.get(name)
        if current is None or current == source:
            aliases[name] = source
        else:
            aliases[name] = "?"               # rebound to something else: unknown

    def walk(stmts: list[ast.stmt]) -> None:
        for stmt in stmts:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue                      # its names belong to its own scope
            if isinstance(stmt, ast.Import):
                for alias in stmt.names:
                    if alias.asname:
                        bind(alias.asname, alias.name)
            elif isinstance(stmt, ast.ImportFrom) and stmt.module:
                for alias in stmt.names:
                    if alias.name != "*":
                        bind(alias.asname or alias.name, f"{stmt.module}.{alias.name}")
            elif isinstance(stmt, ast.Assign) and isinstance(stmt.value, ast.Name):
                source = aliases.get(stmt.value.id, stmt.value.id)
                for target in stmt.targets:
                    if isinstance(target, ast.Name):
                        bind(target.id, source)
            for field in ("body", "orelse", "finalbody"):
                sub = getattr(stmt, field, None)
                if isinstance(sub, list) and sub and isinstance(sub[0], ast.stmt):
                    walk(sub)
            for handler in getattr(stmt, "handlers", None) or []:
                if isinstance(handler, ast.ExceptHandler):
                    walk(handler.body)
            if isinstance(stmt, ast.Match):
                for case in stmt.cases:       # `match` branches can import too
                    walk(case.body)

    walk(body)
    return aliases


def _aliases_for(node) -> dict[str, str]:
    if node is None:
        return {}
    key = id(node)
    hit = _ALIAS_CACHE.get(key)
    if hit is not None:
        return hit
    body = node.body if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef)) else []
    table = _scope_aliases(body)
    _ALIAS_CACHE[key] = table
    return table


def _is_suppress_call(expr: ast.AST, tree, func=None) -> bool:
    """`suppress(...)`, `contextlib.suppress(...)`, `ignore(...)` after an import alias."""
    if not isinstance(expr, ast.Call):
        return False
    name = _call_name(expr.func)
    aliases = dict(_aliases_for(tree))
    aliases.update(_aliases_for(func))        # the function's own names win
    if "." in name:
        head, _, rest = name.partition(".")
        resolved = aliases.get(head, head)
        if resolved == "?":                   # rebound twice: cannot prove it is safe
            return True
        name = f"{resolved}.{rest}"
    else:
        resolved = aliases.get(name, name)
        if resolved == "?":
            return True
        name = resolved
    return name.rsplit(".", 1)[-1] == "suppress"


def _swallowing_classes(tree) -> set[str]:
    """Classes in this file whose `__exit__` can return something truthy."""
    if tree is None:
        return set()
    key = ("classes", id(tree))
    hit = _ALIAS_CACHE.get(key)               # type: ignore[arg-type]
    if hit is not None:
        return set(hit)                       # type: ignore[arg-type]
    out: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        for item in node.body:
            if not isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if item.name not in ("__exit__", "__aexit__"):
                continue
            for sub in ast.walk(item):
                if not isinstance(sub, ast.Return) or sub.value is None:
                    continue                  # bare `return` hands the exception on
                value = sub.value
                if isinstance(value, ast.Constant) and value.value in (None, False, 0, ""):
                    continue                  # provably not swallowing
                # `return True`, `return exc_type is X`, `bool(exc_type)`,
                # `handled`, `self.suppress` — anything we cannot prove false.
                out.add(node.name)
    _ALIAS_CACHE[key] = {name: name for name in out}   # type: ignore[index]
    return out


def _guarded_path(func, target: ast.AST, sink_line: int | None = None,
                  sink: ast.AST | None = None, tree=None) -> bool:
    """Walk up to the function: every ancestor must run unconditionally.

    A guard inside `if`/`for`/`while` runs only sometimes, so it proves nothing.
    A guard inside `try:` is only as good as its handlers: one that swallows the
    rejection lets the next statement run anyway. When `sink_line` is given, the
    sink has to sit inside the same block as the guard.
    """
    parents: dict[int, ast.AST] = {}
    for node in ast.walk(func):
        for child in ast.iter_child_nodes(node):
            parents[id(child)] = node

    def inside(stmts: list[ast.stmt]) -> bool:
        """Is the sink really inside these statements — not in a handler or finally?

        Climbing to the statement is not enough: `try: ... finally: fetch(url)`
        is inside the statement but not inside its body, and the finally runs
        after the rejection.
        """
        if sink is None:
            return sink_line is not None and _line_in(stmts, sink_line)
        path: list[ast.AST] = []
        node: ast.AST | None = sink
        while node is not None:
            path.append(node)
            if node is func:
                break
            node = parents.get(id(node))
        target = next((i for i, n in enumerate(path) if any(n is s for s in stmts)), None)
        if target is None:
            return False
        block_types = (ast.Try, ast.With, ast.AsyncWith)
        if hasattr(ast, "TryStar"):
            block_types = block_types + (ast.TryStar,)
        for i in range(target):           # every block below the target
            parent = path[i + 1]
            if isinstance(parent, block_types) and path[i] not in getattr(parent, "body", []):
                return False
        return True

    try_types = (ast.Try, ast.TryStar) if hasattr(ast, "TryStar") else (ast.Try,)
    node: ast.AST = target
    while node is not func:
        parent = parents.get(id(node))
        if parent is None:
            return False
        if parent is func:
            return True
        if not isinstance(parent, ast.stmt):
            # An expression runs when its statement does — unless it is a lambda
            # body or a comprehension, which may never run at all.
            if isinstance(parent, (ast.Lambda, ast.ListComp, ast.SetComp,
                                   ast.DictComp, ast.GeneratorExp)):
                return False
            node = parent
            continue
        if isinstance(parent, ast.If):
            if node is parent.test:       # a call in the condition always runs
                node = parent
                continue
            return False
        if isinstance(parent, (ast.For, ast.AsyncFor, ast.While, ast.Match)):
            return False
        if isinstance(parent, (ast.With, ast.AsyncWith)):
            # `with suppress(HTTPException):` swallows the rejection this guard
            # raises, and the statement after the block still runs.
            items = getattr(parent, "items", None) or []
            swallowers = _swallowing_classes(tree)
            for item in items:
                if _is_suppress_call(item.context_expr, tree, func):
                    return False
                expr = item.context_expr
                if isinstance(expr, ast.Call):
                    called = _call_name(expr.func)
                    head = called.rsplit(".", 1)[-1]
                    names = dict(_aliases_for(tree))
                    names.update(_aliases_for(func))
                    resolved = names.get(head, head)
                    if resolved == "?" or resolved.rsplit(".", 1)[-1] in swallowers:
                        return False      # a local `__exit__` that may swallow
            if (sink_line is not None or sink is not None) and not inside(parent.body):
                return False
            node = parent
            continue
        if isinstance(parent, try_types):
            if node not in parent.body:
                return False
            if not all(_block_refuses(handler.body) for handler in parent.handlers):
                return False             # `except Exception: pass` lets it through
            if (sink_line is not None or sink is not None) and not inside(parent.body):
                return False             # the sink sits in a handler or a finally
            node = parent
            continue
        node = parent                     # a plain statement: it runs with its block
        continue
    return True


def _unconditional(func, target: ast.AST, tree=None) -> bool:
    """Is this statement reached whenever the function runs — not inside a branch?"""
    return _guarded_path(func, target, tree=tree)


def _owner_evidence(node: ast.AST, anchor: str | None = None,
                    anchor_line: int | None = None, tree=None) -> bool:
    """A constraint ties the row to the caller, and it has to point the right way.

    `if order.owner_id:` proves nothing, and `if order.owner_id != user.id: return order`
    hands the row to the wrong caller. What counts is a query keyword whose value
    is the caller, or a guard that lets a match through and rejects a mismatch.
    """
    def about_the_resource(sub: ast.AST) -> bool:
        """A constraint on another table does not protect this row."""
        if anchor is None:
            return True
        if _names_like(sub, re.compile(rf"(?:^|[.]?){re.escape(anchor)}$")):
            return True
        # `order = db.get(Order, id, owner_id=user.id)`: the call that produces
        # the anchor is the resource, even though it does not spell the name.
        # Another call that merely shares the line is not.
        if anchor_line is not None and getattr(sub, "lineno", None) == anchor_line:
            for stmt in ast.walk(node):
                if not isinstance(stmt, (ast.Assign, ast.AnnAssign)) or stmt.value is None:
                    continue
                value = stmt.value
                if isinstance(value, ast.Await):          # `order = await db.get(...)`
                    value = value.value
                if value is not sub:
                    continue
                targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
                if any(isinstance(x, ast.Name) and x.id == anchor for x in targets):
                    return True
        return False

    for sub in ast.walk(node):
        if not isinstance(sub, ast.Call):
            continue
        callee = _call_name(sub.func)
        if not re.search(r"(?:get|filter|find|query|select|execute|where|fetch|load|db|session)", callee, re.I):
            continue                     # audit_event(owner_id=...) is not a query
        if not about_the_resource(sub):
            continue
        if not _unconditional(node, sub, tree):
            continue          # `if STRICT: db.get(..., owner_id=...)` protects one branch
        for kw in sub.keywords:
            if kw.arg and OWNER_WORD.search(kw.arg) and _names_like(kw.value, CALLER_WORD):
                return True
        for arg in list(sub.args) + [k.value for k in sub.keywords]:
            # `.filter(Order.owner_id == user.id)` is a constraint even without a keyword
            if isinstance(arg, ast.Compare) and _owner_compare(arg):
                return True
    for sub in ast.walk(node):
        if not isinstance(sub, ast.If):
            continue
        if not about_the_resource(sub.test):
            continue
        test, negated = sub.test, False
        if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            test, negated = test.operand, True
        if not isinstance(test, ast.Compare) or not test.ops:
            continue
        if type(test.ops[0]) not in _OWNER_OPS:
            continue
        sides = [test.left, *test.comparators]
        owner_only = [s for s in sides if _names_like(s, OWNER_WORD) and not _names_like(s, CALLER_WORD)]
        caller_only = [s for s in sides if _names_like(s, CALLER_WORD) and not _names_like(s, OWNER_WORD)]
        if not (owner_only and caller_only):
            continue
        matched = _OWNER_OPS[type(test.ops[0])]
        if negated:
            matched = not matched
        # The body runs when the comparison holds. If holding means "this row is
        # the caller's", the path that does not hold has to refuse. If holding
        # means "it is not the caller's", this body has to refuse.
        # A check inside `if role == "admin":` protects that branch only; the
        # caller who is not an admin still reaches the row.
        if not _unconditional(node, sub, tree):
            continue
        if matched:
            if _later_rejects(node, sub):
                return True
        elif _rejects(sub.body):
            return True
    return False


def _function_at(index: ProjectIndex, path: str, line: int):
    tree = index.trees.get(path)
    if tree is None:
        return None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.lineno == line:
            return node
    return None


def _role_guarded_only(index: ProjectIndex, route) -> ast.If | None:
    """The article's seller/shopper shape: the ownership check sits inside one role branch."""
    func = _function_at(index, route.file, route.line)
    if func is None:
        return None
    guarded = [n for n in ast.walk(func)
               if isinstance(n, ast.If) and ROLE_WORD.search(ast.unparse(n.test))
               and _owner_evidence(n)]
    if not guarded:
        return None
    for stmt in func.body:                      # is the check repeated outside the branch?
        if any(stmt is g for g in guarded):
            continue
        if _owner_evidence(stmt):
            return None
    return guarded[0]


TEMPLATE_SINKS = {"render_template_string", "from_string", "Template"}
MONGO_METHODS = {"find", "find_one", "update_one", "update_many", "delete_one",
                 "delete_many", "replace_one", "count_documents", "aggregate"}
MONGO_HINT = re.compile(r"mongo|pymongo|motor", re.I)
ADMIN_PATH = re.compile(r"/(?:admin|internal|manage|staff|backoffice)(?:/|$)", re.I)
ROLE_DEP = re.compile(r"admin|role|permission|scope|superuser|staff|authoriz", re.I)
PAGING = re.compile(r"^(?:limit|page|page_size|per_page|size|offset|take)$", re.I)
VERIFY_NAME = re.compile(r"^(?:verify|validate|check|auth|can|has|is)_?\w*$", re.I)


def _ssti(index: ProjectIndex, lang: str) -> list[Finding]:
    """CWE-1336: the request supplies the template itself, not only its variables."""
    out: list[Finding] = []
    for path, tree in index.trees.items():
        text = index.texts.get(path, "")
        jinja = "jinja2" in text
        for func in [n for n in ast.walk(tree) if isinstance(n, FUNC)]:
            tainted, _ = _taint_of(func)
            for call in [n for n in ast.walk(func) if isinstance(n, ast.Call)]:
                short = _call_name(call.func).rsplit(".", 1)[-1]
                if short not in TEMPLATE_SINKS or not call.args:
                    continue
                if short in ("Template", "from_string") and not jinja:
                    continue                      # some other library's Template
                first = call.args[0]
                if isinstance(first, ast.Constant) or not (_names(first) & tainted):
                    continue
                line = getattr(call, "lineno", func.lineno)
                out.append(_emit("code/ssti", index, path, line, lang=lang,
                                 minus=[line_at(text, line).rstrip()]))
    return out


def _nosql(index: ProjectIndex, lang: str) -> list[Finding]:
    """A filter built from the body can smuggle `$gt` / `$where` operators."""
    out: list[Finding] = []
    for path, tree in index.trees.items():
        text = index.texts.get(path, "")
        mongo = bool(MONGO_HINT.search(text))
        for func in [n for n in ast.walk(tree) if isinstance(n, FUNC)]:
            tainted, derived = _taint_of(func)
            if not tainted:
                continue
            for call in [n for n in ast.walk(func) if isinstance(n, ast.Call)]:
                name = _call_name(call.func)
                short = name.rsplit(".", 1)[-1]
                if short not in MONGO_METHODS or not call.args:
                    continue
                if not mongo and not re.search(r"(?:^|[.])(?:db|collection|col)", name, re.I):
                    continue                      # list.find / ElementTree.find
                first = call.args[0]
                line = getattr(call, "lineno", func.lineno)
                src = line_at(text, line).rstrip()
                where = "$where" in src and bool(_names(first) & tainted)
                loose = isinstance(first, ast.Name) and first.id in derived
                if not (where or loose):
                    continue
                out.append(_emit("code/nosql-injection", index, path, line, lang=lang, minus=[src]))
    return out


def _admin_route(index: ProjectIndex, lang: str) -> list[Finding]:
    """BFLA: the path says admin, the dependency list says only "logged in"."""
    out: list[Finding] = []
    for route in index.routes:
        if not route.has_auth or not ADMIN_PATH.search(route.path):
            continue
        if any(ROLE_DEP.search(dep) for dep in route.depends):
            continue
        src = line_at(index.texts.get(route.file, ""), route.line).rstrip()
        body = src.rstrip()
        if body.endswith(":"):
            body = body[:-1]
        fixed = (body[:-1] + ", admin=Depends(require_admin)):"
                 if body.endswith(")") else src + "  # + admin=Depends(require_admin)")
        out.append(_emit("authz/admin-route-unprotected", index, route.file, route.line, lang=lang,
                         minus=[src], plus=[fixed],
                         evidence=[Evidence("route", route.file, route.line,
                                            f"{route.method} {route.path}")]))
    return out


def _unbounded(index: ProjectIndex, lang: str) -> list[Finding]:
    """API4: a list endpoint with no ceiling, on a table that only grows."""
    out: list[Finding] = []
    for route in index.routes:
        func = _function_at(index, route.file, route.line)
        params = {a.arg for a in func.args.args + func.args.kwonlyargs} if func is not None else set()
        if any(PAGING.match(p) for p in params):
            continue
        body = route.body
        if ".all()" not in body.replace(" ", ""):
            continue
        if re.search("[.]limit[ ]*[(]|LIMIT[ ]+[0-9]", body):
            continue
        offset = next((off for off, text in enumerate(body.splitlines()) if ".all()" in text), None)
        if offset is None:
            continue
        line = route.line + offset
        out.append(_emit("api/unbounded-query", index, route.file, line, lang=lang,
                         minus=[line_at(index.texts.get(route.file, ""), line).rstrip()]))
    return out


def _fail_open(index: ProjectIndex, lang: str) -> list[Finding]:
    """A check that returns True when it throws is not a check."""
    out: list[Finding] = []
    for path, tree in index.trees.items():
        text = index.texts.get(path, "")
        for func in [n for n in ast.walk(tree) if isinstance(n, FUNC)]:
            if not VERIFY_NAME.match(func.name):
                continue
            for node in ast.walk(func):
                if not isinstance(node, ast.Try):
                    continue
                for handler in node.handlers:
                    body = [s for s in handler.body if not isinstance(s, ast.Expr)]
                    if len(body) != 1:
                        continue
                    stmt = body[0]
                    swallow = isinstance(stmt, ast.Pass) or (
                        isinstance(stmt, ast.Return) and isinstance(stmt.value, ast.Constant)
                        and stmt.value.value is True)
                    if not swallow:
                        continue
                    line = getattr(stmt, "lineno", handler.lineno)
                    src = line_at(text, line).rstrip()
                    indent = src[: len(src) - len(src.lstrip())]
                    if isinstance(stmt, ast.Pass):
                        plus = [f"{indent}raise"]
                    else:
                        plus = [src.replace("True", "False")]
                    out.append(_emit("code/fail-open", index, path, line, lang=lang,
                                     minus=[src], plus=plus))
    return out


def _authz(index: ProjectIndex, lang: str) -> list[Finding]:
    out: list[Finding] = []
    for route in index.routes:
        src = line_at(index.texts.get(route.file, ""), route.line).rstrip()
        if not route.has_auth and not PUBLIC_PREFIX.search(route.path):
            body = src.rstrip()
            if body.endswith(":"):
                body = body[:-1]
            if body.endswith(")"):
                fixed = body[:-1] + ", user=Depends(get_current_user)):"
            else:
                fixed = src + "  # + user=Depends(get_current_user)"
            out.append(_emit("authz/route-without-auth", index, route.file, route.line, lang=lang,
                             minus=[src], plus=[fixed],
                             status=None if not route.depends else Status.NEEDS_REVIEW,
                             evidence=[Evidence("route", route.file, route.line, f"{route.method} {route.path}")]))
        untyped = [n for n, ann in route.params if ann in ("dict", "Dict", "Mapping", "Any", "object")]
        if untyped:
            out.append(_emit("input/untyped-body", index, route.file, route.line, lang=lang,
                             minus=[src],
                             plus=[re.sub(r":\s*(?:dict|Dict|Mapping|Any)\b",
                                          f": {route.func.title()}In", src)]))
        branch = _role_guarded_only(index, route)
        if branch is not None:
            text = line_at(index.texts.get(route.file, ""), branch.lineno).rstrip()
            indent = text[: len(text) - len(text.lstrip())]
            out.append(_emit("authz/partial-role-check", index, route.file, branch.lineno, lang=lang,
                             minus=[text],
                             plus=[f"{indent}# move the ownership constraint into the query",
                                   f"{indent}# so every role shares it"],
                             evidence=[Evidence("route", route.file, route.line, f"{route.method} {route.path}")]))
            continue
        func = _function_at(index, route.file, route.line)
        if not _DB_GET.search(route.body):
            continue
        ids = [p for p in route.tainted if _ID_PARAM.match(p)]
        if not ids:
            continue
        # The resource line is the `get(...)` that produced it, not any `.filter()`
        # earlier in the handler: an audit-log filter protects the audit log.
        body_line, fallback = route.line, None
        for offset, text in enumerate(route.body.splitlines()):
            if not _DB_GET.search(text):
                continue
            if re.search(r"(?:db|session|query)[.]get[(]", text):
                body_line = route.line + offset
                break
            fallback = fallback if fallback is not None else route.line + offset
        else:
            if fallback is not None:
                body_line = fallback
        original = line_at(index.texts.get(route.file, ""), body_line).rstrip()
        anchor = _assigned_at(func, body_line) if func is not None else None
        if anchor is None:
            m = re.match(r"\s*([A-Za-z_][A-Za-z0-9_]*)\s*=(?!=)", original)
            anchor = m.group(1) if m else None
        if func is not None and _owner_evidence(func, anchor, body_line,
                                                index.trees.get(route.file)):
            continue
        if func is None and _OWNER.search(route.body):     # no AST: fall back to text
            continue
        indent = original[: len(original) - len(original.lstrip())]
        model = re.search(r"\.get\(\s*([A-Za-z_][A-Za-z0-9_]*)", original)
        model_name = model.group(1) if model else "Model"
        cut = original.find(".get(")
        prefix = original[:cut] if cut >= 0 else indent
        # Built by concatenation, not an f-string: scanners that look for a query
        # interpolated into an f-string would read this suggestion as one.
        pad = " " * (len(prefix) + 4)
        out.append(_emit("authz/query-without-owner", index, route.file, body_line, lang=lang,
                         minus=[original],
                         plus=[prefix + ".scalar(select(" + model_name + ").where(",
                               pad + model_name + ".id == " + ids[0] + ",",
                               pad + model_name + ".owner_id == user.id))  "
                               + "# needs: from sqlalchemy import select"],
                         evidence=[Evidence("route", route.file, route.line, f"{route.method} {route.path}"),
                                   Evidence("query", route.file, body_line, line_at(index.texts.get(route.file, ""), body_line).strip())]))
    return out
