"""wrasse core — models, scan scope, and the project index (L0).

Nothing in this module may import a model client or perform network I/O.
`tests/test_boundary.py` enforces that mechanically.
"""

from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import tomllib
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

# ---------------------------------------------------------------- models


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


SEVERITY_RANK = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3}
SEVERITY_LABEL = {
    "en": {Severity.CRITICAL: "CRITICAL", Severity.HIGH: "HIGH", Severity.MEDIUM: "MEDIUM", Severity.LOW: "LOW"},
    "zh": {Severity.CRITICAL: "严重", Severity.HIGH: "高危", Severity.MEDIUM: "中危", Severity.LOW: "低危"},
}


class Status(str, Enum):
    CONFIRMED = "confirmed"
    NEEDS_REVIEW = "needs_review"


class Mainline(str, Enum):
    PRIVACY = "privacy"
    AI = "ai"


@dataclass(slots=True)
class Evidence:
    kind: str
    file: str
    line: int | None
    snippet: str
    note: str = ""

    def to_dict(self) -> dict:
        return {"kind": self.kind, "file": self.file, "line": self.line, "snippet": self.snippet, "note": self.note}


@dataclass(slots=True)
class Finding:
    rule: str
    title: str
    mainline: Mainline
    severity: Severity
    status: Status
    file: str
    line: int
    column: int
    why: str
    minus: list[str]
    plus: list[str]
    evidence: list[Evidence] = field(default_factory=list)
    prompt: str = ""
    id: str = ""
    # "verified": the green line is a concrete replacement for this line.
    # "template": a shape to adapt. "manual": no automatic fix is offered.
    fix_kind: str = "template"

    def finalize(self) -> "Finding":
        seed = f"{self.rule}|{self.file}|{' '.join(self.minus).strip()}"
        self.id = "WR-" + hashlib.sha1(seed.encode("utf-8")).hexdigest()[:8]
        return self

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "rule": self.rule,
            "title": self.title,
            "mainline": self.mainline.value,
            "severity": self.severity.value,
            "status": self.status.value,
            "file": self.file,
            "line": self.line,
            "column": self.column,
            "why": self.why,
            "fix": {"minus": self.minus, "plus": self.plus, "kind": self.fix_kind},
            "evidence": [e.to_dict() for e in self.evidence],
        }

    @property
    def rank(self) -> tuple:
        return (SEVERITY_RANK[self.severity], self.file, self.line)


# ---------------------------------------------------------------- scope

IGNORED_DIRS = {
    ".git", ".hg", ".svn", ".wrasse", "node_modules", "bower_components", "dist", "build",
    "out", "coverage", ".venv", "venv", "env", "__pycache__", "vendor", "third_party",
    "site-packages", ".next", ".nuxt", ".svelte-kit", ".tox", ".mypy_cache", ".pytest_cache",
    ".idea", ".ruff_cache", "migrations", "miniprogram_npm", "mp_npm",
    # build caches hold generated or extracted copies of the same code
    ".cache", ".parcel-cache", ".turbo", ".nx", ".esbuild", ".nyc_output",
    ".wrangler", ".vercel", ".output",
}
TEST_DIRS = {"test", "tests", "__tests__", "spec", "specs", "fixtures", "examples", "demo", "demos"}
CODE_SUFFIX = {".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".vue", ".svelte", ".go", ".java", ".rb", ".php"}
TEXT_SUFFIX = CODE_SUFFIX | {".toml", ".txt", ".yaml", ".yml", ".json", ".cfg", ".ini", ".env", ".md",
                              ".html", ".htm", ".j2", ".jinja"}
MAX_BYTES = 2_000_000
MAX_FILES = 20_000
MAX_TOTAL_BYTES = 256 * 1024 * 1024
SKIP_NAMES = {"wrasse-report.html", "wrasse-report.json", "wrasse.sarif"}
SENSITIVE_SUFFIX = {".pem", ".key", ".p12", ".pfx"}
# Agent instruction files carry no suffix, so a suffix-only scope skipped the
# one place a hidden instruction is cheapest to plant.
INSTRUCTION_NAMES = {
    ".cursorrules", ".windsurfrules", ".clinerules", ".continuerules",
    ".aiderrules", "copilot-instructions.md", "CLAUDE.md", "AGENTS.md", "GEMINI.md",
}


def _wanted(name: str) -> bool:
    """`.env` has no suffix, so suffix-only matching missed every dotfile."""
    if name == ".env" or name.startswith(".env.") or name in INSTRUCTION_NAMES:
        return True
    return Path(name).suffix.lower() in TEXT_SUFFIX | SENSITIVE_SUFFIX


# Boundaries are lookarounds on purpose: a word-boundary escape here once
# into a literal backspace and silently disabled the whole mask.
_BACK = "(?<![A-Za-z0-9])"
_FWD = "(?![A-Za-z0-9])"
_PROVIDER_SHAPES = (
    _BACK + "AKIA[0-9A-Z]{16}" + _FWD,
    _BACK + "gh[pousr]_[A-Za-z0-9]{30,}" + _FWD,
    _BACK + "(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}" + _FWD,
    _BACK + "sk-ant-[A-Za-z0-9_-]{24,}" + _FWD,
    _BACK + "sk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{32,}" + _FWD,
    _BACK + "AIza[0-9A-Za-z_-]{35}" + _FWD,
    _BACK + "xox[baprs]-[A-Za-z0-9-]{20,}" + _FWD,
    _BACK + "npm_[A-Za-z0-9]{36}" + _FWD,
    _BACK + "eyJ[A-Za-z0-9_-]{10,}[.]eyJ[A-Za-z0-9_-]{10,}[.][A-Za-z0-9_-]{10,}" + _FWD,
)
_LONG_QUOTED = re.compile(r"""(['"`])([A-Za-z0-9_+/-]{16,})""")
# A connection string can carry a password in the userinfo part, and that
# password need not look random. The scheme separator is split so that a
# scanner reading this file does not mistake the pattern for a credential.
_URI_CRED = re.compile(
    r"(?P<scheme>[a-zA-Z][a-zA-Z0-9+.\-]*"
    "://"
    r")(?P<user>[^:/@\s]*):(?P<pw>[^@/\s]+)@")
# `jdbc:postgresql://db/app?user=alice&password=secret` carries it in the query.
# Oracle keeps the credentials in the path: jdbc:oracle:thin:scott/tiger@//host/db
_ORACLE_CRED = re.compile(r"(jdbc:oracle:(?:thin|oci):)([^/@\s:]+)/([^@\s]+)@")
_QUERY_CRED = re.compile(
    r"(?i)(?P<key>[?&;](?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?token)=)"
    r"(?P<val>[^&\s'\"]+)")


def _looks_secret(v: str) -> bool:
    """A long quoted value is only masked when it also looks like a credential."""
    import math
    if len(v) < 16 or v.count(" ") > 2:
        return False
    if not any(ch.isdigit() for ch in v) or not any(ch.isalpha() for ch in v):
        return False
    entropy = -sum((v.count(c) / len(v)) * math.log2(v.count(c) / len(v)) for c in set(v))
    return entropy >= 3.0


def _mask_value(v: str) -> str:
    return "***" if len(v) <= 8 else f"{v[:4]}••••{v[-2:]}"


def mask_text(text: str) -> str:
    """Mask credentials anywhere, whoever asked for the text."""
    out = text
    out = _URI_CRED.sub(
        lambda m: f"{m.group('scheme')}{m.group('user')}:{_mask_value(m.group('pw'))}@", out)
    out = _QUERY_CRED.sub(lambda m: m.group("key") + _mask_value(m.group("val")), out)
    out = _ORACLE_CRED.sub(
        lambda m: f"{m.group(1)}{m.group(2)}:{_mask_value(m.group(3))}@", out)
    for shape in _PROVIDER_SHAPES:
        out = re.sub(shape, lambda m: _mask_value(m.group(0)), out)
    out = _LONG_QUOTED.sub(
        lambda m: m.group(1) + (_mask_value(m.group(2)) if _looks_secret(m.group(2)) else m.group(2)), out)
    return out


def rel(root: Path, path: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def _skip_dir(name: str, include_tests: bool) -> bool:
    if name in IGNORED_DIRS or name.startswith((".venv", "venv-")) or name == "env":
        return True
    return not include_tests and name.lower() in TEST_DIRS


def iter_files(root: Path, include_tests: bool = False, budget: list | None = None,
               skipped: list | None = None) -> list[Path]:
    """Source files under root. Prunes ignored directories instead of walking them."""
    out: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        kept: list[str] = []
        for name in sorted(dirnames):
            if _skip_dir(name, include_tests):
                continue
            if os.path.islink(os.path.join(dirpath, name)):
                # Never follow a link out of the project; never pretend it was read.
                if budget is not None:
                    budget[1] = True
                if skipped is not None:
                    skipped.append(Path(dirpath) / name)
                continue
            kept.append(name)
        dirnames[:] = kept
        for name in sorted(filenames):
            if name in SKIP_NAMES or not _wanted(name):
                continue
            path = Path(dirpath) / name
            try:
                if path.is_symlink():
                    # A link may point outside the project, so it is not followed;
                    # it is still a file the result does not cover.
                    if budget is not None:
                        budget[1] = True
                    if skipped is not None:
                        skipped.append(path)
                    continue
                size = path.stat().st_size
            except OSError:
                if budget is not None:
                    budget[1] = True
                if skipped is not None:
                    skipped.append(path)
                continue
            if size > MAX_BYTES:
                # A file we did not read is a hole in the result, not a pass.
                if budget is not None:
                    budget[1] = True
                if skipped is not None:
                    skipped.append(path)
                continue
            if budget is not None:
                if len(out) >= MAX_FILES or budget[0] + size > MAX_TOTAL_BYTES:
                    budget[1] = True      # truncated: the scan is no longer complete
                    return out
                budget[0] += size
            out.append(path)
    return out


def read_text(path: Path, failed: list | None = None) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        if failed is not None:
            failed.append(path)
        return ""


def safe_read(root: Path, path: Path) -> str:
    """Read a file only when it is a regular file inside the project.

    `is_file()` follows symlinks, so a repository could point a config at
    /etc/passwd and have us print it.
    """
    try:
        if path.is_symlink():
            return ""
        resolved = path.resolve()
        if not resolved.is_relative_to(root.resolve()) or not resolved.is_file():
            return ""
        return read_text(resolved)
    except OSError:
        return ""


def line_at(text: str, line: int) -> str:
    lines = text.splitlines()
    if 1 <= line <= len(lines):
        return lines[line - 1]
    return ""


# ---------------------------------------------------------------- dependencies


@dataclass(slots=True)
class Dependency:
    name: str
    spec: str
    file: str
    line: int
    ecosystem: str = "pypi"


_REQ = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*([<>=!~].*)?$")


def parse_requirements(root: Path) -> list[Dependency]:
    out: list[Dependency] = []
    for name in ("requirements.txt", "requirements-dev.txt"):
        text = safe_read(root, root / name)
        if not text:
            continue
        for i, raw in enumerate(text.splitlines(), 1):
            line = raw.strip()
            if not line or line.startswith(("#", "-r", "--", "git+", "http")):
                continue
            m = _REQ.match(line.split(";")[0])
            if m:
                out.append(Dependency(m.group(1), (m.group(2) or "").strip(), name, i))
    pkg_text = safe_read(root, root / "package.json")
    if pkg_text:
        try:
            data = json.loads(pkg_text)
            for key in ("dependencies", "devDependencies"):
                for name, spec in (data.get(key) or {}).items():
                    out.append(Dependency(name, str(spec), "package.json", 1, "npm"))
        except (json.JSONDecodeError, OSError):
            pass
    pyproject_text = safe_read(root, root / "pyproject.toml")
    if pyproject_text:
        try:
            data = tomllib.loads(pyproject_text)
            project = data.get("project", {}) or {}
            specs = list(project.get("dependencies", []) or [])
            # An extra is still declared: `wrasse[java]` makes javalang a real
            # dependency of this project, so an import of it is not undeclared.
            for group in (project.get("optional-dependencies", {}) or {}).values():
                specs.extend(group or [])
            for dep in specs:
                m = _REQ.match(str(dep).split(";")[0])
                if m:
                    out.append(Dependency(m.group(1), (m.group(2) or "").strip(), "pyproject.toml", 1))
        except (tomllib.TOMLDecodeError, OSError):
            pass
    return out


# ---------------------------------------------------------------- routes


@dataclass(slots=True)
class Route:
    method: str
    path: str
    file: str
    line: int
    func: str
    depends: list[str]
    body: str
    tainted: set[str]
    params: tuple[tuple[str, str], ...] = ()

    @property
    def has_auth(self) -> bool:
        tokens: set[str] = set()
        for dep in self.depends:
            tokens.update(t for t in re.split(r"[^a-z0-9]+", dep.lower()) if t)
        strong = {"auth", "authenticate", "authentication", "authorize", "authorization",
                  "current_user", "user", "token", "bearer", "jwt", "login", "logged",
                  "permission", "permissions", "require", "required", "admin", "oauth2",
                  "session", "identity", "claims", "credentials", "apikey", "signature",
                  "verify", "whoami"}
        if tokens & strong:
            return True
        if re.search(r"require_?auth|login_required|permission_required", "_".join(tokens)):
            return True
        # a body that reads an identity object counts as authenticated
        return bool(re.search(r"\b(current_user|user\.id|request\.user|g\.user)\b", self.body))


_HTTP = {"get", "post", "put", "patch", "delete", "head", "options"}


def _dep_names(node: ast.AST) -> list[str]:
    """Names referenced inside Depends(...) in a decorator or default value."""
    names: list[str] = []
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name) and sub.func.id == "Depends":
            for arg in sub.args[:1]:
                names.append(ast.unparse(arg))
        elif isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute) and sub.func.attr == "Depends":
            for arg in sub.args[:1]:
                names.append(ast.unparse(arg))
    return names


def _route_of(decorator: ast.AST) -> tuple[str, str] | None:
    if not isinstance(decorator, ast.Call) or not decorator.args:
        return None
    func = decorator.func
    if not isinstance(func, ast.Attribute):
        return None
    name = func.attr
    first = decorator.args[0]
    if not (isinstance(first, ast.Constant) and isinstance(first.value, str)):
        return None
    if name in _HTTP:
        return name.upper(), first.value
    if name == "route":
        for kw in decorator.keywords:
            if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple)):
                methods = [e.value for e in kw.value.elts if isinstance(e, ast.Constant)]
                if methods:
                    return str(methods[0]).upper(), first.value
            if kw.arg == "method" and isinstance(kw.value, ast.Constant):
                return str(kw.value.value).upper(), first.value
        return "GET", first.value
    return None


def _const_str(node: ast.AST | None) -> str:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return ""


def _router_prefixes(tree: ast.Module) -> dict[str, str]:
    """`router = APIRouter(prefix="/v1")` → {"router": "/v1"}."""
    out: dict[str, str] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.Call):
            continue
        ctor = getattr(node.value.func, "id", None) or getattr(node.value.func, "attr", None)
        if ctor != "APIRouter":
            continue
        prefix = ""
        for kw in node.value.keywords:
            if kw.arg == "prefix":
                prefix = _const_str(kw.value)
        for target in node.targets:
            if isinstance(target, ast.Name):
                out[target.id] = prefix
    return out


def _includes(tree: ast.Module) -> list[tuple[str, str, str]]:
    """`app.include_router(router, prefix="/api")` → ("app", "router", "/api")."""
    out: list[tuple[str, str, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr != "include_router" or not node.args:
            continue
        parent = getattr(node.func.value, "id", "")
        child = getattr(node.args[0], "id", "") or getattr(node.args[0], "attr", "")
        prefix = ""
        for kw in node.keywords:
            if kw.arg == "prefix":
                prefix = _const_str(kw.value)
        if parent and child:
            out.append((parent, child, prefix))
    return out


def _includes_detail(tree: ast.Module) -> list[tuple[str, str, str]]:
    """`app.include_router(orders.router)` -> ("app", "orders", "router").

    The module name is kept so the other file can be found: `orders` here is an
    imported module, and its `router` is defined in that module's file.
    """
    out: list[tuple[str, str, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr != "include_router" or not node.args:
            continue
        parent = getattr(node.func.value, "id", "")
        arg = node.args[0]
        child = getattr(arg, "id", "") or getattr(arg, "attr", "")
        module = getattr(arg.value, "id", "") if isinstance(arg, ast.Attribute) else ""
        if parent and child:
            out.append((parent, module, child))
    return out


def _import_map(tree: ast.Module) -> dict[str, str]:
    """Local name -> the dotted module it came from."""
    out: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    out[alias.asname] = alias.name
                else:
                    head = alias.name.split(".")[0]
                    out[head] = head
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                out[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    return out


def _module_files(trees: dict[str, ast.Module]) -> dict[str, str]:
    """`app/routes/orders.py` -> {"app.routes.orders": "app/routes/orders.py"}."""
    out: dict[str, str] = {}
    for path in trees:
        if not path.endswith(".py"):
            continue
        mod = path[:-3].replace("\\", "/")
        if mod.endswith("/__init__"):
            mod = mod[: -len("/__init__")]
        out[mod.replace("/", ".")] = path
    return out


def _match_module(dotted: str, modules: dict[str, str]) -> str | None:
    if dotted in modules:
        return modules[dotted]
    for mod, path in modules.items():
        if dotted.endswith("." + mod) or mod.endswith("." + dotted):
            return path
    return None


def resolve_router_deps(trees: dict[str, ast.Module]) -> dict[str, dict[str, list[str]]]:
    """file -> {router variable: dependency names}, app-level deps inherited.

    `app = FastAPI(dependencies=[Depends(require_auth)])` protects the routes on
    `router` in another file once `app.include_router(orders.router)` mounts it.
    Ownership is keyed by file, so two files that both call their router
    `router` do not inherit each other's dependencies.
    """
    own = {path: _router_deps(tree) for path, tree in trees.items()}
    eff = {path: {name: list(deps) for name, deps in table.items()} for path, table in own.items()}
    modules = _module_files(trees)
    edges: list[tuple[tuple[str, str], tuple[str, str]]] = []
    for path, tree in trees.items():
        imports = _import_map(tree)
        for parent, module, child in _includes_detail(tree):
            target, child_var = path, child
            if module:
                found = _match_module(imports.get(module, module), modules)
                if found:
                    target = found
            elif child in imports:
                # `from app.routes.orders import router as orders_router`
                head, sep, tail = imports[child].rpartition(".")
                found = _match_module(head, modules) if sep else None
                if found:
                    target, child_var = found, tail
            edges.append(((path, parent), (target, child_var)))
    for _ in range(8):                       # a few include_router levels at most
        changed = False
        for (parent_file, parent_var), (child_file, child_var) in edges:
            inherited = eff.get(parent_file, {}).get(parent_var, [])
            merged = list(own.get(child_file, {}).get(child_var, []))
            merged.extend(dep for dep in inherited if dep not in merged)
            if eff.setdefault(child_file, {}).get(child_var) != merged:
                eff[child_file][child_var] = merged
                changed = True
        if not changed:
            break
    return eff


def resolve_prefixes(trees: dict[str, ast.Module]) -> dict[str, str]:
    """Full mount prefix for every router variable, following include_router chains."""
    own: dict[str, str] = {}
    edges: list[tuple[str, str, str]] = []
    for tree in trees.values():
        own.update(_router_prefixes(tree))
        edges.extend(_includes(tree))
    eff = dict(own)
    for _ in range(6):                       # a few include_router levels at most
        changed = False
        for parent, child, mount in edges:
            full = eff.get(parent, own.get(parent, "")) + mount + own.get(child, "")
            if eff.get(child) != full:
                eff[child] = full
                changed = True
        if not changed:
            break
    return eff


def _router_deps(tree: ast.Module) -> dict[str, list[str]]:
    """`router = APIRouter(dependencies=[Depends(auth)])` → {"router": ["auth"]}.

    `app = FastAPI(dependencies=[...])` is collected the same way: a route on
    that app inherits the dependency, so it is not unauthenticated.
    """
    out: dict[str, list[str]] = {}
    for node in ast.walk(tree):
        # `app: FastAPI = FastAPI(...)` is an AnnAssign, not an Assign.
        if isinstance(node, ast.Assign):
            value, targets = node.value, node.targets
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            value, targets = node.value, [node.target]
        else:
            continue
        if not isinstance(value, ast.Call):
            continue
        fn = value.func
        ctor = getattr(fn, "id", None) or getattr(fn, "attr", None)
        if ctor not in ("APIRouter", "FastAPI"):
            continue
        names: list[str] = []
        for kw in value.keywords:
            if kw.arg == "dependencies":
                names.extend(_dep_names(kw.value))
        for target in targets:
            if isinstance(target, ast.Name):
                out[target.id] = names
    return out


def extract_routes(text: str, tree: ast.Module, relpath: str, router_deps: dict[str, list[str]],
                   prefixes: dict[str, str] | None = None) -> list[Route]:
    routes: list[Route] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for dec in node.decorator_list:
            parsed = _route_of(dec)
            if not parsed:
                continue
            method, path = parsed
            owner = ""
            if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute) and isinstance(dec.func.value, ast.Name):
                owner = dec.func.value.id
            deps: list[str] = []
            positional = node.args.args
            defaults = node.args.defaults
            if defaults:
                for default in defaults:
                    deps.extend(_dep_names(default))
            del positional
            for default in node.args.kw_defaults:
                if default is not None:
                    deps.extend(_dep_names(default))
            for dec_inner in node.decorator_list:
                deps.extend(_dep_names(dec_inner))
            deps.extend(router_deps.get(owner, []))
            mount = (prefixes or {}).get(owner, "")
            if mount and not path.startswith(mount):
                path = mount.rstrip("/") + path
            tainted = {a.arg for a in list(node.args.args) + list(node.args.kwonlyargs) if a.arg not in ("self", "cls")}
            body = ast.get_source_segment(text, node) or ""
            params = tuple(
                (a.arg, ast.unparse(a.annotation) if a.annotation is not None else "")
                for a in list(node.args.args) + list(node.args.kwonlyargs)
                if a.arg not in ("self", "cls")
            )
            routes.append(Route(method, path, relpath, node.lineno, node.name, deps, body, tainted, params))
    return routes


# ---------------------------------------------------------------- index


@dataclass(slots=True)
class ProjectIndex:
    root: Path
    files: list[str]
    texts: dict[str, str]
    trees: dict[str, ast.Module]
    routes: list[Route]
    deps: list[Dependency]
    manifests: dict[str, str]
    truncated: bool = False
    skipped: tuple[str, ...] = ()          # files over the size cap, never read

    def line(self, relpath: str, line: int) -> str:
        return line_at(self.texts.get(relpath, ""), line)


def build_index(root: Path, include_tests: bool = False, parse: bool = True) -> ProjectIndex:
    root = root.resolve()
    files: list[str] = []
    texts: dict[str, str] = {}
    trees: dict[str, ast.Module] = {}
    routes: list[Route] = []
    budget = [0, False]
    skipped: list[Path] = []
    for path in iter_files(root, include_tests, budget, skipped):
        rp = rel(root, path)
        failed: list[Path] = []
        text = read_text(path, failed)
        if failed:                     # listed, wanted, but never read
            budget[1] = True
            skipped.append(path)
            continue
        files.append(rp)
        texts[rp] = text
        if not parse or path.suffix.lower() != ".py":
            continue
        try:
            tree = ast.parse(text)
        except SyntaxError:
            # Read, but never analysed: the same hole as an unreadable file.
            budget[1] = True
            skipped.append(path)
            continue
        trees[rp] = tree
    prefixes = resolve_prefixes(trees)
    deps_map = resolve_router_deps(trees)
    for rp, tree in trees.items():
        routes.extend(extract_routes(texts[rp], tree, rp, deps_map.get(rp, {}), prefixes))
    return ProjectIndex(root=root, files=files, texts=texts, trees=trees, routes=routes,
                        deps=parse_requirements(root), manifests={}, truncated=budget[1],
                        skipped=tuple(rel(root, p) for p in skipped))
