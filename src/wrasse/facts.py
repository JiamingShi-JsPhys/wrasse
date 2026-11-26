"""L1 facts — the privacy mainline. Deterministic, offline, no model calls."""

from __future__ import annotations

import ast
import json
import math
import re
from pathlib import Path

from .core import (INSTRUCTION_NAMES, Evidence, Finding, ProjectIndex, Status, line_at,
                   mask_text, safe_read)
from .rules import RULES

CODE = (".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".vue", ".svelte")

PROVIDERS = [
    ("aws", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b")),
    ("stripe", re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b")),
    ("openai", re.compile(r"\bsk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{32,}\b")),
    ("anthropic", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{24,}\b")),
    ("google", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("slack", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")),
    ("npm", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}[.]eyJ[A-Za-z0-9_-]{10,}[.][A-Za-z0-9_-]{10,}\b")),
]
PRIVATE_KEY = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ED25519 )?PRIVATE KEY-----")
FRONTEND = re.compile(
    r"\b(?:NEXT_PUBLIC|VITE|REACT_APP)_[A-Z0-9_]*(?:SECRET|PRIVATE|TOKEN|API_?KEY|PASSWORD)[A-Z0-9_]*"
    r"\s*[:=]\s*(['\"`])(?P<val>[^'\"`]{8,})\1"
)
ASSIGN = re.compile(
    r"\b(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*[:=]\s*(?P<q>['\"`])(?P<val>(?:\.|(?!(?P=q)).){6,})(?P=q)"
)
LOG = re.compile(r"\b(?:logger|log|console|logging)\.\w+\s*\([^)\n]*\b(?:password|passwd|token|secret|authorization|cookie|api_?key)\b", re.I)
ERROR_LEAK = re.compile(
    r"(?:JSONResponse|jsonify|res\.(?:send|json)|HttpResponse)\s*\([^)\n]*(?:str\(\s*(?:e|err|exc|error)\s*\)|traceback\.format_exc|error\.message|err\.stack)",
    re.I,
)
SECRET_FIELD = re.compile(r"^\s+(password|passwd|hashed_password|password_hash|secret|token|api_key|access_token|refresh_token)\s*:", re.I)
MODEL_CLASS = re.compile(r"^\s*class\s+\w+\s*\(\s*(?:BaseModel|Schema)\b", re.M)
DEBUG_ON = re.compile(r"^\s*(?:DEBUG|debug)\s*[=:]\s*True\b|\buvicorn\.run\([^)]*debug\s*=\s*True")
CORS_WILD = re.compile(r"allow_origins\s*=\s*\[\s*['\"]\*['\"]|CORS_ALLOW_ALL(?:_ORIGINS)?\s*=\s*True")
CORS_CREDS = re.compile(r"allow_credentials\s*=\s*True")
UPLOAD = re.compile(
    r"(?:open|send_file|send_from_directory|FileResponse|fs\.(?:readFile|writeFile))\s*\([^)]*(?:(?:file|upload|attachment)\.(?:filename|name)|\.files\[)",
)
NAME_KEYWORD = re.compile(r"api_?key|secret|password|passwd|pwd|token|private_?key|credential|access_?key", re.I)
ENV_REF = re.compile(r"process\.env|os\.getenv|os\.environ|import\.meta\.env|ENV\[|settings\.")
PLACEHOLDERS = {"changeme", "change-me", "example", "sample", "placeholder", "your-key", "your-api-key", "your-secret", "your-token", "test", "test-key", "dummy", "fake", "todo", "none", "null", "xxx"}


def _shannon(value: str) -> float:
    return -sum((c / len(value)) * math.log2(c / len(value)) for c in (value.count(ch) for ch in set(value)))


def _randomish(value: str) -> bool:
    if not (16 <= len(value) <= 200) or re.search(r"\s", value):
        return False
    if not re.search(r"[A-Za-z]", value) or not re.search(r"\d", value):
        return False
    return _shannon(value) >= 3.0


def _mask(value: str) -> str:
    return "***" if len(value) <= 8 else f"{value[:4]}••••{value[-2:]}"



DEFAULT_FIX = {
    "fix_env": 'os.environ["API_KEY"]',
    "fix_server": "// server-side only — never expose this value to the browser",
    "fix_log": '"[redacted]"',
    "fix_error": '{"error": "internal_error"}',
    "fix_model": "# remove this field from the response schema",
    "fix_path": "target = (Path(BASE) / name).resolve()",
    "fix_ignore": ".gitignore:  .env",
    "fix_auth": "user=Depends(get_current_user)",
    "fix_owner": "owner_id=user.id",
    "fix_schema": "payload: UpdateUser",
    "fix_debug": 'DEBUG = os.getenv("DEBUG", "false") == "true"',
    "fix_cors": 'allow_origins=["https://app.example.com"]',
    "fix_deser": "json.loads(payload)",
    "fix_sql": 'execute("... WHERE id = ?", (value,))',
}


def _fmt(template: str, **kw) -> str:
    def sub(m):
        key = m.group(1)
        return str(kw.get(key, DEFAULT_FIX.get(key, m.group(0))))
    return re.sub(r"\{(\w+)\}", sub, template)


def _emit(rule_id: str, index: ProjectIndex, path: str, line: int, column: int = 1, lang: str = "en",
          minus: list[str] | None = None, plus: list[str] | None = None,
          status: Status | None = None, evidence: list[Evidence] | None = None,
          fix_kind: str | None = None, **fmt) -> Finding:
    rule = RULES[rule_id]
    meta = rule.t(lang)
    src = line_at(index.texts.get(path, ""), line).rstrip()

    minus = minus if minus is not None else [_fmt(meta["minus"].strip(), line=src, **fmt)]
    plus = plus if plus is not None else [_fmt(meta["plus"].strip(), line=src, **fmt)]
    indent = minus[0][: len(minus[0]) - len(minus[0].lstrip())] if minus else ""
    if indent:
        plus = [p_ if (not p_ or p_[:1].isspace()) else indent + p_ for p_ in plus]
    if plus and minus and plus[0].strip() == minus[0].strip():
        indent = minus[0][: len(minus[0]) - len(minus[0].lstrip())]
        note = ("# manual review required — mask or remove this value before merging"
                if lang == "en" else "# 需要人工处理——合并前把这个值脱敏或移除")
        plus = [indent + note]
        fix_kind = "manual"
    minus = [mask_text(m) for m in minus]
    plus = [mask_text(p_) for p_ in plus]
    src = mask_text(src)
    prompt = (meta["prompt"].replace("{{file}}", path).replace("{{line}}", str(line))
              .replace("{{snippet}}", src.strip()))
    # A caller can hand in its own Evidence, and that snippet used to reach
    # JSON, SARIF and the state file unmasked.
    evidence = [Evidence(e.kind, e.file, e.line, mask_text(e.snippet), mask_text(e.note))
                for e in (evidence or [Evidence("code", path, line, src.strip())])]
    return Finding(
        rule=rule.id, title=meta["title"], mainline=rule.mainline,
        severity=rule.severity, status=status or rule.status,
        file=path, line=line, column=column, why=meta["why"],
        minus=minus, plus=plus, prompt=prompt,
        evidence=evidence,
        fix_kind=fix_kind or "template",
    ).finalize()


def scan(index: ProjectIndex, lang: str = "en") -> list[Finding]:
    out: list[Finding] = []
    for path, text in index.texts.items():
        suffix = Path(path).suffix.lower()
        is_code = suffix in CODE
        lines = text.splitlines()
        string_lines = _string_lines(text) if is_code else set()
        machine: tuple[int, str] | None = None
        machine_hits = 0
        for i, raw in enumerate(lines, 1):
            line = raw.rstrip()
            if not line or line.lstrip().startswith(("#", "//", "*")):
                continue
            out.extend(_providers(index, path, i, line, lang))
            if PRIVATE_KEY.search(line):
                out.append(_emit("secret/private-key-block", index, path, i, lang=lang, minus=[line]))
            # Hosts and machine paths live in docs and config as often as in code.
            lower = line.lower()
            for host in EPHEMERAL:
                if host in lower and ("http" in lower or "://" in lower):
                    out.append(_emit("net/ephemeral-host", index, path, i, lang=lang, minus=[line],
                                     plus=["# point this at a domain you own"]))
                    break
            if _machine_hit(line):
                machine_hits += 1
                machine = machine or (i, line)
            is_template = suffix in (".html", ".htm", ".j2", ".jinja")
            if is_template:
                # A template is checked for unescaped output only — its sample
                # code is not source, so no code rule runs here.
                if re.search(r"\|\s*safe", line) and "{{" in line:
                    out.append(_emit("code/xss-output", index, path, i, lang=lang, minus=[line],
                                     plus=[line.replace("| safe", "| e").replace("|safe", "|e")],
                                     fix_kind="verified"))
                continue
            if not is_code:
                # Documentation and config may quote code as an example; only
                # real key formats are worth reporting outside source files.
                continue
            if i in string_lines:
                continue                      # inside a prompt or a docstring
            out.extend(_entropy(index, path, i, line, lang))
            if FRONTEND.search(line):
                prop = re.match(r"\s*[A-Za-z_$][\w$]*\s*:", line)
                fix = ("// server-side only — never expose this secret to the browser"
                       if prop else "// read it on the server: process.env.STRIPE_SECRET_KEY")
                out.append(_emit("secret/frontend-env", index, path, i, lang=lang,
                                 minus=[line], plus=[fix], fix_kind="verified"))
            elif is_code and suffix in (".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx") and _bundle_key(line):
                out.append(_emit("secret/in-frontend-bundle", index, path, i, lang=lang,
                                 minus=[line], fix_kind="verified"))
            if ERROR_LEAK.search(line):
                out.append(_emit("error/stack-to-client", index, path, i, lang=lang, minus=[line],
                                 plus=[line.replace("str(e)", '"internal_error"').replace(
                                     "traceback.format_exc()", '"internal_error"')],
                                 fix_kind="verified"))
            if DEBUG_ON.search(line):
                out.append(_emit("config/debug-enabled", index, path, i, lang=lang, minus=[line],
                                 plus=[line.replace("True", 'os.getenv("DEBUG", "0") == "1"')]))
            if CORS_WILD.search(line):
                window = chr(10).join(lines[max(0, i - 5):i + 8])
                if "credentials" in window.lower() or CORS_CREDS.search(window):
                    out.append(_emit("config/cors-wildcard-credentials", index, path, i, lang=lang,
                                     minus=[line], plus=[_cors_fix(line)], fix_kind="verified"))
            if suffix in (".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"):
                if "regex" not in line.lower() and re.search("document[.]write[ ]*[(]", _code_only(line)):
                    out.append(_emit("code/xss-output", index, path, i, lang=lang, minus=[line],
                                     plus=["// build a DOM node instead of document.write"],
                                     fix_kind="verified"))
                elif "regex" not in line.lower() and re.search(
                        r"\.innerHTML\s*=|dangerouslySetInnerHTML", _code_only(line)):
                    out.append(_emit("code/xss-output", index, path, i, lang=lang, minus=[line],
                                     plus=[line.replace(".innerHTML", ".textContent")],
                                     fix_kind="verified"))
            code = _code_only(line)
            # A row of a rule table describes a pattern; it is not that pattern in
            # use. Without this, scanning a scanner reports its own table.
            if RULE_ROW.match(line):
                continue
            for rule_id, test in LINE_RULES:
                if rule_id == "code/dynamic-eval" and suffix in JS_FILES and not re.search(
                        "(?<![A-Za-z0-9_.])eval[ ]*[(]", code):
                    continue
                if test(line, code):
                    fix = _line_fix(rule_id, line, path)
                    out.append(_emit(rule_id, index, path, i, lang=lang, minus=[line], plus=fix,
                                     fix_kind="verified" if fix else None))
            if WEAK_HASH.search(line) and re.search("pass|pwd|secret", line, re.I):
                out.append(_emit("auth/md5-sha1-password", index, path, i, lang=lang, minus=[line],
                                 plus=["# bcrypt.hashpw(pw, bcrypt.gensalt(12))"]))
            if UPLOAD.search(line):
                out.append(_emit("upload/path-from-filename", index, path, i, lang=lang, minus=[line],
                                 plus=_upload_fix(line, path, _path_alias(index.texts.get(path, "")))))
        if machine is not None:
            # One finding per file: the same report copied 13 times is one problem.
            line_no, src = machine
            out.append(_emit("leak/machine-path", index, path, line_no, lang=lang, minus=[src],
                             evidence=[Evidence("path", path, line_no,
                                                f"{machine_hits} local path(s) in this file")]))
        if Path(path).suffix.lower() == ".py":
            out.extend(_response_models(index, path, text, lines, lang))
            out.extend(_pii_fields(index, path, text, lines, lang))
    out.extend(_java_rules(index, lang))
    out.extend(_api_docs(index, lang))
    out.extend(_insecure_source(index, lang))
    out.extend(_agent_files(index, lang))
    out.extend(_hidden_chars(index, lang))
    out.extend(_license_check(index, lang))
    out.extend(_undeclared_imports(index, lang))
    out.extend(_js_imports(index, lang))
    out.extend(_lockfile(index, lang))
    out.extend(_rate_limit(index, lang))
    return out


def _swap_value(line: str, value: str, replacement: str) -> str:
    """Replace the literal where it sits, dropping the quotes that wrapped it.

    `KEY = "AKIA…"` becomes `KEY = os.environ["API_KEY"]`, not `KEY = "os.environ["API_KEY"]"`.
    """
    for quote in ('"', "'", "`"):
        quoted = quote + value + quote
        if quoted in line:
            return line.replace(quoted, replacement, 1)
    return line.replace(value, replacement, 1)


def _env_fix(name: str, path: str) -> str:
    key = name.upper()
    return f"process.env.{key}" if path.endswith(JS_FILES) else f'os.getenv("{key}")'


def _providers(index, path, ln, line, lang) -> list[Finding]:
    out = []
    browser = path.endswith((".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".vue", ".svelte"))
    for _name, pattern in PROVIDERS:
        for m in pattern.finditer(line):
            replacement = "process.env.API_KEY" if browser else 'os.environ["API_KEY"]'
            out.append(_emit("secret/provider-key", index, path, ln, m.start() + 1, lang,
                             minus=[line.replace(m.group(0), _mask(m.group(0)))],
                             plus=[_swap_value(line, m.group(0), replacement)]))
    return out


def _bundle_key(line: str) -> bool:
    return bool(re.search(r"['\"`](?:sk_live_|AKIA|gh[pousr]_|AIza)[A-Za-z0-9_\-]{10,}['\"`]", line))


def _entropy(index, path, ln, line, lang) -> list[Finding]:
    if ENV_REF.search(line):
        return []
    m = ASSIGN.search(line)
    if not m or not NAME_KEYWORD.search(m.group("name")):
        return []
    value = m.group("val")
    if "${" in value or "{" in value:      # template / f-string: computed, not literal
        return []
    if value.strip().lower().replace(" ", "-") in PLACEHOLDERS or not _randomish(value):
        return []
    return [_emit("secret/assignment-entropy", index, path, ln, m.start() + 1, lang,
                  minus=[line.replace(value, _mask(value))],
                  plus=[_swap_value(line, value, _env_fix(m.group("name"), path))])]


_Q = chr(34)
_Q1 = chr(39)
_STRINGS = re.compile(_Q + "[^" + _Q + "]*" + _Q + "|" + _Q1 + "[^" + _Q1 + "]*" + _Q1)
IMPORT_ALIASES = {"yaml": "pyyaml", "pil": "pillow", "cv2": "opencv-python", "bs4": "beautifulsoup4",
                  "sklearn": "scikit-learn", "dotenv": "python-dotenv", "jwt": "pyjwt",
                  "crypto": "pycryptodome", "cryptodome": "pycryptodome",
                  "dateutil": "python-dateutil", "OpenSSL": "pyopenssl"}
_CQ = "[" + chr(39) + chr(34) + "]"
RULE_ROW = re.compile("^[ ]*[(]?[ ]*" + _CQ + "[a-z][a-z0-9]*/[a-z0-9-]+" + _CQ + "[ ]*,")


def _has(line: str, *needles: str) -> bool:
    low = line.lower()
    return all(n in low for n in needles)


LINE_RULES = [
    ("config/allowed-hosts-wildcard", lambda line, code: "ALLOWED_HOSTS" in line and chr(42) in line),
    ("config/host-check-disabled", lambda line, code: re.search(
        "DANGEROUSLY_DISABLE_HOST_CHECK" + _CQ + "?[ ]*[:=][ ]*" + _CQ + "?(?:1|true|True|yes)",
        line) is not None),
    ("config/csrf-exempt", lambda line, code: "csrf_exempt" in code),
    ("code/dynamic-eval", lambda line, code: re.search(
        "(?<![A-Za-z0-9_.])(?:eval|exec)[ ]*[(]", code) is not None),
    ("config/cookie-flags", lambda line, code: re.search(
        "(?:secure|httponly)[ ]*:[ ]*false", code, re.I) is not None),
    ("config/tls-verification-off", lambda line, code: _has(code, "verify=false")
        or "NODE_TLS_REJECT_UNAUTHORIZED" in code or "AutoAddPolicy" in code),
    ("config/autoescape-off", lambda line, code: re.search(
        "autoescape[ ]*[:=][ ]*false", code, re.I) is not None),
    ("config/object-storage-public-acl", lambda line, code: re.search(
        "(?:ACL|acl)" + _CQ + "?[ ]*[:=][ ]*" + _CQ + "public-read-write" + _CQ, line) is not None),
    ("secret/default-credentials", lambda line, code: re.search(
        "(?:password|passwd|pwd)" + _CQ + "?[ ]*[:=][ ]*" + _CQ
        + "(?:admin|123456|password|admin123)" + _CQ,
        line, re.I) is not None),
    ("auth/jwt-misuse", lambda line, code: ("jwt" in code.lower() and "algorithms" in line.lower()
                                            and "none" in line.lower())
        or re.search("ignoreExpiration[ ]*:[ ]*true", line, re.I) is not None),
    ("auth/insecure-token-source", lambda line, code: re.search(
        "(?:Math|random)[.]random[ ]*[(]", line) is not None
        and any(w in line.lower() for w in ("token", "secret", "session", "apikey", "nonce"))),
    ("auth/weak-password-hash", lambda line, code: re.search(
        "(?:bcrypt|genSalt)(?:[.][A-Za-z0-9_]+)?[ ]*[(][^)]*,[ ]*[0-4][ ]*[)]", code) is not None),
    ("code/open-redirect", lambda line, code: re.search(
        "(?<![A-Za-z0-9_])redirect[(]", code) is not None
        and any(w in code for w in ("request", "next", "return_url", "redirect_uri", "url"))),
    ("code/weak-crypto", lambda line, code: any(re.search(p, code) for p in (
        "(?:DES|ARC4|DES3|Blowfish|IDEA|TripleDES)[.]new[ ]*[(]",
        "AES[.]MODE_ECB|modes[.]ECB[ ]*[(]|AESModeOfOperationECB",
        "algorithms[.](?:DES|ARC4|Blowfish|IDEA|TripleDES)[ ]*[(]",
        "createCipher[ ]*[(]|createDecipher[ ]*[(]"))
        or re.search("AES[.]new[ ]*[(][ ]*b?[\"']", line) is not None),
]

WEAK_HASH = re.compile("hashlib[.](?:md5|sha1)[ ]*[(]"
                       "|MessageDigest[.]getInstance[ ]*[(][^)]*(?:MD5|SHA-?1)")
# Java names its cipher inside a string literal, which `_code_only` removes.
JAVA_WEAK = re.compile("Cipher[.]getInstance[ ]*[(][ ]*" + _CQ
                       + "[^" + chr(39) + chr(34) + "]*(?:DES|RC4|RC2|Blowfish|IDEA|ECB)")
IPV4 = re.compile("[0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}")
EPHEMERAL = ("trycloudflare.com", "ngrok.io", "ngrok-free.app", "ngrok.app", "duckdns.org",
             "serveo.net", "loca.lt", "localtunnel.me", "telebit.io", "pinggy.io",
             "bore.pub", "tunnelto.dev", "lhr.life")


def _private(tok: str) -> bool:
    parts = tok.split(".")
    if len(parts) != 4 or not all(p.isdigit() for p in parts):
        return False
    a, b = int(parts[0]), int(parts[1])
    return a == 10 or (a == 192 and b == 168) or (a == 172 and 16 <= b <= 31)


WIN_PATH = re.compile("[A-Za-z]:" + chr(92) + chr(92) + "Users" + chr(92) + chr(92)
                      + "([A-Za-z0-9._-]+)")
# A trailing slash matters: `/api/home/index` is a route, `/home/alice/x` is a disk.
NIX_PATH = re.compile("(?<![A-Za-z0-9_/.-])/(?:home|Users)/([A-Za-z0-9._-]+)/")
PLACEHOLDER_USERS = {"x", "user", "username", "demo", "example", "me", "you", "yourname",
                     "someone", "foo", "bar", "name"}
# A private address is a leak when it configures something. In a pentest
# example or a help string it is a placeholder, and reporting it is noise.
HOST_VALUE = re.compile(
    r"(?:host|hostname|addr|address|server|endpoint|proxy|broker|gateway|redis|mongo|db"
    r"|database|url|dsn|uri)[a-z0-9_]*\s*[:=]\s*[\"']?(?:[a-z][a-z0-9+.-]*://)?(?:[^\s\"'@]*@)?"
    r"([0-9]{1,3}(?:[.][0-9]{1,3}){3})", re.I)


JS_FILES = (".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".vue", ".svelte")


def _cors_fix(line: str) -> str:
    """Replace the quoted wildcard, not the bare star: `["*"]` has both."""
    if "CORS_ALLOW_ALL_ORIGINS" in line:
        return line.replace("True", "False")
    for pattern, value in (('"[*]"', '["https://app.example.com"]'),
                           ("'[*]'", "['https://app.example.com']"),
                           ('"*"', '"https://app.example.com"'),
                           ("'*'", "'https://app.example.com'")):
        if pattern in line:
            return line.replace(pattern, value, 1)
    return line


def _line_fix(rule_id: str, line: str, path: str) -> list[str] | None:
    """A green line has to be valid in the language of the file it lands in."""
    js = path.endswith(JS_FILES)
    if rule_id == "config/autoescape-off":
        return [line.replace("false", "true") if js else line.replace("False", "True")]
    if rule_id == "config/cookie-flags":
        return [line.replace("false", "true") if js else line.replace("False", "True")]
    if rule_id == "config/object-storage-public-acl":
        m = re.search("public-read-[a-z]+", line)      # not spelled out: it would match us
        return [line.replace(m.group(0), "private")] if m else None
    if rule_id == "config/host-check-disabled":
        mark = "//" if js else "#"
        return [f"{mark} remove the host-check bypass and allowlist the hosts you serve"]
    return None


def _machine_hit(line: str) -> str | None:
    """A path or address from the author's own machine (not a marker string)."""
    for pattern in (WIN_PATH, NIX_PATH):
        match = pattern.search(line)
        if match and match.group(1).lower() not in PLACEHOLDER_USERS:
            return line.strip()[:120]
    match = HOST_VALUE.search(line)
    if match and _private(match.group(1)):
        after = line[match.end():match.end() + 1]
        if after != "/":                 # 10.0.0.0/8 is a range, not a host
            return line.strip()[:120]
    return None


_REGEX_LIT = re.compile(r"(?:(?<=[=(,:!&|])[ ]*|^[ ]*)/[^/]+/[a-z]*")


def _code_only(line: str) -> str:
    """Drop string and regex literals: a rule that *describes* innerHTML is not a sink."""
    return _REGEX_LIT.sub(" ", _STRINGS.sub(" ", line))


def _path_alias(text: str) -> str:
    """`const p = require("path")` → p; default to path."""
    m = re.search(r"(?:const|let|var)\s+(\w+)\s*=\s*require\(\s*['\"]path['\"]\s*\)", text)
    if m:
        return m.group(1)
    m = re.search(r"import\s+\*\s+as\s+(\w+)\s+from\s+['\"]path['\"]", text)
    return m.group(1) if m else "path"


def _upload_fix(line: str, path: str, alias: str = "path") -> list[str]:
    """Build the fix from the real arguments, in the file's own language."""
    indent = line[: len(line) - len(line.lstrip())]
    m = re.search(r"join\s*\(([^)]*)\)", line)
    base, tail = "BASE_DIR", "name"
    if m:
        parts = [p.strip().strip(chr(34) + chr(39)) for p in m.group(1).split(",")]
        if len(parts) >= 2:
            base, tail = parts[0], ", ".join(parts[1:])
    if path.endswith(".py"):
        return [f"{indent}target = (Path({base}) / {tail}).resolve()",
                f"{indent}if not target.is_relative_to({base}): raise HTTPException(400)"]
    return [f"{indent}const target = {alias}.resolve({base}, {tail});",
            f"{indent}const rel = {alias}.relative({alias}.resolve({base}), target);",
            f"{indent}if (rel.startsWith('..') || {alias}.isAbsolute(rel)) return res.status(400).end();"]


def _response_models(index, path, text, lines, lang) -> list[Finding]:
    out = []
    for m in MODEL_CLASS.finditer(text):
        start = text.count("\n", 0, m.end()) + 1          # the `class` line itself
        for offset in range(1, 12):
            idx = start + offset
            if idx > len(lines):
                break
            if lines[idx - 1].strip() == "":
                break
            f = SECRET_FIELD.match(lines[idx - 1])
            if f:
                out.append(_emit("response/model-leaks-secret", index, path, idx, lang=lang,
                                 minus=[lines[idx - 1].rstrip()], plus=[]))
                break
    return out


PII_FIELD = re.compile(
    r"^\s+(?:id_card|id_number|ssn|passport(?:_number)?|bank_account|card_number"
    r"|credit_card|tax_id|national_id)\s*:", re.I)
FASTAPI_APP = re.compile("FastAPI[ ]*[(]")
DOCS_OFF = re.compile(r"docs_url[ ]*=[ ]*None|openapi_url[ ]*=[ ]*None")
DEMO_SHAPE = re.compile(r"debug[ ]*=[ ]*True|allow_origins[ ]*=[ ]*\[[ ]*[\"']\*")
HTTP_SOURCE = re.compile(r"(?<!s)http://")
MANIFESTS = {"requirements.txt", "requirements-dev.txt", "pyproject.toml", "package.json", "Pipfile"}


def _pii_fields(index, path, text, lines, lang) -> list[Finding]:
    out = []
    for m in MODEL_CLASS.finditer(text):
        name = re.match(r"\s*class\s+(\w+)", m.group(0))
        if not name or not name.group(1).endswith(("Out", "Response", "Schema", "Dto")):
            continue
        start = text.count("\n", 0, m.end()) + 1          # the `class` line itself
        for offset in range(1, 14):
            idx = start + offset
            if idx > len(lines):
                break
            if lines[idx - 1].strip() == "":
                break
            if PII_FIELD.match(lines[idx - 1]):
                out.append(_emit("response/pii-fields", index, path, idx, lang=lang,
                                 minus=[lines[idx - 1].rstrip()]))
                break
    return out


def _api_docs(index: ProjectIndex, lang: str) -> list[Finding]:
    """Only when the app already looks shipped: docs alone fire on every FastAPI project."""
    out: list[Finding] = []
    for path, text in index.texts.items():
        if not path.endswith(".py") or not DEMO_SHAPE.search(text):
            continue
        lines = text.splitlines()
        for i, line in enumerate(lines, 1):
            if not FASTAPI_APP.search(line):
                continue
            window = chr(10).join(lines[i - 1:i + 6])
            if DOCS_OFF.search(window):
                continue
            out.append(_emit("config/api-docs-public", index, path, i, lang=lang,
                             minus=[line.rstrip()]))
    return out


def _insecure_source(index: ProjectIndex, lang: str) -> list[Finding]:
    """A dependency fetched over plain HTTP can be replaced on the way in."""
    out: list[Finding] = []
    for path, text in index.texts.items():
        if Path(path).name not in MANIFESTS:
            continue
        for i, raw in enumerate(text.splitlines(), 1):
            line = raw.rstrip()
            if not line or line.lstrip().startswith(("#", "//")):
                continue
            if HTTP_SOURCE.search(line):
                out.append(_emit("deps/insecure-source", index, path, i, lang=lang, minus=[line]))
    return out


def _declared_license(root: Path) -> tuple[str, str]:
    """(declared licence, manifest name) from pyproject.toml or package.json."""
    pyproject = safe_read(root, root / "pyproject.toml")
    if pyproject:
        m = re.search(r'license\s*=\s*\{\s*text\s*=\s*"([^"]+)"', pyproject) or             re.search(r'license\s*=\s*"([^"]+)"', pyproject)
        if m:
            return m.group(1).strip(), "pyproject.toml"
    package = safe_read(root, root / "package.json")
    if package:
        m = re.search(r'"license"\s*:\s*"([^"]+)"', package)
        if m:
            return m.group(1).strip(), "package.json"
    return "", ""


def _license_check(index: ProjectIndex, lang: str) -> list[Finding]:
    root = index.root
    declared, manifest = _declared_license(root)
    if not declared:
        return []
    body = safe_read(root, root / "LICENSE") or safe_read(root, root / "LICENSE.md")
    if not body:
        return [_emit("license/mismatch", index, manifest, 1, lang=lang,
                      minus=[f'{manifest}: license = "{declared}"'],
                      plus=[f"# add a LICENSE file, or drop the declaration"])]
    head = body[:600].lower()
    want = declared.lower()
    missing = ("mit" in want and "mit license" not in head) or               ("apache" in want and "apache license" not in head) or               ("bsd" in want and "redistribution and use" not in head and "bsd" not in head)
    if missing:
        return [_emit("license/mismatch", index, manifest, 1, lang=lang,
                      minus=[f'{manifest}: license = "{declared}"'],
                      plus=[f"# LICENSE says something else — align them or mark UNLICENSED"])]
    return []


OPTIONAL_NAMES = {"ImportError", "ModuleNotFoundError", "Exception", "BaseException"}


def _optional_lines(tree: ast.AST) -> set[int]:
    """`try: import x except ImportError` — the project means for x to be absent."""
    out: set[int] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Try):
            continue
        caught = False
        for handler in node.handlers:
            kind = handler.type
            if kind is None:
                caught = True
            elif isinstance(kind, ast.Name) and kind.id in OPTIONAL_NAMES:
                caught = True
            elif isinstance(kind, ast.Tuple) and any(
                    isinstance(e, ast.Name) and e.id in OPTIONAL_NAMES for e in kind.elts):
                caught = True
        if not caught:
            continue
        for inner in ast.walk(node):
            if isinstance(inner, (ast.Import, ast.ImportFrom)):
                out.add(getattr(inner, "lineno", 0))
    return out


def _undeclared_imports(index: ProjectIndex, lang: str) -> list[Finding]:
    import sys as _sys
    stdlib = set(getattr(_sys, "stdlib_module_names", ())) | {"__future__"}
    from .core import parse_requirements
    manifests: dict[str, set[str]] = {}
    for rel_path in index.files:
        name = Path(rel_path).name
        # A Python import is judged only against Python manifests. A repo with
        # nothing but package.json is not evidence that `pandas` is declared.
        if name in ("requirements.txt", "pyproject.toml"):
            folder = Path(rel_path).parent.as_posix()
            deps_ex = parse_requirements(index.root / folder)
            manifests.setdefault(folder, set()).update(
                d.name.lower().replace("-", "_") for d in deps_ex if d.ecosystem == "pypi")

    def declared_for(rel_path: str) -> set[str] | None:
        parts = Path(rel_path).parent.parts
        for depth in range(len(parts), -1, -1):
            folder = "/".join(parts[:depth]) or "."
            if folder in manifests:
                return manifests[folder]
        return None                      # no manifest at all: nothing to compare against

    local = {Path(f).stem for f in index.files}
    local |= {Path(f).parent.name for f in index.files if Path(f).name == "__init__.py"}
    local |= {Path(f).parts[0] for f in index.files if len(Path(f).parts) > 1}
    local |= {Path(f).parts[1] for f in index.files
              if len(Path(f).parts) > 2 and Path(f).parts[0] == "src"}
    seen: dict[str, tuple[str, int]] = {}
    for path, tree in index.trees.items():
        optional = _optional_lines(tree)
        for node in ast.walk(tree):
            if getattr(node, "lineno", 0) in optional:
                continue
            names: list[str] = []
            if isinstance(node, ast.Import):
                names = [a.name.split(".")[0] for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                names = [node.module.split(".")[0]]
            declared = declared_for(path)
            if declared is None:
                continue
            for name in names:
                if name in stdlib or name in local:
                    continue
                if name.lower() in declared or IMPORT_ALIASES.get(name.lower(), "") in declared:
                    continue
                seen.setdefault(name, (path, node.lineno))
    return [_emit("deps/undeclared-import", index, path, line, lang=lang,
                  minus=[f"import {name}"],
                  plus=[f"# {name} is not in any manifest — add it with a version range"],
                  module=name)
            for name, (path, line) in seen.items()]


HOST_MODULES = {"vscode", "electron", "vscode-webview", "vscode-extension-api"}
MODULE_SPEC = re.compile("^[@A-Za-z][A-Za-z0-9._@/-]*$")
NODE_BUILTINS = {"assert", "buffer", "child_process", "cluster", "console", "constants", "crypto",
                 "dgram", "dns", "domain", "events", "fs", "http", "http2", "https", "inspector",
                 "module", "net", "os", "path", "perf_hooks", "process", "punycode", "querystring",
                 "readline", "repl", "stream", "string_decoder", "timers", "tls", "trace_events",
                 "tty", "url", "util", "v8", "vm", "wasi", "worker_threads", "zlib"}
JS_IMPORT = re.compile(r"""(?:from|require\(|import)\s*['"]([^'"]+)['"]""")
JS_SUFFIX = (".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".vue", ".svelte")


def _nearest_js_deps(index: ProjectIndex, rel_path: str) -> set[str] | None:
    parts = Path(rel_path).parent.parts
    for depth in range(len(parts), -1, -1):
        folder = "/".join(parts[:depth]) or "."
        text = safe_read(index.root, index.root / folder / "package.json")
        if not text:
            continue
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return None
        names: set[str] = set()
        for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
            names.update((data.get(key) or {}).keys())
        return names
    return None


def _js_imports(index: ProjectIndex, lang: str) -> list[Finding]:
    """The JS side of deps/undeclared-import: a bare import no package.json lists."""
    out: list[Finding] = []
    seen: dict[tuple[str, str], int] = {}
    # A monorepo imports its own workspace packages; only the declaring
    # package.json lists them, and it is usually not the nearest one.
    local_pkgs: set[str] = set()
    for rel in index.files:
        if Path(rel).name != "package.json":
            continue
        try:
            data = json.loads(safe_read(index.root, index.root / rel) or "{}")
        except json.JSONDecodeError:
            continue
        declared_name = data.get("name")
        if isinstance(declared_name, str):
            local_pkgs.add(declared_name)
    for path in index.files:
        if not path.endswith(JS_SUFFIX):
            continue
        text = index.texts.get(path, "")
        deps = _nearest_js_deps(index, path)
        if deps is None:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            for match in JS_IMPORT.finditer(line):
                spec = match.group(1)
                if spec.startswith((".", "/")) or not MODULE_SPEC.match(spec):
                    continue                      # a doc string, not an import
                head = spec[5:] if spec.startswith("node:") else spec
                if head.split("/")[0] in NODE_BUILTINS:
                    continue                      # fs/promises is still fs
                name = "/".join(head.split("/")[:2]) if head.startswith("@") else head.split("/")[0]
                if name in deps or name in HOST_MODULES or name in local_pkgs:
                    continue
                seen.setdefault((path, name), i)
    for (path, name), line in seen.items():
        out.append(_emit("deps/undeclared-import", index, path, line, lang=lang,
                         minus=[f"import … from {name!r}"],
                         plus=[f"# {name} is not in the nearest package.json — add it"],
                         module=name))
    return out


def _lockfile(index: ProjectIndex, lang: str) -> list[Finding]:
    """Every package-lock.json in the tree, not just the one at the root."""
    out: list[Finding] = []
    for rel_path in index.files:
        if Path(rel_path).name != "package-lock.json":
            continue
        text = safe_read(index.root, index.root / rel_path)
        if not text:
            continue
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            continue
        packages = data.get("packages") or {}
        entries = [v for k, v in packages.items() if k and isinstance(v, dict) and v.get("version")]
        missing = [v for v in entries if not v.get("integrity") and not v.get("resolved")]
        if entries and missing:
            out.append(_emit("deps/lockfile-integrity", index, rel_path, 1, lang=lang,
                             minus=[f"{rel_path}: {len(missing)}/{len(entries)} entries without integrity"],
                             plus=["npm install --package-lock-only"],
                             count=len(missing)))
    return out


RATE_HINT = re.compile(r"rate.?limit|limiter|throttle|slowapi|key_func|ratelimit", re.I)


def _rate_limit(index: ProjectIndex, lang: str) -> list[Finding]:
    out: list[Finding] = []
    for path, text in index.texts.items():
        if not path.endswith(".py"):
            continue
        lines = text.splitlines()
        for i, line in enumerate(lines, 1):
            if "remote_addr" not in line and "REMOTE_ADDR" not in line:
                continue
            window = " ".join(lines[max(0, i - 3):i + 2])
            if RATE_HINT.search(window):
                out.append(_emit("config/rate-limit-key", index, path, i, lang=lang, minus=[line]))
    return out


HIDDEN_RANGES = ((0x200B, 0x200F), (0x202A, 0x202E), (0x2060, 0x206F),
                 (0x180E, 0x180E), (0xFEFF, 0xFEFF), (0xE0000, 0xE007F))
# A single stray zero-width space is what a copy-paste leaves behind. These
# cannot be explained away: an override or a tag character reorders or hides text.
HIGH_SIGNAL = ((0x202A, 0x202E), (0x2066, 0x2069), (0xE0000, 0xE007F))
AGENT_DIR = re.compile(r"(?:^|/)[.](?:claude|cursor|github|windsurf|continue)/")


def _string_lines(text: str) -> set[int]:
    """Lines inside a multi-line string: a prompt or a docstring, not code.

    The line-based stripper sees an exec call inside a prompt as code; the
    tokenizer knows it is one string that happens to span lines.
    """
    import io
    import tokenize
    out: set[int] = set()
    try:
        for tok in tokenize.generate_tokens(io.StringIO(text).readline):
            if tok.type == tokenize.STRING and tok.end[0] > tok.start[0]:
                out.update(range(tok.start[0], tok.end[0] + 1))
    except (tokenize.TokenError, IndentationError, SyntaxError):
        pass
    return out


def _hidden_codes(text: str) -> list[int]:
    return [ord(ch) for ch in text if any(lo <= ord(ch) <= hi for lo, hi in HIDDEN_RANGES)]


def _instruction_file(rel_path: str) -> bool:
    name = Path(rel_path).name
    return name in INSTRUCTION_NAMES or name == ".mcp.json" or bool(AGENT_DIR.match(rel_path))


def _hidden_chars(index: ProjectIndex, lang: str) -> list[Finding]:
    """Rules File Backdoor: instructions a reviewer cannot see.

    The offending line is deliberately not printed — text that carries hidden
    instructions is text that should not be copied into a report another agent
    will read.
    """
    out: list[Finding] = []
    for path, text in index.texts.items():
        if not _instruction_file(path):
            continue
        codes = _hidden_codes(text[1:] if text.startswith(chr(0xFEFF)) else text)
        strong = [c for c in codes if any(lo <= c <= hi for lo, hi in HIGH_SIGNAL)]
        if not strong and len(codes) < 3:
            continue
        line = 1
        for i, raw in enumerate(text.splitlines(), 1):
            if _hidden_codes(raw):
                line = i
                break
        shown = ", ".join(sorted({"U+%04X" % c for c in codes}))
        summary = f"{len(codes)} invisible character(s): {shown}"
        out.append(_emit("agent/hidden-instructions", index, path, line, lang=lang,
                         minus=[f"{path}:{line}  <- {summary}"],
                         evidence=[Evidence("hidden", path, line, summary)]))
    return out


def _java_rules(index: ProjectIndex, lang: str) -> list[Finding]:
    """The two Java checks that need only a line: cipher choice and digest choice.

    `facts.CODE` holds Python/JS shapes and would misfire on Java, so these run
    in their own pass and work without the optional parser.
    """
    out: list[Finding] = []
    for path, text in index.texts.items():
        if not path.endswith(".java"):
            continue
        for i, raw in enumerate(text.splitlines(), 1):
            line = raw.rstrip()
            if not line or line.lstrip().startswith(("//", "*")):
                continue
            if JAVA_WEAK.search(line):
                out.append(_emit("code/weak-crypto", index, path, i, lang=lang, minus=[line]))
            if WEAK_HASH.search(line) and re.search("pass|pwd|secret", line, re.I):
                out.append(_emit("auth/md5-sha1-password", index, path, i, lang=lang, minus=[line]))
    return out


def _agent_files(index: ProjectIndex, lang: str) -> list[Finding]:
    out: list[Finding] = []
    root = index.root
    env = root / ".env"
    if not env.exists():
        return out
    checks = [root / ".gitignore", root / ".cursorignore", root / ".claude" / "settings.json"]
    def _mentions_env(path: Path) -> bool:
        text = safe_read(root, path)
        if not text:
            return False
        for raw in text.splitlines():
            entry = raw.strip().lstrip("/").strip()
            if entry == ".env" or entry == ".env*":
                return True
            if entry.startswith(".env.") and not entry.endswith(
                    (".example", ".sample", ".template", ".dist", ".md")):
                return True
        return False

    excluded = any(_mentions_env(p) for p in checks)
    if excluded:
        return out
    out.append(_emit("agent/env-not-ignored", index, ".env", 1, lang=lang,
                     minus=[".env  (present, not ignored)"],
                     plus=[".gitignore:  .env", ".cursorignore:  .env"]))
    return out
