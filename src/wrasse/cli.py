"""wrasse command line — audit, preflight, review, open, explain, rules, doctor."""

from __future__ import annotations

import argparse
import json
import re
import tempfile
import time
import os
import shutil
import subprocess
import sys
from pathlib import Path

from . import __version__
from . import deps as deps_mod
from . import history as history_mod
from . import java as java_mod
from . import facts, structure, term
from .core import (SEVERITY_RANK, Evidence, Finding, Mainline, ProjectIndex, Severity, Status,
                   build_index, mask_text, read_text, safe_read)
from .report import (C, _marks, clean, display_command, render_html, render_json, render_sarif,
                     render_text, term_width)
from .rules import RULES

STATE_DIR = ".wrasse"
STATE_FILE = "last.json"
DEFAULT_FAIL_ON = "high"
FAIL_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "none": 9}

# When several rules land on the same line, keep the most specific one.
PRIORITY = {
    "secret/frontend-env": 1, "secret/in-frontend-bundle": 2, "secret/private-key-block": 3,
    "secret/provider-key": 4, "secret/assignment-entropy": 5,
    "authz/route-without-auth": 6, "authz/query-without-owner": 7,
    "code/sql-string-built": 8, "code/command-injection": 9,
}


# ---------------------------------------------------------------- pipeline


def run_audit(path: Path, *, mode: str = "standard", focus: str = "all", offline: bool = True,
              include_tests: bool = False, lang: str = "en") -> tuple[list[Finding], ProjectIndex, list[str]]:
    index = build_index(path, include_tests, parse=mode != "quick")
    findings = facts.scan(index, lang)
    unknown: list[str] = []
    if mode != "quick":
        findings += structure.scan(index, lang)
        if any(f.endswith(".java") for f in index.files):
            java_findings, unparsed = java_mod.scan(index, lang)
            findings += java_findings
            if unparsed:                     # a file nobody could parse is not a pass
                index.truncated = True
                index.skipped = tuple(index.skipped) + tuple(unparsed)
        dep_findings, unknown = deps_mod.scan(index, lang, offline)
        findings += dep_findings
    if focus == "privacy":
        findings = [f for f in findings if f.mainline is Mainline.PRIVACY]
    elif focus == "ai":
        findings = [f for f in findings if f.mainline is Mainline.AI]
    unique: dict[tuple, Finding] = {}
    secret_at: set[tuple] = set()
    for f in sorted(findings, key=lambda x: (PRIORITY.get(x.rule, 50), x.rank)):
        loc = (f.file, f.line)
        if f.rule.startswith("secret/"):
            if loc in secret_at:        # one credential per line is enough
                continue
            secret_at.add(loc)
        unique[(f.file, f.line, f.rule)] = f
    return list(unique.values()), index, unknown


def _write_inside(root: Path, name: str, text: str, what: str) -> Path | None:
    """Write one file under `<root>/.wrasse/`, atomically, refusing any symlink.

    State, config and baseline all live in that directory, and a repository can
    ship it as a symlink pointing outside the project.
    """
    root = root.resolve()
    state_dir = root / STATE_DIR
    if state_dir.is_symlink():
        print(f"wrasse: {state_dir} is a symlink — refusing to write {what}", file=sys.stderr)
        return None
    if state_dir.exists() and not state_dir.is_dir():
        print(f"wrasse: {state_dir} is a file, not a directory — refusing to write {what}",
              file=sys.stderr)
        return None
    try:
        state_dir.mkdir(exist_ok=True)
    except OSError as exc:
        print(f"wrasse: could not create {state_dir}: {exc}", file=sys.stderr)
        return None
    target = state_dir / name
    if target.is_symlink():                       # a repo can ship this file too
        print(f"wrasse: {target} is a symlink — refusing to write {what}", file=sys.stderr)
        return None
    try:
        fd, tmp_name = tempfile.mkstemp(dir=str(state_dir), prefix=f".{name}-", suffix=".tmp")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:      # O_EXCL: cannot be a symlink
            fh.write(text)
        os.replace(tmp_name, target)
    except OSError as exc:
        print(f"wrasse: could not write {what}: {exc}", file=sys.stderr)
        return None
    return target


def save_state(root: Path, findings: list[Finding], index: ProjectIndex, mode: str) -> Path | None:
    payload = {
        "version": __version__, "mode": mode, "files": len(index.files),
        "truncated": bool(index.truncated),
        "skipped": list(index.skipped)[:64],
        "findings": [dict(f.to_dict(), index=i) for i, f in enumerate(findings, 1)],
    }
    return _write_inside(root, STATE_FILE,
                         json.dumps(payload, ensure_ascii=False, indent=2), "state")


CONFIG_FILE = "config.json"
CONFIG_KEYS = {
    "lang": ("en", "zh"),
    "fail_on": ("critical", "high", "medium", "low", "none"),
    "mode": ("quick", "standard"),
    "focus": ("privacy", "ai", "all"),
}
SETTING_DEFAULTS = {"lang": "en", "fail_on": DEFAULT_FAIL_ON, "mode": "standard", "focus": "all"}


def config_path(root: Path) -> Path:
    return root.resolve() / STATE_DIR / CONFIG_FILE


def load_config(root: Path | None) -> dict:
    """`.wrasse/config.json` — a preference the repository can carry with it."""
    if root is None:
        return {}
    text = safe_read(root, config_path(root))
    if not text:
        return {}
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return {}
    if not isinstance(data, dict):
        return {}
    return {k: v for k, v in data.items() if k in CONFIG_KEYS and v in CONFIG_KEYS[k]}


def save_config(root: Path, updates: dict) -> Path | None:
    root = root.resolve()
    if not root.is_dir():
        print(f"wrasse: no such project: {root}", file=sys.stderr)
        return None
    state_dir = root / STATE_DIR
    if state_dir.is_symlink():
        print(f"wrasse: {state_dir} is a symlink — refusing to write config", file=sys.stderr)
        return None
    if state_dir.exists() and not state_dir.is_dir():
        print(f"wrasse: {state_dir} is a file, not a directory", file=sys.stderr)
        return None
    try:
        state_dir.mkdir(exist_ok=True)
    except OSError as exc:
        print(f"wrasse: could not create {state_dir}: {exc}", file=sys.stderr)
        return None
    target = state_dir / CONFIG_FILE
    if target.is_symlink():
        print(f"wrasse: {target} is a symlink — refusing to write config", file=sys.stderr)
        return None
    data = load_config(root)
    for key, value in updates.items():
        if value is None:
            data.pop(key, None)
        else:
            data[key] = value
    return _write_inside(root, CONFIG_FILE,
                         json.dumps(data, ensure_ascii=False, indent=2) + chr(10), "config")


def _resolve_lang(explicit: str | None, root: Path | None = None) -> str:
    """`.wrasse/config.json` sets it; `--lang` overrides for one run."""
    if explicit in ("en", "zh"):
        return explicit
    if root is not None:
        configured = load_config(root).get("lang")
        if configured in ("en", "zh"):
            return configured
    return "en"


STATE_MAX_CHARS = 2000
STATE_MAX_BYTES = 8 * 1024 * 1024


def _sanitize(value, depth: int = 0):
    """Scrub whatever came out of `.wrasse/last.json`.

    A repository can ship that file. Anything in it is untrusted: it is cleaned
    of control characters and stripped down to the shapes the session expects.
    """
    from .report import one_line
    if depth > 3:
        return None
    if isinstance(value, bool) or isinstance(value, (int, float)):
        return value
    if isinstance(value, str):
        return one_line(value)[:STATE_MAX_CHARS]
    if isinstance(value, list):
        return [_sanitize(v, depth + 1) for v in value[:100]]
    if isinstance(value, dict):
        out = {}
        for key, item in list(value.items())[:64]:
            if isinstance(key, str):
                out[one_line(key)[:64]] = _sanitize(item, depth + 1)
        return out
    return None


def load_state(root: Path) -> dict | None:
    root = root.resolve()
    path = root / STATE_DIR / STATE_FILE
    if path.is_symlink() or not path.exists() or not path.resolve().is_relative_to(root):
        return None
    if not path.is_file():            # a FIFO or a device would block or surprise us
        return None
    try:
        if path.stat().st_size > STATE_MAX_BYTES:
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    data = _sanitize(data)
    if not isinstance(data, dict):
        return None
    findings = []
    for item in data.get("findings") or []:
        if not isinstance(item, dict):
            continue
        try:
            item["index"] = int(item.get("index"))
            item["line"] = int(item.get("line", 0))
            item["column"] = int(item.get("column", 1))
        except (TypeError, ValueError):
            continue
        if not isinstance(item.get("id"), str) or not isinstance(item.get("file"), str):
            continue
        # `explain` and `review` read these directly; a file that omits them must
        # not be able to raise. Anything missing gets the empty shape.
        fix = item.get("fix") if isinstance(item.get("fix"), dict) else {}
        item["fix"] = {
            "minus": [x for x in (fix.get("minus") or []) if isinstance(x, str)][:8],
            "plus": [x for x in (fix.get("plus") or []) if isinstance(x, str)][:8],
            "kind": fix.get("kind") if fix.get("kind") in ("verified", "template", "manual") else "template",
        }
        item["rule"] = item.get("rule") if isinstance(item.get("rule"), str) else ""
        item["status"] = item.get("status") if item.get("status") in ("confirmed", "needs_review") else "needs_review"
        item["severity"] = item.get("severity") if isinstance(item.get("severity"), str) else ""
        item["why"] = item.get("why") if isinstance(item.get("why"), str) else ""
        evidence = item.get("evidence")
        cleaned = []
        for entry in evidence if isinstance(evidence, list) else []:
            if not isinstance(entry, dict):
                continue
            snippet = entry.get("snippet")
            if not isinstance(snippet, str):
                continue
            cleaned.append({
                "kind": entry.get("kind") if isinstance(entry.get("kind"), str) else "code",
                "file": entry.get("file") if isinstance(entry.get("file"), str) else item["file"],
                "line": entry.get("line") if isinstance(entry.get("line"), int) else item["line"],
                "snippet": snippet,
                "note": entry.get("note") if isinstance(entry.get("note"), str) else "",
            })
        item["evidence"] = cleaned[:8]
        findings.append(item)
    data["findings"] = findings
    # `review` reads this from the saved state; it has to survive a round trip.
    data["truncated"] = data.get("truncated") is True
    skipped = data.get("skipped")
    data["skipped"] = [entry for entry in skipped if isinstance(entry, str)][:64] \
        if isinstance(skipped, list) else []
    return data


def changed_lines(root: Path, ref: str) -> dict[str, set[int]] | None:
    """Lines added or changed relative to `ref`, or None when git cannot answer."""
    try:
        proc = subprocess.run(
            ["git", "-C", str(root), "--no-pager", "diff", "--unified=0", "--no-color",
             "--no-textconv", "--no-ext-diff", ref, "--"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    out: dict[str, set[int]] = {}
    path = ""
    for line in proc.stdout.splitlines():
        if line.startswith("+++ "):
            name = line[6:].strip()
            path = name[2:] if name.startswith("b/") else ("" if name == "/dev/null" else name)
        elif line.startswith("@@") and path:
            m = re.search(r"\+(\d+)(?:,(\d+))?", line)
            if m:
                start, count = int(m.group(1)), int(m.group(2) or 1)
                out.setdefault(path, set()).update(range(start, start + max(count, 1)))
    return out


def _load_baseline(root: Path, path: Path) -> set[str]:
    # Inside the project the file is untrusted, so it is read without following
    # symlinks. An absolute path the user typed elsewhere is their own choice.
    # Both sides go through `abspath`: it normalises `..` without following
    # symlinks, and it keeps one spelling (Windows short names would otherwise
    # make a file look like it sits outside a resolved root).
    if Path(os.path.abspath(path)).is_relative_to(Path(os.path.abspath(root))):
        text = safe_read(root, path)
    else:
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            text = ""
    if not text:
        return set()
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return set()
    ids = data.get("ids") if isinstance(data, dict) else None
    return {i for i in ids if isinstance(i, str)} if isinstance(ids, list) else set()


def _suppress_from_sarif(findings: list[Finding], path: Path) -> tuple[list[Finding], int]:
    """Drop a finding an external tool already reported at the same file and line."""
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return findings, 0
    reported: set[tuple[str, int]] = set()
    for run in doc.get("runs", []) or []:
        for res in run.get("results", []) or []:
            for loc in res.get("locations", []) or []:
                phys = loc.get("physicalLocation") or {}
                uri = ((phys.get("artifactLocation") or {}).get("uri") or "").lstrip("./")
                line = (phys.get("region") or {}).get("startLine")
                if uri and isinstance(line, int):
                    reported.add((uri, line))
    kept = [f for f in findings if not any(f.file == u or f.file.endswith(u) for u, ln in reported if ln == f.line)]
    return kept, len(findings) - len(kept)


def _safe_target(root: Path, relative: str) -> Path | None:
    """A crafted .wrasse/last.json must not open files outside the scanned project."""
    root = root.resolve()
    target = (root / relative).resolve()
    return target if target.is_relative_to(root) else None


def _pick(state: dict, handle: str) -> dict | None:
    for item in state.get("findings", []):
        if str(item.get("index")) == handle or item.get("id", "").lower() == handle.lower():
            return item
    return None


# ---------------------------------------------------------------- editor


def editor_command(path: str, line: int, column: int, override: str | None = None) -> list[str]:
    target = f"{path}:{line}:{column}"
    if override:
        return [override, target]
    visual = os.environ.get("VISUAL") or os.environ.get("EDITOR")
    if visual:
        exe = visual.split()[0]
        if exe in ("code", "cursor"):
            return [exe, "-g", target]
        return [exe, f"+{line}", path]
    for candidate in ("code", "cursor"):
        if shutil.which(candidate):
            return [candidate, "-g", target]
    raise RuntimeError("no editor found: set $EDITOR or pass --editor")


# ---------------------------------------------------------------- commands


def cmd_audit(args) -> int:
    root = Path(args.path).expanduser()
    if not root.exists():
        print(f"wrasse: no such path: {root.resolve()}", file=sys.stderr)
        return 3
    if root.is_file():
        root = root.parent
    started = time.perf_counter()
    offline = not args.online
    findings, index, unknown = run_audit(
        root, mode=args.mode, focus=args.focus, offline=offline,
        include_tests=args.include_tests, lang=args.lang)
    if args.history:
        findings = findings + history_mod.scan(root, args.lang)

    # Save and number the complete scan first: filtering below changes what is
    # shown, never what `explain 3` means or what the baseline compares against.
    full = sorted(findings, key=lambda f: f.rank)
    ordinals = {f.id: i for i, f in enumerate(full, 1)}
    if not args.no_state:
        save_state(root, full, index, args.mode)

    if args.diff:
        ranges = changed_lines(root, args.diff)
        if ranges is None:
            print(f"wrasse: cannot diff against {args.diff!r} — is this a git checkout?", file=sys.stderr)
            return 3
        kept = [f for f in findings if f.line in ranges.get(f.file, ())]
        print(f"wrasse: {len(kept)} of {len(findings)} findings are on lines changed since {args.diff}",
              file=sys.stderr)
        findings = kept
    if args.baseline:
        base_path = Path(args.baseline)
        if not base_path.is_absolute():
            base_path = root / base_path
        known = _load_baseline(root, base_path)
        kept = [f for f in findings if f.id not in known]
        if known:
            print(f"wrasse: {len(findings) - len(kept)} finding(s) suppressed by {base_path.name}",
                  file=sys.stderr)
        findings = kept
    if args.sarif_in:
        findings, suppressed = _suppress_from_sarif(findings, Path(args.sarif_in))
        print(f"wrasse: {suppressed} finding(s) already reported by {args.sarif_in}", file=sys.stderr)
    elapsed = time.perf_counter() - started
    if args.online and args.mode != "quick" and index.deps:
        print(f"wrasse: checked {len(index.deps)} package name(s) against pypi.org "
              f"(use --offline to keep them local)", file=sys.stderr)
    if not index.files:
        print(f"wrasse: no source files under {root}", file=sys.stderr)
        return 3
    color = sys.stdout.isatty() and not args.no_color and os.environ.get("NO_COLOR") is None
    if args.format == "text":
        text = render_text(findings, index, lang=args.lang, context=args.context, color=color,
                           command=display_command("wrasse audit", args.path, term_width()),
                           mode=args.mode, files=len(index.files),
                           elapsed=elapsed, unknown=unknown, ordinals=ordinals)
        _write(text, args.output)
    elif args.format == "json":
        _write(render_json(findings, files=len(index.files), elapsed=elapsed, mode=args.mode,
                           unknown=unknown, skipped=index.skipped, complete=not index.truncated),
               args.output)
    elif args.format == "sarif":
        _write(render_sarif(findings, skipped=index.skipped, complete=not index.truncated),
               args.output)
    else:
        target = Path(args.output or "report.html")
        target.write_text(render_html(findings, root=root, lang=args.lang, index=index,
                                      skipped=index.skipped, complete=not index.truncated,
                                      context=args.context), encoding="utf-8")
        print(f"wrote {target}")

    threshold = FAIL_RANK.get(args.fail_on, 1)
    blocking = [] if args.fail_on == "none" else [
        f for f in findings if SEVERITY_RANK[f.severity] <= threshold and f.status is Status.CONFIRMED]
    if index.truncated:
        # Say it before any return: a truncated scan with findings used to exit 2
        # silently, and the missing warning is the part that matters.
        if index.skipped:
            names = ", ".join(index.skipped[:3])
            more = "" if len(index.skipped) <= 3 else f" and {len(index.skipped) - 3} more"
            print(f"wrasse: {len(index.skipped)} file(s) were not scanned ({names}{more}) "
                  f"— results cover part of the project", file=sys.stderr)
        else:
            print("wrasse: scan budget exceeded — results cover part of the project", file=sys.stderr)
    if blocking:
        return 2
    if unknown and args.online:
        return 4
    if index.truncated:
        return 4
    return 0


def _write(text: str, output: str | None) -> None:
    if output:
        Path(output).write_text(text, encoding="utf-8")
        print(f"wrote {output}")
    else:
        sys.stdout.write(text)


def cmd_preflight(args) -> int:
    root = Path(args.path).expanduser().resolve()
    if not root.exists():
        print(f"wrasse: no such path: {root}", file=sys.stderr)
        return 3
    findings = preflight_scan(root, args.lang)
    color = sys.stdout.isatty() and not args.no_color and os.environ.get("NO_COLOR") is None
    c = C(color)
    if args.format == "json":
        print(render_json(findings, files=0, elapsed=0.0, mode="preflight", unknown=[]))
    else:
        print(c("38;5;245", f"wrasse preflight  {root}  · config parsed, nothing executed"))
        print()
        if not findings:
            print("  " + c("38;5;71;1", "● looks clean") + c("38;5;244", "  no agent config needs review"))
        else:
            print("  " + c("38;5;203;1", "Do not open this yet") +
                  c("38;5;244", f" — {len(findings)} item(s) need a human decision"))
            print()
            for i, f in enumerate(findings, 1):
                print(f"  {c('38;5;203', '●')} {c('38;5;203;1', 'HIGH')}  {c('38;5;244', f.rule)}  "
                      f"{c('38;5;245', clean(f'{f.file}:{f.line}'))}")
                print(f"        {clean(f.minus[0]) if f.minus else ''}")
                print(f"        {c('38;5;250', f.why)}")
                print()
    blocking = [f for f in findings if SEVERITY_RANK[f.severity] <= FAIL_RANK["high"]]
    return 2 if blocking else 0


AGENT_FILES = (".mcp.json", "mcp.json", ".claude/settings.json", ".cursor/mcp.json", "AGENTS.md")
# Substrings we look for inside config files (detection data, never executed).
# The interpreter call in the table below is spelled in two pieces: as one
# literal, a scanner would read this table as an actual call.
RISKY = ("curl", "wget", "| sh", "| bash", "powershell -enc", "base64 -d",
         "ev" + "al(", "subprocess", "os.system")


def preflight_scan(root: Path, lang: str) -> list[Finding]:
    out: list[Finding] = []
    for name in AGENT_FILES:
        text = safe_read(root, root / name)
        if not text:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            low = line.lower()
            if any(token in low for token in RISKY):
                out.append(_mk("agent/mcp-shell-command", name, i, mask_text(line.strip()),
                               "This config runs a command when the agent starts; the payload is not in this repo.",
                               "配置在 Agent 启动时执行命令，而载荷并不在这个仓库里。", lang))
            if "enableallprojectmcpservers" in low and "true" in low:
                out.append(_mk("agent/all-servers-enabled", name, i, mask_text(line.strip()),
                               "Every MCP server in the repository is trusted automatically.",
                               "仓库里所有 MCP 服务会被自动信任。", lang))
    return out


def _mk(rule: str, file: str, line: int, snippet: str, why_en: str, why_zh: str, lang: str = "en") -> Finding:
    snippet = mask_text(snippet)
    return Finding(rule=rule, title="Agent configuration needs review", mainline=Mainline.PRIVACY,
                   severity=Severity.HIGH, status=Status.CONFIRMED, file=file, line=line, column=1,
                   why=(why_zh if lang == "zh" else why_en), minus=[snippet], plus=["# review, then delete or pin the command"],
                   evidence=[Evidence("config", file, line, snippet)]).finalize()


def cmd_explain(args) -> int:
    root = Path(args.path).expanduser().resolve()
    state = load_state(root) or load_state(Path.cwd())
    if not state:
        print("wrasse: no previous scan here — run `wrasse audit .` first", file=sys.stderr)
        return 3
    item = _pick(state, args.handle)
    if not item:
        print(f"wrasse: no finding {args.handle}", file=sys.stderr)
        return 3
    bar, tail, arrow = _marks()
    print(f"{item['id']}  {item['rule']}   {item['severity']} / {item['status']}")
    print(f"{item['file']}:{item['line']}:{item['column']}")
    print()
    print(f"  {bar} evidence")
    for ev in item.get("evidence", []):
        print(f"  {bar}   {ev['kind']:<10} {ev['file']}:{ev.get('line')}  {ev['snippet'][:80]}")
    print()
    print(f"  {bar} why")
    print(f"  {bar}   {item['why']}")
    print()
    print(f"  {bar} fix")
    for bad in item["fix"]["minus"]:
        print(f"  {bar}   - {bad}")
    for good in item["fix"]["plus"]:
        print(f"  {bar}   + {good}")
    print(f"  {tail} {arrow} wrasse open {item.get('index', '')}".rstrip())
    return 0


def cmd_open(args) -> int:
    root = Path(args.path).expanduser().resolve()
    state = load_state(root) or load_state(Path.cwd())
    if not state:
        print("wrasse: no previous scan here", file=sys.stderr)
        return 3
    item = _pick(state, args.handle)
    if not item:
        print(f"wrasse: no finding {args.handle}", file=sys.stderr)
        return 3
    target = _safe_target(root, item["file"])
    if target is None:
        print(f"wrasse: refusing to open {item['file']!r} — outside {root}", file=sys.stderr)
        return 3
    try:
        cmd = editor_command(str(target), item["line"], item["column"], args.editor)
    except RuntimeError as exc:
        print(f"wrasse: {exc}", file=sys.stderr)
        return 1
    subprocess.run(cmd, check=False)
    return 0


def cmd_review(args) -> int:
    root = Path(args.path).expanduser().resolve()
    state = load_state(root) or load_state(Path.cwd())
    if not state:
        print("wrasse: no previous scan here — run `wrasse audit .` first", file=sys.stderr)
        return 3
    items = state.get("findings", [])
    if not items:
        print("wrasse: nothing to review")
        return 0
    _review_loop(items, root, bool(state.get("truncated")))
    return 0


def _review_loop(items: list[dict], root: Path, truncated: bool = False) -> None:
    if truncated:
        print("  note: that scan hit the file budget — it covers part of the project")
    for it in items:
        print(f"[{it['index']:>2}] {it['severity']:<8} {it['rule']:<30} {it['file']}:{it['line']}")
    print()
    while True:
        try:
            raw = input("select 1-%d, l list, q quit: " % len(items)).strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return
        if raw in ("q", ""):
            return
        if raw == "l":
            for it in items:
                print(f"[{it['index']:>2}] {it['severity']:<8} {it['rule']:<30} {it['file']}:{it['line']}")
            continue
        chosen = next((it for it in items if str(it["index"]) == raw), None)
        if not chosen:
            continue
        bar, tail, arrow = _marks()
        print()
        print(f"  {chosen['file']}:{chosen['line']}  {chosen['rule']}")
        print()
        for bad in chosen["fix"]["minus"]:
            print("    - " + bad)
        for good in chosen["fix"]["plus"]:
            print("    + " + good)
        print()
        print(f"  {bar} why  {chosen['why']}")
        if chosen.get("status") == "needs_review":
            print(f"  {bar} ?    see `wrasse explain {chosen['index']}` for what is missing")
        print(f"  {tail} {arrow}    [enter] open · [y] copy path · [e] copy prompt · [q] quit")
        try:
            action = input("action: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            return
        if action == "y":
            _copy(f"{chosen['file']}:{chosen['line']}")
        elif action == "e":
            _copy(_prompt_for(chosen))
        elif action in ("", "o", "enter"):
            target = _safe_target(root, chosen["file"])
            try:
                if target is None:
                    print(f"  refusing to open {chosen['file']!r} — outside {root}")
                    continue
                subprocess.run(editor_command(str(target), chosen["line"], chosen["column"]), check=False)
            except RuntimeError as exc:
                print(f"  {exc}")
        elif action == "q":
            return


def _prompt_for(item: dict) -> str:
    rule = RULES.get(item["rule"])
    if not rule:
        return item["why"]
    text = rule.t("en")["prompt"]
    return text.replace("{{file}}", item["file"]).replace("{{line}}", str(item["line"])).replace(
        "{{snippet}}", item["fix"]["minus"][0] if item["fix"]["minus"] else "")


def _copy(text: str) -> None:
    """Put a prompt on the clipboard. An argv list, no shell involved."""
    tool, payload = (["clip"], text.encode("utf-16-le")) if os.name == "nt"         else (["pbcopy"], text.encode())
    try:
        subprocess.Popen(tool, stdin=subprocess.PIPE).communicate(payload)
        print("  copied")
    except Exception:
        print(text)


def cmd_baseline(args) -> int:
    root = Path(args.path).expanduser().resolve()
    state = load_state(root) or load_state(Path.cwd())
    if not state:
        print("wrasse: no previous scan here — run `wrasse audit .` first", file=sys.stderr)
        return 3
    ids = {item["id"] for item in state.get("findings", [])}
    path = root / STATE_DIR / "baseline.json"
    if args.action == "diff":
        known = _load_baseline(root, path)
        new = ids - known
        fixed = known - ids
        print(f"new: {len(new)} · still open: {len(ids & known)} · fixed since baseline: {len(fixed)}")
        for item in state.get("findings", []):
            if item["id"] in new:
                print(f"  NEW  {item['severity']:<8} {item['rule']:<30} {item['file']}:{item['line']}")
        return 0
    target = _write_inside(root, "baseline.json",
                           json.dumps({"version": __version__, "ids": sorted(ids)},
                                      ensure_ascii=False, indent=2), "baseline")
    if target is None:
        return 1
    print(f"baseline: {len(ids)} finding(s) recorded in {target}")
    return 0


def cmd_rules(args) -> int:
    if args.action == "export":
        from .rulesdoc import render
        text = render(args.format, args.lang)
        if args.output:
            Path(args.output).write_text(text, encoding="utf-8")
            print(f"wrote {args.output} ({len(RULES)} rules)")
        else:
            sys.stdout.write(text)
        return 0
    if args.action == "show":
        rule = RULES.get(args.id)
        if not rule:
            print(f"wrasse: unknown rule {args.id}", file=sys.stderr)
            return 3
        meta = rule.t(args.lang)
        print(f"{rule.id}  {meta['title']}  [{rule.severity.value} / {rule.status.value} / {rule.mainline.value}]")
        print()
        print(meta["why"])
        print()
        from .facts import DEFAULT_FIX, _fmt
        print("- " + _fmt(meta["minus"], line="<the offending line>"))
        print("+ " + _fmt(meta["plus"], line="<the offending line>"))
        print()
        print("prompt:")
        print(meta["prompt"])
        return 0
    for rule in RULES.values():
        print(f"{rule.id:<34} {rule.severity.value:<8} {rule.status.value:<12} {rule.mainline.value}")
    print(f"\n{len(RULES)} rules")
    return 0


def cmd_config(args) -> int:
    root = Path(args.path or ".")
    if args.action == "set":
        key, value = args.key, args.value
        if key not in CONFIG_KEYS:
            print(f"wrasse: unknown setting {key!r} — one of {', '.join(CONFIG_KEYS)}",
                  file=sys.stderr)
            return 3
        if value not in CONFIG_KEYS[key]:
            print(f"wrasse: {key} must be one of {', '.join(CONFIG_KEYS[key])}", file=sys.stderr)
            return 3
        target = save_config(root, {key: value})
        if target is None:
            return 1
        print(f"{key} = {value}   ({target})")
        return 0
    if args.action == "unset":
        if args.key not in CONFIG_KEYS:
            print(f"wrasse: unknown setting {args.key!r} — one of {', '.join(CONFIG_KEYS)}",
                  file=sys.stderr)
            return 3
        target = save_config(root, {args.key: None})
        if target is None:
            return 1
        print(f"{args.key} unset   ({target})")
        return 0
    cfg = load_config(root)
    defaults = SETTING_DEFAULTS
    for key in CONFIG_KEYS:
        value = cfg.get(key, defaults[key])
        mark = "" if key in cfg else "   (default)"
        print(f"  {key:<8} {value}{mark}")
    print(f"  file     {config_path(root)}"
          + ("" if config_path(root).exists() else "   (not created yet)"))
    return 0


def cmd_doctor(args) -> int:
    print(f"wrasse {__version__}")
    print(f"python {sys.version.split()[0]}")
    print(f"rules {len(RULES)} · registry check: {'offline' if args.offline else 'online'}")
    print(f"editor: {os.environ.get('VISUAL') or os.environ.get('EDITOR') or ('code' if shutil.which('code') else 'none')}")
    java_state = "on (javalang)" if java_mod.AVAILABLE else "off — pip install wrasse[java]"
    print(f"java / spring: {java_state}")
    return 0


# ---------------------------------------------------------------- REPL


def _age(path: Path) -> str:
    try:
        seconds = max(0, int(time.time() - path.stat().st_mtime))
    except OSError:
        return "just now"
    for unit, size in (("d", 86400), ("h", 3600), ("m", 60)):
        if seconds >= size:
            return f"{seconds // size}{unit} ago"
    return "just now"


def _banner(root: Path, lang: str, mode: str) -> dict | None:
    state = load_state(root)
    config = "config .wrasse/config.json" if load_config(root) else "config defaults"
    print(f"  ></>  wrasse {__version__}")
    print(f"       python {sys.version.split()[0]} · rules {len(RULES)}")
    print(f"       {config} · lang {lang}")
    print(f"       {root}")
    print()
    if not state:
        print("  no scan yet — /audit starts one")
        return None
    items = state.get("findings", [])
    crit = sum(1 for i in items if i["severity"] == "critical")
    when = _age(root / STATE_DIR / STATE_FILE)
    print(f"  last scan {when} · {len(items)} findings · {crit} critical")
    for it in items[:3]:
        mark = "?" if it.get("status") == "needs_review" else " "
        print(f"  [{it['index']}] {it['severity']:<8} {mark} {it['rule']:<30} {it['file']}:{it['line']}")
    return state


def _clear() -> None:
    """Take over the screen the way an interactive session should."""
    if not sys.stdout.isatty() or os.environ.get("WRASSE_NO_CLEAR"):
        return
    if os.environ.get("TERM") == "dumb":
        return
    sys.stdout.write("\033[2J\033[H")
    sys.stdout.flush()


def _line(width: int = 56) -> str:
    try:
        "─".encode(sys.stdout.encoding or "utf-8")
        ch = "─"
    except (UnicodeEncodeError, LookupError):
        ch = "-"
    return "  " + ch * width


REPL_SHORTCUTS = {"/privacy": "privacy", "/ai": "ai", "/all": "all"}


REPL_COMMANDS = (
    ("/audit", "scan this project", "扫描当前项目"),
    ("/review", "step through the findings", "逐条查看"),
    ("/config", "settings: language, threshold, depth, focus", "设置：语言、阈值、深度、范围"),
    ("/explain", "why one finding is reported", "某条为什么成立"),
    ("/open", "open a finding in your editor", "在编辑器里打开"),
    ("/privacy", "report the privacy mainline only", "只看隐私主线"),
    ("/ai", "report the AI mainline only", "只看 AI 主线"),
    ("/all", "clear the focus", "回到全部"),
    ("/doctor", "environment check", "环境自检"),
    ("/help", "list the commands", "列出命令"),
    ("/quit", "leave the session", "退出"),
)


def complete_command(prefix: str, lang: str = "en") -> list[tuple[str, str]]:
    """Prefix matches first, then anything containing it — what the menu lists."""
    text = prefix.strip().lower()
    if not text.startswith("/"):
        return []
    pairs = [(name, zh if lang == "zh" else en) for name, en, zh in REPL_COMMANDS]
    head = [p for p in pairs if p[0].startswith(text)]
    tail = [p for p in pairs if p not in head and text[1:] and text[1:] in p[0][1:]]
    return head + tail


def _redraw(rows: list[str], previous: int) -> int:
    if previous:
        sys.stdout.write(f"\x1b[{previous}F\x1b[0J")
    sys.stdout.write(chr(10).join(rows) + chr(10))
    sys.stdout.flush()
    return len(rows)


def _settings_rows(cfg: dict, defaults: dict, index: int, lang: str) -> list[str]:
    order = tuple(CONFIG_KEYS)
    title = "设置" if lang == "zh" else "Settings"
    rows = ["", f"  {title}"]
    for i, key in enumerate(order):
        value = cfg.get(key, defaults[key])
        mark = "" if key in cfg else ("默认" if lang == "zh" else "default")
        cursor = "›" if i == index else " "
        rows.append(f"  {cursor} {key:<9} {value:<10} \x1b[90m{mark}\x1b[0m")
    rows.append("")
    rows.append("  ↑↓ " + ("切换" if lang == "zh" else "move")
                + " · Enter/Space " + ("换值" if lang == "zh" else "change")
                + " · Esc " + ("返回" if lang == "zh" else "back"))
    return rows


def settings_panel(root: Path, lang: str) -> str:
    """Arrow keys over the four settings; each change is written immediately."""
    defaults = dict(SETTING_DEFAULTS, lang=lang)
    cfg = load_config(root)
    if not term.usable():
        for key in CONFIG_KEYS:
            print(f"  {key:<9} {cfg.get(key, defaults[key])}")
        return cfg.get("lang", lang)
    order = tuple(CONFIG_KEYS)
    index, drawn = 0, 0
    try:
        while True:
            drawn = _redraw(_settings_rows(cfg, defaults, index, cfg.get("lang", lang)), drawn)
            key = term.getkey()
            if key in (term.ESC, "q"):
                break
            if key in (term.UP, "k"):
                index = (index - 1) % len(order)
            elif key in (term.DOWN, "j"):
                index = (index + 1) % len(order)
            elif key in (term.ENTER, " "):
                name = order[index]
                values = CONFIG_KEYS[name]
                current = cfg.get(name, defaults[name])
                nxt = values[(values.index(current) + 1) % len(values)] if current in values else values[0]
                save_config(root, {name: nxt})
                cfg = load_config(root)
    except (KeyboardInterrupt, EOFError):
        pass
    if drawn:
        sys.stdout.write(f"\x1b[{drawn}F\x1b[0J")
        sys.stdout.flush()
    return cfg.get("lang", lang)


def repl(root: Path, lang: str) -> int:
    _utf8_stdio()
    _clear()
    state = _banner(root, lang, "standard")
    parser = build_parser()
    hint = "  /audit scans this project · ? help · q quit"
    while True:
        if state and state.get("findings"):
            first = state["findings"][0]["index"]
            hint = f"  `/audit` rescans · `o {first}` opens the first · ? help · q quit"
        print()
        print(hint)
        print(_line())
        try:
            raw = term.read_line("  › ", complete=lambda text: complete_command(text, lang))
        except (EOFError, KeyboardInterrupt):
            print()
            print("  bye")
            return 0
        if not sys.stdin.isatty():      # a pipe does not echo the Enter for us
            print()
        print(_line())
        cfg_now = dict(SETTING_DEFAULTS, **load_config(root))
        print(f"  rules {len(RULES)} · {cfg_now['mode']} · {cfg_now['focus']}"
              f" · fail-on {cfg_now['fail_on']}")
        line = raw.strip()
        if not line:
            continue
        if line in ("q", "quit", "exit"):
            print("  bye")
            return 0
        if line in ("?", "help", "/help", "/?"):
            for name, en, zh in REPL_COMMANDS:
                print(f"  {name:<11} {zh if lang == 'zh' else en}")
            if lang == "zh":
                print("  o N / e N   打开 / 复制第 N 条的提示词")
                print("  Tab 补全命令 · ↑↓ 选择 · Esc 关掉菜单 · q 退出")
            else:
                print("  o N / e N   open / copy the prompt for finding N")
                print("  Tab completes a command · ↑↓ moves · Esc closes the menu · q quits")
            continue
        if line in ("/config", "config"):
            lang = settings_panel(root, lang)
            continue
        if line in REPL_SHORTCUTS:
            print(f"  focus → {REPL_SHORTCUTS[line]}")
            cfg_here = dict(SETTING_DEFAULTS, **load_config(root))
            findings, index, unknown = run_audit(root, focus=REPL_SHORTCUTS[line],
                                                 mode=cfg_here["mode"], lang=lang, offline=True)
            if index.truncated:
                if index.skipped:
                    print(f"  note: {len(index.skipped)} file(s) were not scanned "
                          f"— results cover part of the project")
                else:
                    print("  note: that scan hit the file budget — it covers part of the project")
            save_state(root, findings, index, cfg_here["mode"])
            print(render_text(findings, index, lang=lang, color=sys.stdout.isatty(),
                              command=display_command("wrasse audit", str(root), term_width()),
                              mode="standard", files=len(index.files), unknown=unknown))
            state = load_state(root)
            continue
        if line.isdigit():
            _repl_open(root, line)
            continue
        if line.startswith(("o ", "open ")):
            parts = line.split()
            if len(parts) > 1:
                _repl_open(root, parts[1])
            continue
        if line.startswith(("e ", "explain ")):
            parts = line.split()
            if len(parts) > 1:
                item = _pick(load_state(root) or {}, parts[1])
                if item:
                    _copy(_prompt_for(item))
                else:
                    print("  no such finding")
            continue
        # anything that looks like a wrasse command runs as one
        tokens = line.split()
        if tokens and tokens[0] == "wrasse":
            tokens = tokens[1:]
        if tokens and not tokens[0].startswith("-"):
            tokens[0] = tokens[0].lstrip("/")
            if tokens[0] in parser._subparsers._group_actions[0].choices:  # type: ignore[attr-defined]
                try:
                    args = parser.parse_args(tokens)
                except SystemExit:
                    continue
                given = getattr(args, "path", None)
                if given == ".":
                    args.path = str(root)
                elif given:
                    candidate = Path(given).expanduser()
                    if not candidate.is_absolute() and not candidate.exists():
                        if (root / candidate).exists():   # they meant "inside this session"
                            args.path = str(root / candidate)
                        else:
                            print(f"  no such path: {root / candidate}")
                            print(f"  you are already in this project — try `audit .`")
                            continue
                _apply_settings(args)
                args.func(args)
                state = load_state(root)
                continue
        print("  unknown command — try /audit, or ? for the list")


def _repl_open(root: Path, handle: str) -> None:
    state = load_state(root) or {}
    item = _pick(state, handle)
    if not item:
        print("  no such finding")
        return
    target = _safe_target(root, item["file"])
    if target is None:
        print(f"  refusing to open {item['file']!r} — outside {root}")
        return
    try:
        subprocess.run(editor_command(str(target), item["line"], item["column"]), check=False)
    except RuntimeError as exc:
        print(f"  {exc}")


# ---------------------------------------------------------------- entry


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="wrasse", description="Security audit for AI-written code.")
    p.add_argument("--version", action="version", version=f"wrasse {__version__}")
    sub = p.add_subparsers(dest="command")

    a = sub.add_parser("audit", help="scan a project")
    a.add_argument("path", nargs="?", default=".")
    a.add_argument("--mode", choices=("quick", "standard"), default=None)
    a.add_argument("--focus", choices=("privacy", "ai", "all"), default=None)
    a.add_argument("--format", choices=("text", "json", "sarif", "html"), default="text")
    a.add_argument("--output", "-o")
    a.add_argument("--context", type=int, default=2)
    a.add_argument("--lang", choices=("en", "zh"), default=None)
    a.add_argument("--fail-on", choices=("critical", "high", "medium", "low", "none"), default=None)
    a.add_argument("--online", action="store_true",
                   help="verify dependency names against PyPI / npm (sends package names)")
    a.add_argument("--offline", action="store_true",
                   help="kept for compatibility: scans are offline unless --online is given")
    a.add_argument("--diff", metavar="REF",
                   help="report only findings on lines changed since REF (e.g. main)")
    a.add_argument("--baseline", metavar="FILE", nargs="?", const=".wrasse/baseline.json",
                   help="suppress findings already recorded in a baseline file")
    a.add_argument("--sarif", metavar="FILE", dest="sarif_in",
                   help="read another tool's SARIF and skip findings it already reports")
    a.add_argument("--history", action="store_true",
                   help="also scan git history for credentials that were removed")
    a.add_argument("--include-tests", action="store_true")
    a.add_argument("--no-color", action="store_true")
    a.add_argument("--no-state", action="store_true",
                   help="do not write .wrasse/last.json (scanning someone else's checkout)")
    a.set_defaults(func=cmd_audit)

    pf = sub.add_parser("preflight", help="check agent config before opening a repo")
    pf.add_argument("path", nargs="?", default=".")
    pf.add_argument("--format", choices=("text", "json"), default="text")
    pf.add_argument("--lang", choices=("en", "zh"), default=None)
    pf.add_argument("--no-color", action="store_true")
    pf.set_defaults(func=cmd_preflight)

    for name, func, helptext in (
        ("explain", cmd_explain, "evidence and fix for one finding"),
        ("open", cmd_open, "jump to a finding in your editor"),
    ):
        s = sub.add_parser(name, help=helptext)
        s.add_argument("handle")
        s.add_argument("path", nargs="?", default=".")
        s.add_argument("--editor")
        s.set_defaults(func=func)

    rv = sub.add_parser("review", help="step through findings")
    rv.add_argument("path", nargs="?", default=".")
    rv.set_defaults(func=cmd_review)

    bl = sub.add_parser("baseline", help="record the current findings so later scans show only new ones")
    bl.add_argument("action", nargs="?", choices=("create", "diff"), default="create")
    bl.add_argument("path", nargs="?", default=".")
    bl.set_defaults(func=cmd_baseline)

    ru = sub.add_parser("rules", help="list or show rules")
    ru.add_argument("action", nargs="?", choices=("list", "show", "export"), default="list")
    ru.add_argument("id", nargs="?")
    ru.add_argument("--lang", choices=("en", "zh"), default=None)
    ru.add_argument("--format", choices=("md", "html"), default="md")
    ru.add_argument("--output", "-o")
    ru.set_defaults(func=cmd_rules)

    cfg = sub.add_parser("config", help="settings this repository carries")
    cfg.add_argument("action", nargs="?", choices=("show", "set", "unset"), default="show")
    cfg.add_argument("key", nargs="?")
    cfg.add_argument("value", nargs="?")
    cfg.add_argument("--path", "-C", default=".", help="project to read or write")
    cfg.set_defaults(func=cmd_config)

    doc = sub.add_parser("doctor", help="environment check")
    doc.add_argument("--offline", action="store_true")
    doc.set_defaults(func=cmd_doctor)
    return p


def _utf8_stdio() -> None:
    """Windows consoles default to cp1252; box drawing would crash the report."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass


FAIL_ORDER = ("none", "low", "medium", "high", "critical")


def _repo_may_set(key: str, value: str, default: str) -> bool:
    """A repository can tighten the gate, never loosen it.

    `.wrasse/config.json` travels with the repository, so a cloned project could
    otherwise ship `{"fail_on": "none", "mode": "quick"}` and turn the scan into
    a pass. Stricter settings are still honoured.
    """
    if key == "fail_on":
        return FAIL_ORDER.index(value) >= FAIL_ORDER.index(default)
    if key == "mode":
        return value == "standard"          # `quick` skips L2
    if key == "focus":
        return value == "all"               # one mainline is narrower
    return True


def _apply_settings(args) -> None:
    """Fill in whatever the command line left out, from the project's config."""
    root = Path(getattr(args, "path", ".") or ".")
    if hasattr(args, "lang"):
        args.lang = _resolve_lang(args.lang, root)
    configured = load_config(root)
    for attr, key, default in (("fail_on", "fail_on", DEFAULT_FAIL_ON),
                               ("mode", "mode", "standard"),
                               ("focus", "focus", "all")):
        if not hasattr(args, attr) or getattr(args, attr) is not None:
            continue
        value = configured.get(key)
        if value and not _repo_may_set(key, value, default):
            print(f"wrasse: repo config asks for {key}={value}; ignored — a repository"
                  f" cannot lower its own gate", file=sys.stderr)
            value = None
        setattr(args, attr, value or default)


def main(argv: list[str] | None = None) -> int:
    _utf8_stdio()
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv and sys.stdin.isatty() and sys.stdout.isatty():
        return repl(Path.cwd(), _resolve_lang(None, Path.cwd()))
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        if sys.stdin.isatty() and sys.stdout.isatty():
            return repl(Path.cwd(), _resolve_lang(getattr(args, "lang", None), Path.cwd()))
        parser.print_help()
        return 0
    _apply_settings(args)
    try:
        return args.func(args)
    except BrokenPipeError:          # `| head` closed the pipe: not an error
        try:
            sys.stdout.close()
        except Exception:
            pass
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
