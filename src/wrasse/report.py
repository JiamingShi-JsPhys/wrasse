"""Reporters — text (humans), json (machines), sarif (CI), html (sharing)."""

from __future__ import annotations

import html as _html
import json
import shutil
import sys
from pathlib import Path

from . import __version__
from .core import (SEVERITY_LABEL, SEVERITY_RANK, Finding, Mainline, ProjectIndex, Severity, Status,
                   line_at, mask_text)

CSI = "\033["

# C0, DEL, and C1 — U+009B is an 8-bit CSI on many terminals, so leaving the
# C1 block in place would defeat this filter on its own promise.
_BAD_BYTES = {c: None for c in list(range(0, 9)) + [11, 12] + list(range(14, 32))
              + [127] + list(range(0x80, 0xA0))}
# Line and paragraph separators break a line without a newline byte; the
# zero-width and bidi characters can carry text a reviewer never sees.
_ONE_LINE_EXTRA = {0x2028: " ", 0x2029: " "}
for _code in list(range(0x200B, 0x2010)) + list(range(0x202A, 0x202F)) + [0x2060, 0xFEFF]:
    _ONE_LINE_EXTRA[_code] = None


def clean(text: str) -> str:
    """A repository must not be able to repaint the terminal or forge the report."""
    return text.translate(_BAD_BYTES)


def one_line(text: str) -> str:
    """For a field printed on one line: nothing may start a forged entry."""
    return (clean(text).replace(chr(10), " ").replace(chr(13), " ").replace(chr(9), " ")
            .translate(_ONE_LINE_EXTRA))


class C:
    def __init__(self, enabled: bool):
        self.on = enabled

    def __call__(self, code: str, text: str) -> str:
        return f"{CSI}{code}m{text}{CSI}0m" if self.on else text


LABELS = {
    "en": {"why": "why", "next": "next", "findings": "findings", "context": "context",
           "files": "files", "file_one": "file", "none": "no findings", "finding_one": "finding", "open": "wrasse explain", "review": "wrasse review",
           "checked": "checked", "not_covered": "not covered",
           "checked_hint": "hard-coded keys · frontend variables · log fields · error text · upload paths · agent config",
           "runtime_hint": "runtime behaviour — whether a value is actually logged or sent"},
    "zh": {"why": "原因", "next": "下一步", "findings": "条", "context": "上下文",
           "files": "个文件", "file_one": "个文件", "none": "没有发现问题", "finding_one": "条", "open": "wrasse explain", "review": "wrasse review",
           "checked": "已检查", "not_covered": "未覆盖",
           "checked_hint": "硬编码密钥 · 前端变量 · 日志字段 · 错误信息 · 上传路径 · Agent 配置",
           "runtime_hint": "运行时行为——值是否真的被写进日志或发出"},
}

MISSING = {
    "authz/query-without-owner": {"en": "no owner or tenant constraint appears in this function",
                                  "zh": "本函数内未见 owner/tenant 约束"},
    "deps/typosquat": {"en": "confirm the intended package name before installing",
                       "zh": "安装前需确认原定的包名"},
    "deps/version-not-found": {"en": "the version is absent from PyPI",
                               "zh": "该版本在 PyPI 上不存在"},
    "input/untyped-body": {"en": "the request body has no Pydantic model",
                           "zh": "请求体没有对应的 Pydantic 模型"},
    "code/ssrf": {"en": "no host allowlist is visible here", "zh": "此处未见主机白名单"},
    "log/sensitive-field": {"en": "the value is written without masking", "zh": "该值未经脱敏即写出"},
    "response/model-leaks-secret": {"en": "the field is part of the response schema",
                                    "zh": "该字段属于响应模型"},
    "authz/mass-assignment": {"en": "the sender of this body controls this field",
                              "zh": "提交该请求体者可设置此字段"},
    "net/request-without-timeout": {"en": "a session-level default may already set one",
                                    "zh": "会话级默认值可能已设置超时"},
    "log/injection": {"en": "a newline in this value produces a second entry",
                      "zh": "该值中的换行可产生第二条记录"},
    "deps/new-package": {"en": "recent publication alone is not malicious; verify the maintainer",
                         "zh": "近期发布本身不等于恶意，需核实维护者"},
    "code/nosql-injection": {"en": "an upstream operator allowlist would preclude this",
                             "zh": "上游若限制操作符白名单，则不受影响"},
    "authz/admin-route-unprotected": {"en": "a role check may exist inside the handler",
                                      "zh": "角色校验可能位于函数体内"},
    "api/unbounded-query": {"en": "a limit may be applied in the service layer",
                            "zh": "上限可能施加于 service 层"},
    "config/api-docs-public": {"en": "acceptable on an internal-only deployment",
                               "zh": "仅内网部署时可接受"},
    "code/fail-open": {"en": "unless the caller validates the result again",
                       "zh": "除非调用方再次校验结果"},
}

# A green line is not always a patch: `+` is, `~` is a shape to adapt, `!` means
# no automatic fix is offered.
FIX_MARKS = {"verified": ("+", "38;5;71"), "template": ("~", "38;5;178"),
             "manual": ("!", "38;5;203")}

SEV_COLOR = {Severity.CRITICAL: "38;5;203", Severity.HIGH: "38;5;208",
             Severity.MEDIUM: "38;5;178", Severity.LOW: "38;5;75"}
DIM, PATH_C, RULE_C, DEL_BG, ADD_BG = "38;5;244", "38;5;245", "38;5;244", "48;5;52", "48;5;22"


def display_command(verb: str, path: str, width: int) -> str:
    """Keep the echo on one line without mangling paths that contain spaces."""
    text = f"{verb} {path}"
    if len(text) <= width:
        return text
    name = Path(path.rstrip("/\\")).name or "."
    return f"{verb} …/{name}"


def _marks() -> tuple[str, str, str]:
    """Commentary gutters. Falls back to ASCII when the console cannot print them."""
    try:
        "│└→".encode(sys.stdout.encoding or "utf-8")
        return "│", "└", "→"
    except (UnicodeEncodeError, LookupError):
        return "|", "`", "->"


def term_width() -> int:
    """Follow the terminal instead of assuming a width — a fixed 88 wraps on 80."""
    try:
        cols = shutil.get_terminal_size().columns
    except OSError:
        cols = 88
    return max(58, min(cols, 100))


def _dots(left: str, right: str, width: int) -> str:
    fill = width - len(left) - len(right) - 2
    if fill < 3:
        return " · "
    return " " + "." * fill + " "


def render_text(findings: list[Finding], index: ProjectIndex | None, *, lang: str = "en",
                context: int = 2, color: bool = True, command: str = "wrasse audit .",
                mode: str = "standard", elapsed: float = 0.0, files: int = 0,
                unknown: list[str] | None = None, ordinals: dict | None = None) -> str:
    c = C(color)
    L = LABELS.get(lang, LABELS["en"])
    labels = SEVERITY_LABEL.get(lang, SEVERITY_LABEL["en"])
    width = term_width()
    out: list[str] = []

    file_label = L["files"] if files != 1 else L["file_one"]
    finding_label = L["findings"] if len(findings) != 1 else L["finding_one"]
    head = f"{command}   {mode} · {files} {file_label} · {L['context']} {context} · {elapsed:.1f}s"
    out.append(c(DIM, head))
    out.append("")

    if not findings:
        out.append("  " + c("38;5;71;1", "● " + L["none"]))
        out.append("")
        out.append("  " + c(DIM, L["checked"] + "  ") + c("38;5;250", L["checked_hint"]))
        out.append("  " + c(DIM, L["not_covered"] + "  ") + c("38;5;250", L["runtime_hint"]))
        out.append("")
        out.append("  " + c(DIM, L["next"] + "  ") + command + " --format html -o report.html")
        return chr(10).join(out) + chr(10)

    counts: dict[Severity, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    parts = [c(SEV_COLOR[s] + ";1", f"{counts[s]} {labels[s].lower()}") for s in sorted(counts, key=SEVERITY_RANK.__getitem__)]
    out.append("  " + "   ".join(parts) + "   " + c(DIM, f"· {len(findings)} {finding_label}"))
    out.append("")

    ordered = sorted(findings, key=lambda f: f.rank)
    groups: dict[str, list[tuple[int, Finding]]] = {}
    for i, f in enumerate(ordered, 1):
        number = (ordinals or {}).get(f.id, i)
        groups.setdefault(f.file, []).append((number, f))

    for path, items in groups.items():
        tail = f" {len(items)}"
        fill = max(3, width - len(path) - len(tail) - 3)
        out.append("  " + c(PATH_C + ";1", clean(path)) + c(DIM, " " + "─" * fill + tail))
        out.append("")
        for number, f in items:
            out.extend(_entry(c, index, f, number, lang, labels, L, context, width))
            out.append("")

    out.append(c(DIM, "─" * width))
    out.append("  " + c(DIM, L["next"] + "  ") + c(DIM, f"{L['review']} step through")
               + c(DIM, "   ·   ") + c("38;5;71", "wrasse") + c(DIM, " to stay in a session   ·   --format html"))
    if unknown:
        out.append("  " + c("38;5;178", f"unknown: {len(unknown)} package(s) could not be checked (offline?)") )
    return "\n".join(out) + "\n"


def _entry(c: C, index, f: Finding, number: int, lang: str, labels, L, context: int, width: int) -> list[str]:
    lines: list[str] = []
    gutter = "    "
    sev = labels[f.severity]
    badge = c(SEV_COLOR[f.severity] + ";1", f"● {sev}")
    mark_plain = "?" if f.status == Status.NEEDS_REVIEW else " "
    mark = c("38;5;178", "?") if f.status == Status.NEEDS_REVIEW else " "
    rule = c(RULE_C, f.rule)
    pos = c(PATH_C, clean(f"{f.line}:{f.column}"))
    left = f"{sev} {mark_plain} {f.rule}"
    lines.append(f"{gutter}{badge} {mark} {rule}" + c(DIM, _dots(left, f"{f.line}:{f.column}", width - 4))
                 + pos)

    before, after = _context(index, f, context)
    for ln, text in before:
        lines.append(f"{gutter}  {str(ln).rjust(3)}  " + c(DIM, clean(text)))
    # red / green, indent printed outside the colour range
    num = str(f.line).rjust(3)
    for bad in f.minus:
        lines.append(gutter + c("38;5;203", "-") + f" {num}  " + c(f"{DEL_BG};38;5;217", f" {clean(bad)}"))
    add_mark, add_colour = FIX_MARKS.get(f.fix_kind, FIX_MARKS["template"])
    for good in f.plus:
        lines.append(gutter + c(add_colour, add_mark) + f" {num}  "
                     + c(f"{ADD_BG};38;5;150", f" {clean(good)}"))
    for ln, text in after:
        lines.append(f"{gutter}  {str(ln).rjust(3)}  " + c(DIM, clean(text)))

    bar, tail, arrow = _marks()
    lines.append(f"{gutter}{c('38;5;240', bar)} " + c(DIM, L["why"]) + "  " + c("38;5;250", f.why))
    if f.status == Status.NEEDS_REVIEW:
        note = MISSING.get(f.rule, {}).get(lang) or MISSING.get(f.rule, {}).get("en", "")
        if note:
            lines.append(f"{gutter}{c('38;5;240', bar)} " + c("38;5;178", "?") + "    " + c(DIM, note))
    lines.append(f"{gutter}{c('38;5;240', tail)} " + c(DIM, arrow) + "    " + c(DIM, f"{L['open']} {number}"))
    return lines


def _context(index, f: Finding, span: int = 2):
    if index is None:
        return [], []
    text = index.texts.get(f.file)
    if not text:
        return [], []
    lines = text.splitlines()
    start = max(1, f.line - span)
    end = min(len(lines), f.line + span)
    before = [(i, mask_text(lines[i - 1].rstrip())) for i in range(start, min(f.line, end + 1))]
    after = [(i, mask_text(lines[i - 1].rstrip())) for i in range(f.line + 1, end + 1)]
    return before, after


# ---------------------------------------------------------------- other formats


def render_json(findings: list[Finding], *, files: int, elapsed: float, mode: str,
                unknown: list[str], skipped: tuple[str, ...] = (), complete: bool = True) -> str:
    payload = {
        "tool": "wrasse", "version": __version__, "mode": mode,
        # A consumer that only reads JSON still has to know the scan was partial.
        "scan": {"complete": complete, "skipped": list(skipped)[:64]},
        "summary": {
            "files": files, "elapsed_ms": round(elapsed * 1000, 1), "findings": len(findings),
            "by_severity": {s.value: sum(1 for f in findings if f.severity == s) for s in Severity},
            "unknown": unknown,
        },
        "findings": [f.to_dict() for f in sorted(findings, key=lambda x: x.rank)],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


def render_sarif(findings: list[Finding], *, tool_version: str = __version__,
                 skipped: tuple[str, ...] = (), complete: bool = True) -> str:
    rules = {}
    for f in findings:
        rules.setdefault(f.rule, {"id": f.rule, "name": f.title,
                                  "defaultConfiguration": {"level": _sarif_level(f.severity)}})
    results = [{
        "ruleId": f.rule,
        "level": _sarif_level(f.severity),
        "message": {"text": f"{f.title}. {f.why}"},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.file},
                                            "region": {"startLine": f.line, "startColumn": f.column}}}],
        "properties": {"status": f.status.value, "mainline": f.mainline.value,
                       "fix_kind": f.fix_kind},
    } for f in findings]
    invocation: dict = {"executionSuccessful": complete}
    if skipped:
        names = ", ".join(skipped[:10])
        invocation["toolExecutionNotifications"] = [{
            "level": "warning",
            "message": {"text": f"{len(skipped)} file(s) were not scanned: {names}"},
        }]
    doc = {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
           "runs": [{"tool": {"driver": {"name": "wrasse", "version": tool_version,
                                          "rules": list(rules.values())}},
                     "invocations": [invocation],
                     "results": results}]}
    return json.dumps(doc, ensure_ascii=False, indent=2)


def _sarif_level(sev: Severity) -> str:
    return {Severity.CRITICAL: "error", Severity.HIGH: "error", Severity.MEDIUM: "warning", Severity.LOW: "note"}[sev]


def render_html(findings: list[Finding], *, root: Path | None = None, lang: str = "en",
                index: ProjectIndex | None = None, context: int = 2,
                skipped: tuple[str, ...] = (), complete: bool = True) -> str:
    """Same block as the terminal, in a page: line numbers, red/green, `│ why`, `└ →`."""
    labels = SEVERITY_LABEL.get(lang, SEVERITY_LABEL["en"])
    sev_class = {Severity.CRITICAL: "crit", Severity.HIGH: "high",
                 Severity.MEDIUM: "med", Severity.LOW: "low"}
    blocks = []
    for n, f in enumerate(sorted(findings, key=lambda x: x.rank), 1):
        # The report is a file people share. An absolute `vscode://` href would
        # write the author's home directory into every row — the very leak this
        # tool reports. Resolve it in the browser, from the report's own path.
        rel = f.file.replace(chr(92), "/")
        link = (f'data-file="{_html.escape(rel)}" data-line="{f.line}" '
                f'data-col="{f.column}"')
        before, after = _context(index, f, context)
        code = []
        for ln, text in before:
            code.append(f'<span class="ln">{ln:>4}</span>  <span class="dim">{_html.escape(clean(text))}</span>')
        for bad in f.minus:
            code.append(f'<span class="mk del-mk">-</span><span class="ln">{f.line:>4}</span>  '
                        f'<span class="del"> {_html.escape(clean(bad))}</span>')
        html_mark = {"verified": "+", "template": "~", "manual": "!"}.get(f.fix_kind, "~")
        for good in f.plus:
            code.append(f'<span class="mk add-mk">{html_mark}</span><span class="ln">{f.line:>4}</span>  '
                        f'<span class="add"> {_html.escape(clean(good))}</span>')
        for ln, text in after:
            code.append(f'<span class="ln">{ln:>4}</span>  <span class="dim">{_html.escape(clean(text))}</span>')
        note = ""
        if f.status == Status.NEEDS_REVIEW:
            why_missing = MISSING.get(f.rule, {}).get(lang) or MISSING.get(f.rule, {}).get("en", "")
            if why_missing:
                note = (f'<div class="note"><span class="bar">│</span> <span class="q">?</span>    '
                        f'<span class="dim">{_html.escape(why_missing)}</span></div>')
        blocks.append(f"""
  <section class="entry">
    <div class="head"><span class="dot {sev_class[f.severity]}">●</span>
      <span class="sev {sev_class[f.severity]}">{_html.escape(labels[f.severity])}</span>
      {('<span class="q">?</span>' if f.status == Status.NEEDS_REVIEW else '')}
      <span class="rule">{_html.escape(f.rule)}</span>
      <a class="pos" href="#" {link}>{f.line}:{f.column}</a></div>
    <pre>{chr(10).join(code)}</pre>
    <div class="note"><span class="bar">│</span> <span class="dim">why</span>  <span class="why">{_html.escape(f.why)}</span></div>
    {note}
    <div class="note"><span class="bar">└</span> <span class="dim">→</span>    wrasse explain {n}</div>
  </section>""")
    banner = ""
    if not complete:
        names = ", ".join(_html.escape(clean(s)) for s in skipped[:3])
        more = "" if len(skipped) <= 3 else " …"
        detail = f" ({names}{more})" if skipped else ""
        banner = (f'<p class="warn">⚠ {len(skipped)} file(s) were not scanned{detail} '
                  f'— this report covers part of the project</p>')
    return f"""<!doctype html><html lang="{lang}"><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>wrasse report</title>
<style>
 body{{margin:0;background:#0b0f14;color:#c9d1d9;padding:40px 24px 100px;
      font:13px/1.7 ui-monospace,SFMono-Regular,Consolas,monospace}}
 main{{max-width:900px;margin:0 auto}}
 h1{{font:600 16px/1.4 -apple-system,"Segoe UI","PingFang SC",sans-serif;color:#e6edf3;margin:0 0 4px}}
 .lede{{color:#6e7681;margin:0 0 28px;font-family:-apple-system,"Segoe UI","PingFang SC",sans-serif}}
 .entry{{border:1px solid #1e2733;border-radius:8px;background:#0d1219;padding:14px 16px;margin:0 0 16px}}
 .head{{display:flex;gap:10px;align-items:baseline;margin-bottom:8px}}
 .dot{{font-size:12px}} .sev{{font-weight:600;font-size:12px;letter-spacing:.04em}}
 .crit{{color:#f85149}} .high{{color:#f0883e}} .med{{color:#d29922}} .low{{color:#58a6ff}}
 .q{{color:#d29922;font-weight:700}}
 .rule{{color:#6e7681;font-size:12px}} .pos{{margin-left:auto;color:#8b949e;text-decoration:none;font-size:12px}}
 .pos:hover{{text-decoration:underline}}
 pre{{margin:0;padding:0;white-space:pre-wrap;font:inherit}}
 .ln{{color:#4b5563}} .dim{{color:#7d8590}} .mk{{display:inline-block;width:1ch}}
 .del-mk{{color:#f85149}} .add-mk{{color:#3fb950}}
 .del{{color:#ffa198;background:#3d1d1d}} .add{{color:#7ee787;background:#12301f}}
 .note{{margin-top:6px;color:#6e7681}} .bar{{color:#30363d}} .why{{color:#9aa4af}}
 .warn{{color:#d29922;border:1px solid #3d2f0b;background:#1c1608;border-radius:6px;
        padding:8px 12px;margin:0 0 20px;font-family:-apple-system,"Segoe UI","PingFang SC",sans-serif}}
</style>
<main>
<h1>wrasse report</h1>
<p class="lede">{_html.escape(root.name) + " · " if root else ""}{len(findings)} finding(s) · same layout as the terminal</p>
{banner}
{''.join(blocks)}
<script>
document.querySelectorAll('a.pos').forEach(function (a) {{
  a.addEventListener('click', function (e) {{
    e.preventDefault();
    var rel = new URL(a.dataset.file, location.href).pathname.replace(/^[/]/, '');
    location.href = 'vscode://file/' + rel + ':' + a.dataset.line + ':' + a.dataset.col;
  }});
}});
</script>
</main></html>"""
