"""Generate the rule catalogue from the registry — never hand-maintained."""

from __future__ import annotations

import html as _html

from .core import SEVERITY_LABEL
from .facts import DEFAULT_FIX, _fmt
from .rules import RULES

GROUPS = {
    "privacy": ("A · privacy", "A · 隐私",
                "Will this code leak something?",
                "这段代码会不会把东西漏出去？"),
    "ai": ("B · AI pitfalls", "B · AI 的坑",
           "What did the AI leave out?",
           "AI 少写了什么？"),
}


def _readable(text: str) -> str:
    for token, label in (("{{file}}", "<file>"), ("{{line}}", "<line>"),
                         ("{{snippet}}", "<snippet>"), ("{{commit}}", "<commit>"),
                         ("{{module}}", "<module>"), ("{{count}}", "<count>")):
        text = text.replace(token, label)
    return " ".join(text.split())


def _rule_row(rule, lang: str) -> dict:
    meta = rule.t(lang)
    labels = SEVERITY_LABEL.get(lang, SEVERITY_LABEL["en"])
    return {
        "id": rule.id,
        "severity": labels[rule.severity],
        "status": ("待确认" if lang == "zh" else "needs_review") if rule.status.value == "needs_review"
                  else ("已确认" if lang == "zh" else "confirmed"),
        "raw_status": rule.status.value,
        "mainline_label": ("隐私" if rule.mainline.value == "privacy" else "AI 的坑") if lang == "zh"
                          else rule.mainline.value,
        "title": meta["title"],
        "why": meta["why"],
        "minus": _fmt(meta["minus"], line="<这行代码>" if lang == "zh" else "<the offending line>"),
        "plus": _fmt(meta["plus"], line="<这行代码>" if lang == "zh" else "<the offending line>"),
        "prompt": _readable(meta["prompt"]),
        "mainline": rule.mainline.value,
    }


def _grouped(lang: str) -> list[tuple[tuple[str, str], list[dict]]]:
    out = []
    for key, (en, zh, sub_en, sub_zh) in GROUPS.items():
        rows = [_rule_row(r, lang) for r in RULES.values() if r.mainline.value == key]
        rows.sort(key=lambda r: r["id"])
        out.append(((en if lang == "en" else zh, sub_en if lang == "en" else sub_zh), rows))
    return out


CHROME = {
    "en": {"title": "wrasse rule catalogue",
           "intro": "{n} rules. Generated from `src/wrasse/rules.py` by `wrasse rules export` "
                    "— do not edit by hand.",
           "note": "`needs_review` means the tool reports it but never counts it by `--fail-on`.",
           "prompt": "preset prompt"},
    "zh": {"title": "wrasse 规则清单",
           "intro": "共 {n} 条。由 `wrasse rules export` 从 `src/wrasse/rules.py` 生成，请勿手改。",
           "note": "标 `待确认` 的条目会报出来，但不计入 `--fail-on`。",
           "prompt": "预设提示词"},
}


def render_md(lang: str) -> str:
    chrome = CHROME.get(lang, CHROME["en"])
    lines = [f"# {chrome['title']}", ""]
    lines.append(chrome["intro"].format(n=len(RULES)))
    lines.append("")
    lines.append(chrome["note"])
    lines.append("")
    for (title, subtitle), rows in _grouped(lang):
        lines.append(f"## {title}")
        lines.append("")
        lines.append(f"*{subtitle}*")
        lines.append("")
        for row in rows:
            lines.append(f"### `{row['id']}` — {row['title']}")
            lines.append("")
            lines.append(f"**{row['severity']}** · {row['status']} · {row['mainline_label']}")
            lines.append("")
            lines.append(row["why"])
            lines.append("")
            lines.append("```diff")
            lines.append(f"- {row['minus']}")
            lines.append(f"+ {row['plus']}")
            lines.append("```")
            lines.append("")
            lines.append(f"<sub>{chrome['prompt']}: {row['prompt']}</sub>")
            lines.append("")
    return "\n".join(lines)


def render_html(lang: str) -> str:
    """Same block as the terminal report: badge, red line, green line, │ why, └ →."""
    chrome = CHROME.get(lang, CHROME["en"])
    sev_class = {"CRITICAL": "crit", "HIGH": "high", "MEDIUM": "med", "LOW": "low",
                 "严重": "crit", "高危": "high", "中危": "med", "低危": "low"}
    blocks = []
    for (title, subtitle), rows in _grouped(lang):
        blocks.append(f'<h2>{_html.escape(title)}</h2><p class="sub">{_html.escape(subtitle)}</p>')
        for row in rows:
            flag = '<span class="q">?</span>' if row["raw_status"] == "needs_review" else ""
            cls = sev_class.get(row["severity"], "med")
            blocks.append(f"""
  <section class="entry">
    <div class="head"><span class="dot {cls}">●</span>
      <span class="sev {cls}">{_html.escape(row['severity'])}</span> {flag}
      <span class="rule">{_html.escape(row['id'])}</span></div>
    <pre><span class="mk del-mk">-</span><span class="ln">   1</span>  <span class="del"> {_html.escape(row['minus'])}</span>
<span class="mk add-mk">+</span><span class="ln">   1</span>  <span class="add"> {_html.escape(row['plus'])}</span></pre>
    <div class="note"><span class="bar">│</span> <span class="dim">why</span>  <span class="why">{_html.escape(row['why'])}</span></div>
    <div class="note"><span class="bar">└</span> <span class="dim">→</span>    wrasse rules show {_html.escape(row['id'])}</div>
  </section>""")
    return f"""<!doctype html><html lang="{lang}"><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{chrome['title']}</title>
<style>
 body{{margin:0;background:#0b0f14;color:#c9d1d9;padding:40px 24px 100px;
      font:13px/1.7 ui-monospace,SFMono-Regular,Consolas,monospace}}
 main{{max-width:900px;margin:0 auto}}
 h1{{font:600 16px/1.4 -apple-system,"Segoe UI","PingFang SC",sans-serif;color:#e6edf3;margin:0 0 4px}}
 .lede{{color:#6e7681;margin:0 0 28px;font-family:-apple-system,"Segoe UI","PingFang SC",sans-serif}}
 h2{{font:600 14px/1.4 -apple-system,"Segoe UI","PingFang SC",sans-serif;color:#e6edf3;margin:36px 0 2px}}
 .sub{{color:#6e7681;margin:0 0 14px;font-family:-apple-system,"Segoe UI","PingFang SC",sans-serif}}
 .entry{{border:1px solid #1e2733;border-radius:8px;background:#0d1219;padding:14px 16px;margin:0 0 14px}}
 .head{{display:flex;gap:10px;align-items:baseline;margin-bottom:8px}}
 .dot{{font-size:12px}} .sev{{font-weight:600;font-size:12px;letter-spacing:.04em}}
 .crit{{color:#f85149}} .high{{color:#f0883e}} .med{{color:#d29922}} .low{{color:#58a6ff}}
 .q{{color:#d29922;font-weight:700}} .rule{{color:#6e7681;font-size:12px}}
 pre{{margin:0;padding:0;white-space:pre-wrap;font:inherit}}
 .ln{{color:#4b5563}} .dim{{color:#7d8590}} .mk{{display:inline-block;width:1ch}}
 .del-mk{{color:#f85149}} .add-mk{{color:#3fb950}}
 .del{{color:#ffa198;background:#3d1d1d}} .add{{color:#7ee787;background:#12301f}}
 .note{{margin-top:6px;color:#6e7681}} .bar{{color:#30363d}} .why{{color:#9aa4af}}
</style>
<main>
<h1>{chrome['title']}</h1>
<p class="lede">{chrome['intro'].format(n=len(RULES))}</p>
{''.join(blocks)}
</main></html>"""


def render(fmt: str, lang: str) -> str:
    return render_html(lang) if fmt == "html" else render_md(lang)
