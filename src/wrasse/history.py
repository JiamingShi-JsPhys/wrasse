"""Git history — credentials that were committed and deleted again.

Deleting the line in HEAD does not remove it from clones, forks or CI caches, so
this runs `git log -p` and looks at added lines only.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

from .core import Evidence, Finding, Mainline, Severity, Status, mask_text
from .rules import RULES

PROVIDER = re.compile(
    r"\bAKIA[0-9A-Z]{16}\b|\bgh[pousr]_[A-Za-z0-9]{30,}\b|\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b"
    r"|\bsk-ant-[A-Za-z0-9_-]{24,}\b|\bsk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{32,}\b"
    r"|\bAIza[0-9A-Za-z_-]{35}\b|\bxox[baprs]-[A-Za-z0-9-]{20,}\b")
HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")
COMMIT = re.compile(r"^commit ([0-9a-f]{7,40})")


def _finding(path: str, line: int, snippet: str, commit: str, lang: str) -> Finding:
    rule = RULES["secret/in-git-history"]
    meta = rule.t(lang)
    masked = mask_text(snippet)
    prompt = (meta["prompt"].replace("{{file}}", path).replace("{{line}}", str(line))
              .replace("{{snippet}}", masked).replace("{{commit}}", commit[:7]))
    return Finding(
        rule=rule.id, title=meta["title"], mainline=Mainline.PRIVACY,
        severity=Severity.CRITICAL, status=Status.CONFIRMED,
        file=path, line=line, column=1, why=meta["why"],
        minus=[masked], plus=[meta["plus"].replace("{{commit}}", commit[:7])],
        prompt=prompt,
        evidence=[Evidence("commit", path, line, masked, note=commit[:7])],
    ).finalize()


def scan(root: Path, lang: str = "en", limit: int = 800) -> list[Finding]:
    """Credential-looking additions in the last `limit` commits."""
    root = root.resolve()
    if not (root / ".git").exists():
        return []
    try:
        proc = subprocess.run(
            ["git", "-C", str(root), "--no-pager", "log", "--no-color", "--unified=0",
             "--no-textconv", "--no-ext-diff", f"-n{limit}", "-p"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=90,
            env={**os.environ, "GIT_PAGER": "cat", "GIT_EXTERNAL_DIFF": ""})
    except (OSError, subprocess.TimeoutExpired):
        return []
    if proc.returncode != 0:
        return []

    out: list[Finding] = []
    commit, path, next_line = "", "", 0
    for raw in proc.stdout.splitlines():
        m = COMMIT.match(raw)
        if m:
            commit = m.group(1)
            continue
        if raw.startswith("+++ "):
            path = raw[6:].strip()
            if path.startswith("b/"):
                path = path[2:]
            next_line = 0
            continue
        m = HUNK.match(raw)
        if m:
            next_line = int(m.group(1))
            continue
        if not raw.startswith("+") or raw.startswith("+++"):
            continue
        body = raw[1:]
        line_no = next_line
        next_line += 1
        if not PROVIDER.search(body):
            continue
        out.append(_finding(path, line_no, body.strip(), commit, lang))
    return out
