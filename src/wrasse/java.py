"""Optional Java / Spring analysis.

Parsing Java needs a grammar, not a JDK: nothing here compiles or runs the code.
`javalang` is a pure-Python parser, installed with `pip install wrasse[java]`
(it lands wherever Python lives — on this machine, D:\\mamba). Without it these
rules do not run and `wrasse doctor` says so: a regex that matches three
literals would look like coverage without being it.
"""

from __future__ import annotations

from .core import Evidence, Finding, ProjectIndex, line_at, mask_text
from .rules import RULES

try:                                             # optional dependency
    from javalang import tree as jtree
    from javalang.parse import parse as jparse
    AVAILABLE = True
except Exception:                                # pragma: no cover
    jtree = None                                 # type: ignore[assignment]
    jparse = None                                # type: ignore[assignment]
    AVAILABLE = False


def _finding(rule_id: str, index: ProjectIndex, path: str, line: int, lang: str,
             snippet: str, kind: str = "code") -> Finding:
    snippet = mask_text(snippet)                 # same invariant as every other emitter
    rule = RULES[rule_id]
    meta = rule.t(lang)
    return Finding(
        rule=rule.id, title=meta["title"], mainline=rule.mainline,
        severity=rule.severity, status=rule.status,
        file=path, line=line, column=1, why=meta["why"],
        minus=[snippet], plus=[meta["plus"]],
        prompt=meta["prompt"].replace("{{file}}", path).replace("{{line}}", str(line))
                              .replace("{{snippet}}", snippet.strip()),
        evidence=[Evidence(kind, path, line, snippet.strip())],
    ).finalize()


def _strings(annotation) -> list[str]:
    """Every string literal inside an annotation, e.g. `origins = "*"`."""
    element = getattr(annotation, "element", None)
    if element is None:
        return []
    values = element if isinstance(element, list) else [element]
    found: list[str] = []
    for value in values:
        inner = getattr(value, "value", value)
        text = getattr(inner, "value", "")
        if isinstance(text, str):
            found.append(text.strip(chr(34) + chr(39)))   # javalang keeps the quotes
    return found


def scan(index: ProjectIndex, lang: str = "en") -> tuple[list[Finding], list[str]]:
    """Findings plus the Java files that could not be parsed."""
    if not AVAILABLE or jtree is None or jparse is None:
        return [], []
    out: list[Finding] = []
    unparsed: list[str] = []
    for path, text in index.texts.items():
        if not path.endswith(".java"):
            continue
        try:
            tree = jparse(text)
        except Exception:                        # a file that does not parse proves nothing
            unparsed.append(path)                # ... and the scan has to say so
            continue

        for _, node in tree.filter(jtree.Annotation):
            if getattr(node, "name", "") != "CrossOrigin":
                continue
            values = _strings(node)
            # Bare @CrossOrigin defaults to every origin; `origins = "*"` says so.
            if not values or "*" in values:
                line = getattr(node.position, "line", 1)
                out.append(_finding("spring/cors-wildcard", index, path, line, lang,
                                    line_at(text, line).strip(), "annotation"))

        for _, node in tree.filter(jtree.MethodInvocation):
            member = getattr(node, "member", "")
            if member not in ("permitAll", "disable"):
                continue
            line = getattr(node.position, "line", 1)
            if member == "disable":
                # javalang drops the chain, so read a small window of lines:
                # `.csrf()` and `.disable()` are usually written on two.
                window = "\n".join(line_at(text, n).lower()
                                    for n in range(max(1, line - 2), line + 1))
                if "csrf" not in window:
                    continue
            rule_id = "spring/permit-all" if member == "permitAll" else "spring/csrf-disabled"
            out.append(_finding(rule_id, index, path, line, lang, line_at(text, line).strip()))
    return out, unparsed
