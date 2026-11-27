"""Dependency facts — typosquatting offline, existence/version against PyPI when online."""

from __future__ import annotations

import datetime
import json
import re
import urllib.error
import urllib.request

from .core import Finding, ProjectIndex
from .facts import _emit

POPULAR = (
    "requests", "flask", "django", "fastapi", "pydantic", "sqlalchemy", "numpy", "pandas",
    "pytest", "httpx", "click", "typer", "rich", "jinja2", "celery", "redis", "boto3",
    "uvicorn", "starlette", "alembic", "asyncpg", "psycopg2", "pyyaml", "python-dotenv",
    "beautifulsoup4", "scrapy", "pillow", "openai", "anthropic", "langchain", "transformers",
)
NPM_POPULAR = (
    "react", "react-dom", "next", "vue", "express", "lodash", "axios", "typescript",
    "webpack", "eslint", "prettier", "jest", "zod", "tailwindcss", "prisma", "mongoose",
    "socket.io", "dotenv", "chalk", "commander", "vitest", "vite", "esbuild", "swr",
)
TIMEOUT = 6.0


def _distance(a: str, b: str) -> int:
    if abs(len(a) - len(b)) > 1:
        return 2
    row = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        prev, row[0] = row[0], i
        for j, cb in enumerate(b, 1):
            old = row[j]
            row[j] = min(row[j] + 1, row[j - 1] + 1, prev + (ca != cb))
            prev = old
    return row[-1]


def _npm(name: str) -> dict | None:
    try:
        with urllib.request.urlopen(f"https://registry.npmjs.org/{name}", timeout=TIMEOUT) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return None if exc.code == 404 else {"__error__": str(exc)}
    except Exception as exc:
        return {"__error__": str(exc)}


def _pypi(name: str) -> dict | None:
    """Return release metadata, or None when the package is not on PyPI."""
    try:
        with urllib.request.urlopen(f"https://pypi.org/pypi/{name}/json", timeout=TIMEOUT) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return None if exc.code == 404 else {"__error__": str(exc)}
    except Exception as exc:  # network down, DNS, TLS — never guess
        return {"__error__": str(exc)}


NEW_PACKAGE_DAYS = 90


def _epoch(raw: str) -> float | None:
    text = (raw or "").strip().replace("Z", "+00:00")
    try:
        stamp = datetime.datetime.fromisoformat(text)
    except ValueError:
        return None
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=datetime.timezone.utc)
    return stamp.timestamp()


def _first_publish(meta: dict, ecosystem: str) -> float | None:
    """When the package first appeared — not its latest release.

    Slopsquatting registers a name nobody wanted before; a long-lived package
    that shipped yesterday is not the same signal.
    """
    stamps: list[float] = []
    if ecosystem == "npm":
        stamps = [s for s in (_epoch(((meta.get("time") or {}).get("created") or "")),) if s]
    else:
        for files in (meta.get("releases") or {}).values():
            for item in files or []:
                for key in ("upload_time_iso_8601", "upload_time"):
                    stamp = _epoch(item.get(key) or "")
                    if stamp:
                        stamps.append(stamp)
                        break
    return min(stamps) if stamps else None


def scan(index: ProjectIndex, lang: str = "en", offline: bool = True) -> tuple[list[Finding], list[str]]:
    """Return findings plus a list of packages whose state could not be determined."""
    out: list[Finding] = []
    unknown: list[str] = []
    cache: dict[str, dict | None] = {}
    for dep in index.deps:
        name = dep.name.lower().replace("_", "-")
        popular = NPM_POPULAR if dep.ecosystem == "npm" else POPULAR
        near = [p for p in popular if p != name and _distance(name, p) == 1]
        if near:
            out.append(_emit("deps/typosquat", index, dep.file, dep.line, lang=lang,
                             minus=[f"{dep.name}{dep.spec}"], plus=[near[0]],
                             name=dep.name, spec=dep.spec))
        if offline:
            unknown.append(dep.name)
            continue
        key = f"{dep.ecosystem}:{name}"
        if key not in cache:
            cache[key] = _npm(name) if dep.ecosystem == "npm" else _pypi(name)
        meta = cache[key]
        if meta is None:
            out.append(_emit("deps/package-not-found", index, dep.file, dep.line, lang=lang,
                             minus=[f"{dep.name}{dep.spec}"],
                             plus=[f"# {dep.name} not found on {dep.ecosystem}"],
                             name=dep.name, spec=dep.spec))
            continue
        if "__error__" in meta:
            unknown.append(dep.name)
            continue
        first = _first_publish(meta, dep.ecosystem)
        if first is not None:
            age_days = (datetime.datetime.now(datetime.timezone.utc).timestamp() - first) / 86400
            if age_days < NEW_PACKAGE_DAYS:
                out.append(_emit("deps/new-package", index, dep.file, dep.line, lang=lang,
                                 minus=[f"{dep.name}{dep.spec}"],
                                 plus=[f"# {dep.name} first appeared {int(age_days)} day(s) ago"],
                                 name=dep.name, spec=dep.spec))
        spec = dep.spec.strip()
        exact = re.match(r"^==\s*([0-9][0-9A-Za-z.+\-]*)$", spec)
        releases = (meta.get("releases") or {}) if dep.ecosystem == "pypi" else (meta.get("versions") or {})
        # Ranges (>=, ~=, ^, commas) need a PEP 440 resolver; guessing here would
        # report every legitimate range as a missing version.
        if exact and exact.group(1) not in releases:
            out.append(_emit("deps/version-not-found", index, dep.file, dep.line, lang=lang,
                             minus=[f"{dep.name}{dep.spec}"], plus=[dep.name],
                             name=dep.name, spec=dep.spec))
    return out, unknown
