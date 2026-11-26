# Security policy

wrasse is a security tool, so it is held to the same standard it applies to others.

## Reporting a vulnerability

Open a private security advisory on GitHub, or email the maintainer listed in
`pyproject.toml`. Please do not open a public issue first.

Include: affected version (`wrasse --version`), a minimal reproduction, and what
the tool did instead of what it should have done.

## Scope

In scope:

- wrasse executing, importing, or installing code from the project it scans
- wrasse writing files outside `./.wrasse/` and the requested output path
- a secret appearing unmasked in any output (terminal, JSON, SARIF, HTML, state file)
- network access that is not the PyPI lookup, or that happens despite `--offline`
- a rule that crashes the scanner on ordinary input

Out of scope:

- findings wrasse misses (that is a detection gap, not a vulnerability — open an issue)
- false positives
- anything requiring the attacker to already control the scanned project

## Guarantees wrasse makes about itself

| Guarantee | How it is enforced |
|---|---|
| Never imports or runs the scanned project | `core.py` / `facts.py` / `structure.py` contain no `import` of project code; only `ast.parse` |
| Never calls a model | `tests/test_wrasse.py::BoundaryTests` asserts no model/HTTP import in the detection layer |
| Never sends a secret | every `secret/*` finding is masked before it reaches any renderer; a test asserts the raw value is absent from text + JSON |
| Offline by default for scans | `--offline` skips the registry lookups (PyPI / npm existence checks) |
| Reads only regular files inside the project | `core.safe_read` refuses symlinks and anything resolving outside the root |
| Writes state only inside the project | `cli.save_state` refuses a symlinked `.wrasse`/`last.json` and replaces the file atomically |
| A repository cannot repaint the terminal | `report.clean` strips control bytes from every scanned line before printing |
| No stray control bytes in our own regexes | `SourceHygieneTests` fails the build if a source file contains one |

## Supported versions

Only the latest release receives fixes.
