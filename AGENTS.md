# Notes for agents

wrasse is a local security scanner. It is deterministic: a rule fires or it does not, and the same input always produces the same finding id. Preserve that when you drive it.

## Calling it

```bash
wrasse preflight .                       # config only, executes nothing
wrasse audit . --format json             # machine-readable, one object
wrasse audit . --fail-on high            # exit 2 means the gate failed
wrasse explain 3                         # evidence for one finding
```

Read `--format json`. It has a stable shape: `summary`, then `findings[]` with `id`, `rule`, `severity`, `status`, `file`, `line`, `why`, `fix.minus`, `fix.plus`, `evidence`.

## Rules for relaying results

- **Quote findings; do not summarise them away.** A `critical` finding does not become "a small issue" because the rest looked fine.
- **Report the exit code as it is.** `4` means the scan did not finish. It is not a pass, and it is not "no problems found".
- **A `needs_review` finding is not a confirmed bug.** Say so, with the reason the tool gave.
- **Never edit code to satisfy a finding** unless the user asked for a fix. Emit the `fix.plus` line and let them decide.
- **Never run `--online`** without asking; it sends dependency names to PyPI or npm.

## Where things are

| Path | Holds |
|---|---|
| `src/wrasse/rules.py` | every rule: id, severity, bilingual title/why/fix, preset prompt |
| `src/wrasse/facts.py` | line-level detectors (L1) |
| `src/wrasse/structure.py` | AST detectors (L2): data flow, structural authorization |
| `src/wrasse/core.py` | project index, route extraction, masking, safe file reads |
| `tests/corpus/` | 53 planted rule/file pairs (62 findings) that must all be found, 16 secure samples that must stay clean |

To add a rule, follow [CONTRIBUTING.md](CONTRIBUTING.md): a rule needs a detector, a corpus sample and an entry in `EXPECTED`. `test_precision_on_secure_corpus` is what will catch a rule that fires on the fixed version of the code.
