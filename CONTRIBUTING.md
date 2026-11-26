# Contributing

## Run the tests

```bash
python -m unittest discover -s tests -v
```

No third-party test runner. 34 tests, about a second.

## Adding a rule

A rule is six pieces of content plus one detector. All six live in
`src/wrasse/rules.py`; the detector lives in `facts.py` (L1, line/regex level) or
`structure.py` (L2, AST level).

```python
_r("category/name", mainline, severity, status,
   "Title in English", "标题（中文）",
   "Why it matters in English.", "为什么重要（中文）。",
   "{line}", "<the suggested replacement>",
   "Preset prompt in English, with {{file}} {{line}} {{snippet}}.",
   "中文预设提示词。")
```

Then:

1. Add a vulnerable sample under `tests/corpus/vulnerable/`.
2. Add the rule to `EXPECTED` in `tests/test_wrasse.py`.
3. Add a secure sample under `tests/corpus/secure/` that must stay clean — the
   most common regression is a rule that fires on the *fixed* version of the code.
4. Run the tests. `test_precision_on_secure_corpus` is the one that will catch you.

## Rule standards

- **`fix` must be pasteable.** Not "add a check" — the actual line. If we cannot
  give a correct generic fix, the fix line is `# manual review required — …`.
- **`needs_review` when we cannot see the whole picture.** Anything that depends
  on code outside the scanned tree, on middleware, or on deployment config must
  not be `confirmed`.
- **No rule may print a secret.** Route every `secret/*` finding through `_emit`,
  which masks values.
- **Deterministic only.** No model calls, no network, no randomness. A rule that
  needs judgement beyond the AST belongs in `needs_review`, not in a heuristic.

## Commit messages

One line, imperative, what changed and why: `tighten ssrf rule to ignore fixed hosts`.
