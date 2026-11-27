# Changelog

## 1.0.0

First stable release. The rule set, the report formats, the session and the
config file are as described under `1.0.0-beta`; what changed is how the
analysis decides that code is safe.

- **A guard has to dominate the request.** It must run before the sink, cannot
  sit inside a branch some callers never take, and cannot be defeated by the
  exception path: a handler that swallows the rejection, a handler that returns
  the row, or a request in a `finally:` block all mean the guard proved nothing.
- **Escaping is judged where it is bound.** `shlex.quote` and
  `urllib.parse.quote` are not HTML escaping; a rebound `escape`, an imported
  module replaced by another object, and a local `escape = lambda v: v` are not
  the escaper they look like.
- **An ownership check has to refuse on every path that does not own the row** —
  the `else` branch, a nested branch, a loop's `else`, and a context manager
  that swallows exceptions (`suppress` under any import alias, or a local
  `__exit__` / `__aexit__` that can return something truthy).
- **A credential is masked before any renderer sees it**, including the password
  inside a connection string at any length, `?password=` in a query, and
  Oracle's `user/password@host` form.
- **An incomplete scan says so in every output.** A file that is too large,
  unreadable, unstattable, symlinked or unparsable is named and the command
  exits 4; JSON carries `scan.complete`, SARIF sets
  `invocations[].executionSuccessful`, and the HTML page opens with a banner.
- A Java file the parser cannot read is reported instead of skipped, and a
  `.csrf()` / `.disable()` chain split across lines is found.

## 1.0.0-beta

First usable release. No dependencies, no model calls, offline by default.

### Detection

62 rules across two mainlines.

Privacy: hard-coded provider keys, entropy-scored assignments, private key
blocks, secrets in frontend variables, secrets in browser code, sensitive
values in logs, exception text returned to clients, secret fields in response
models, upload paths built from filenames, `.env` readable by an agent.

AI pitfalls: packages that do not exist, pinned versions that do not exist,
typosquatted names, routes with no authentication, queries with no ownership
constraint, request bodies without a schema, debug mode, wildcard CORS with
credentials, unsafe deserialization, SQL built from values, command injection,
SSRF, ownership checked only inside one role branch, credentials that were
deleted but still sit in git history, request data rendered into HTML without
escaping, endpoints on disposable tunnels, machine paths and private addresses
leaked into docs, undeclared imports, and a licence declaration that the LICENSE
file does not support.

Three groups were added later in the same release.

- Input models and passwords: mass assignment through a privileged field on an
  input model, MD5/SHA-1 password hashing, outbound `requests` / `httpx` calls
  with no timeout.
- From the 2026 reports: invisible characters (zero-width, bidi, tag) in agent
  instruction files, reported without echoing the line; request text written
  into a log line with no newline handling (CWE-117); broken ciphers (DES, RC4,
  3DES, ECB, a literal key, Java `Cipher.getInstance`); a dependency whose first
  release is under 90 days old, the one signal slopsquatting leaves before
  install.
- OWASP API gaps: server-side template injection; a request body used directly
  as a Mongo filter; an admin path that requires login but no role; a list
  endpoint with no `limit`; API docs left open on an app that already looks
  shipped; a dependency installed over plain HTTP; a `verify*` function whose
  `except` returns `True`; strong PII (`id_card`, `ssn`, card numbers) on a
  response model.

### Java and Spring

Two line-level Java rules need nothing installed: `Cipher.getInstance` and
`MessageDigest.getInstance`. Three Spring rules need a parser, not a JDK:
`pip install wrasse[java]` adds wildcard `@CrossOrigin`, `.csrf().disable()` and
`permitAll()`. Nothing is compiled or run.

### Precision

Measured on seven real repositories: 191 findings became 54. What changed:

- A logging call has to be a level method. `logger.setup_logging(...)` stopped
  matching as a sink.
- A value counts as request data when it is request-derived, or when the file
  imports a web framework. A CLI's `args` stopped counting.
- Lines inside multi-line strings are skipped, so prompt text and docstrings no
  longer match code rules.
- An import inside `try/except ImportError` counts as an optional dependency.
- `fs/promises` resolves to the Node builtin, and `vscode` / `electron` are
  host-provided.
- Machine paths produce one finding per file instead of one per line.
- `shell=True` fires only when request data reaches the command.
- A monorepo's own workspace packages count as declared.
- A Python import is checked against Python manifests only.
- Placeholder paths such as `/Users/x/` and `/Users/demo/` are ignored.
- A private address counts where it configures a host, and not in a pentest
  example or a help string.
- Build caches (`.cache`, `.turbo`, `.nx`, `.esbuild`) are out of scope.
- A bucket ACL and the Django host-check setting match only when a value is
  assigned, so another scanner's rule table no longer matches them.
- In JavaScript and TypeScript only `eval(` is a sink. `exec(` is an interface
  method and `RegExp.prototype.exec`, so it no longer matches there.

### Green lines carry their kind

Each finding now says whether its green line is a verified replacement (`+`), a
template to adapt (`~`), or a case with no automatic fix (`!`). The kind is in
JSON (`fix.kind`) and SARIF (`properties.fix_kind`), so a CI job can treat a
template differently from a patch.

### Session and configuration

`wrasse` opens a session with a banner, the last scan, and a numbered list.
Typing `/` opens a command menu (`Tab` completes, `↑↓` selects, `Esc` closes,
the list scrolls). `/config` opens an arrow-key panel over four settings:
`lang`, `fail_on`, `mode`, `focus`. Both fall back to plain input when there is
no TTY, so piped use is unchanged.

Settings live in `.wrasse/config.json`, written only by `wrasse config set` and
by `/config`; every command reads it. `--lang` overrides the language for one
run and writes nothing, so you can read someone else's repository in your own
language without leaving a file in it. `.wrasse/last.json` stays out of version
control; `config.json` and `baseline.json` can be committed.

### Reporting

`--diff REF`, `--baseline FILE`, `--sarif FILE`, and a `baseline` command
(`create` / `diff`). Output is text (red/green fix lines, line gutter, context),
JSON, SARIF 2.1.0, or a single-file HTML report, in English or Chinese.

The project model is a Python AST index with symbol and route extraction,
FastAPI `Depends` chains, `APIRouter(prefix=…)` and `include_router(prefix=…)`
resolution, dependency manifests, and agent config discovery.

Commands: `audit`, `preflight`, `review`, `open`, `explain`, `rules`, `config`,
`baseline`, `doctor`. Finding ids are stable across scans; `open 3` works on the
last scan's numbering.

### Privacy and honesty

Offline by default; `--online` is the only way package names leave the machine,
and the run says which ones it checked. Every finding is `confirmed` or
`needs_review`, severity is kept separate from confidence, exit code 4 means the
scan did not finish, and a credential is masked before any renderer sees it.

### Known limits

- Python and FastAPI in depth. Java gets two line rules plus the optional Spring
  parser; other languages are not scanned.
- Authorization is structural. Semantic inference is planned for 1.1.
- No incremental scan.
- `pytest`-style fixtures are not modelled.

### Review rounds

The first external review turned up three things. This round also gave every
green line a kind, so a reader can tell a verified replacement from a template.

- Baseline reads and writes go through the same writer as state and config:
  atomic, and refusing a symlinked `.wrasse/` or a symlinked target. Reading a
  baseline inside the project no longer follows a symlink.
- `.wrasse/last.json` is treated as untrusted input. Every string is cleaned of
  control characters and the entries are validated before `explain`, `review`
  or `baseline diff` prints them.
- An ownership check now needs a comparison, or a query keyword whose value is
  the caller. A row field that merely carries the name `owner_id` is not a
  check: `if order.owner_id:` passes every row and is reported again.

Each finding says whether its green line is a verified replacement (`+`), a
template to adapt (`~`), or a case with no automatic fix (`!`). The kind is in
JSON (`fix.kind`) and SARIF (`properties.fix_kind`). Ten rules produce verified
fixes today; the rest stay templates.

`npm/` holds `wrasse-audit`, a four-file launcher that forwards its arguments to
the installed Python CLI. It contains no scanner.

The second external review found four things. Two could produce a wrong answer;
one could leak what the tool exists to protect.

- A caller-supplied `Evidence` snippet is now masked like the red and green
  lines. It used to reach JSON, SARIF and the state file untouched, so a line
  that matched an authorization rule and carried a key would show that key.
- An ownership guard is checked for direction. `if order.owner_id != user.id:
  return order` used to count as a check; it hands the row to the wrong caller
  and is reported now. A mismatch branch that raises still counts.
- `FastAPI(dependencies=[Depends(...)])` is collected as an app-level
  dependency, so routes on that app are no longer reported as unauthenticated.
- The state file has to be a regular file under 8 MB, and text read from it is
  folded onto one line before it is printed, so a planted `.wrasse/last.json`
  cannot start a forged entry.

The README now shows a rendered finding instead of drawing one in ASCII; a
Chinese copy sits beside it. `REVIEW.md` numbers match the tree again.

The third round read the detectors themselves. Five of them answered wrongly,
each now fixed with a test and a safe twin: `html.unescape` no longer counts as
escaping; an ownership constraint on another table no longer protects the row
being returned; an allowlist that is defined but never used is not a guard; a
query renamed through a local variable is followed to the sink; and a `.wrasse`
that is a file is refused instead of crashing the scan.

The fourth review read the detectors again and found four heuristics passing
themselves off as proof. `shlex.quote` and `urllib.parse.quote` no longer count
as HTML escaping; an f-string whose literal part is only `https://` no longer
counts as a fixed host; an allowlist mentioned in the function is no longer a
guard unless the check compares this URL's host; and an `else: return order` no
longer counts as refusing the request. SQL aliases are followed to a fixed
point instead of two hops, and a router in another file inherits the app-level
dependencies of the `FastAPI()` that mounts it.

The fifth review found the offline promise had a hole behind the prompt. The
interactive `/audit` shortcut inherited a default that let the dependency check
reach PyPI, while the plain `audit` command did not; offline is now the default
of the pipeline itself, and `--online` is the only thing that changes it. The
same round found the 2 MB per-file cap skipping files without saying so: a
skipped file now marks the scan incomplete, is named in the warning, and makes
the command exit 4.

The sixth review asked for proof rather than shape, and found three places where
a shape was enough. A prefix test counted as a host check, although
`https://api.example.com.attacker.example` passes `startswith()`; a bare
`escape()` counted as HTML escaping even when this file defined it; and a nested
`else: if ... else: return order` counted as a refusal. Guards now need a parsed
host or a membership test on the URL, a bare escaper needs an import from an HTML
module (a local definition wins), and nested branches are followed one by one.
A router imported by name (`from ... import router as x`) joins the dependency
graph, and the session now says how many files it did not scan.

The seventh review's four detector reports were already fixed in the build it
read, but one of its counterexamples still slipped through: `else: if not
user.is_admin: return order` counted as an authorised branch because the test
named a role, and a negated role test is the opposite of a guard. Only a
positive role test counts now. It was also right that a file whose size or
contents cannot be read was dropped in silence: a stat or read failure is now
recorded like an oversized file. The corpus numbers in AGENTS.md were two rounds
stale; the suite checks them now, the same way it checks the test count.
