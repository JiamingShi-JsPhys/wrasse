# wrasse rule catalogue

62 rules. Generated from `src/wrasse/rules.py` by `wrasse rules export` — do not edit by hand.

`needs_review` means the tool reports it but never counts it by `--fail-on`.

## A · privacy

*Will this code leak something?*

### `agent/env-not-ignored` — Secrets readable by an agent or committed

**HIGH** · needs_review · privacy

A .env file is present and is not excluded from version control or from the assistant's file index.

```diff
- <the offending line>
+ .gitignore:  .env
```

<sub>preset prompt: <file> exists but is not excluded. Add it to .gitignore and to .cursorignore / .claude settings so the agent never reads it into context.</sub>

### `error/stack-to-client` — Exception text returned to the client

**HIGH** · confirmed · privacy

A traceback discloses file paths, SQL statements and dependency versions to whoever triggers an error.

```diff
- <the offending line>
+ {"error": "internal_error"}
```

<sub>preset prompt: At <file>:<line> an exception is returned to the caller. Log it server-side with the request id and return a fixed message plus that id.</sub>

### `leak/machine-path` — Document or config leaks a machine path or private address

**MEDIUM** · needs_review · privacy

A username, home directory or internal address discloses host layout to readers of the repository.

```diff
- <the offending line>
+ {fix_machine}
```

<sub>preset prompt: <file>:<line> contains a path or address from someone's machine. Replace it with a placeholder (<user>, <project-root>) or an environment variable.</sub>

### `log/sensitive-field` — Sensitive value written to logs

**MEDIUM** · needs_review · privacy

Log records are persisted, collected and retained far longer than the request that produced them.

```diff
- <the offending line>
+ "[redacted]"
```

<sub>preset prompt: In <file>:<line> a secret-looking value is logged. Log an identifier instead (user id, request id) or mask all but the last four characters.</sub>

### `response/model-leaks-secret` — Response model exposes a secret field

**MEDIUM** · needs_review · privacy

The response schema serializes these fields by default.

```diff
- <the offending line>
+ # remove this field from the response schema
```

<sub>preset prompt: The response model at <file>:<line> contains a secret field. Remove it from the response schema and keep it only on the ORM model.</sub>

### `secret/assignment-entropy` — Hard-coded secret by name and entropy

**HIGH** · confirmed · privacy

The identifier denotes a secret and the literal has enough entropy to be a real value rather than a placeholder.

```diff
- <the offending line>
+ os.environ["API_KEY"]
```

<sub>preset prompt: Move the value at <file>:<line> to an environment variable and rotate it if the file is tracked by git. Keep the placeholder in documentation only.</sub>

### `secret/default-credentials` — Default credentials shipped

**CRITICAL** · confirmed · privacy

Default credentials are the first combination attempted in automated login attacks.

```diff
- <the offending line>
+ # provision the first user from an environment secret
```

<sub>preset prompt: Default credentials are the first combination attempted in automated login attacks.</sub>

### `secret/frontend-env` — Secret exposed through a public frontend variable

**CRITICAL** · confirmed · privacy

NEXT_PUBLIC_, VITE_ and REACT_APP_ variables are inlined into the client bundle at build time.

```diff
- <the offending line>
+ // server-side only — never expose this value to the browser
```

<sub>preset prompt: In <file>:<line> a secret is assigned to a public frontend variable. Move the call to a server route, read the key from the server environment, and return only the client-safe token (e.g. a publishable key). Assume the current value is already public.</sub>

### `secret/in-frontend-bundle` — Secret literal inside browser code

**CRITICAL** · confirmed · privacy

A provider key literal is present in a file the browser downloads.

```diff
- <the offending line>
+ // server-side only — never expose this value to the browser
```

<sub>preset prompt: A key literal is in browser code at <file>:<line>. Move it server-side and rotate it; anything that ships to the browser must be treated as published.</sub>

### `secret/in-git-history` — Secret committed in git history

**CRITICAL** · confirmed · privacy

Removing the line does not remove it from existing clones, forks or CI caches.

```diff
- <the offending line>
+ # rotate this credential — deleting the line is not enough
```

<sub>preset prompt: Commit <commit> still contains a credential in <file>. Rotate the key first, then rewrite history (git filter-repo) if the repository is public.</sub>

### `secret/private-key-block` — Private key committed to source

**CRITICAL** · confirmed · privacy

PEM private-key material is readable in a tracked file.

```diff
- <the offending line>
+ # load the key from a secret manager or a path outside the repo
```

<sub>preset prompt: A private key is committed at <file>:<line>. Remove it, rotate the key pair, and load it from a file path outside the repository or a secret manager.</sub>

### `secret/provider-key` — Hard-coded provider key

**CRITICAL** · confirmed · privacy

The value matches a published credential format for a cloud provider and is stored in the source tree.

```diff
- <the offending line>
+ os.environ["API_KEY"]
```

<sub>preset prompt: Replace the hard-coded key in <file>:<line> with an environment variable lookup, keep the variable name, and add the key to .gitignore if it is in a tracked file. Do not print the key anywhere in logs.</sub>

### `upload/path-from-filename` — Uploaded filename used in a path

**HIGH** · confirmed · privacy

A filename containing path separators or .. resolves outside the upload directory.

```diff
- <the offending line>
+ target = (Path(BASE) / name).resolve()
```

<sub>preset prompt: At <file>:<line> a caller-supplied filename is joined into a path. Resolve the final path and reject anything outside the base directory.</sub>

## B · AI pitfalls

*What did the AI leave out?*

### `agent/hidden-instructions` — Invisible characters in an agent instruction file

**HIGH** · confirmed · ai

Zero-width and bidirectional control characters can encode instructions that are invisible in review.

```diff
- <the offending line>
+ # delete every invisible character; retype the file from a trusted source
```

<sub>preset prompt: Zero-width and bidirectional control characters can encode instructions that are invisible in review.</sub>

### `api/unbounded-query` — Route returns an unbounded query

**MEDIUM** · needs_review · ai

The handler returns every row matching the query; the result set grows with the table.

```diff
- <the offending line>
+ .limit(page_size).offset(page * page_size)
```

<sub>preset prompt: The handler returns every row matching the query; the result set grows with the table.</sub>

### `auth/insecure-token-source` — Security token built from a predictable source

**HIGH** · needs_review · ai

Math.random and random.random are not cryptographically secure; the next value is predictable.

```diff
- <the offending line>
+ secrets.token_urlsafe(32)  /  crypto.randomBytes(32)
```

<sub>preset prompt: Math.random and random.random are not cryptographically secure; the next value is predictable.</sub>

### `auth/jwt-misuse` — JWT verification can be bypassed

**HIGH** · confirmed · ai

alg:none accepts an unsigned token; a key literal is readable by anyone with the source.

```diff
- <the offending line>
+ jwt.decode(token, key, algorithms=["RS256"])
```

<sub>preset prompt: alg:none accepts an unsigned token; a key literal is readable by anyone with the source.</sub>

### `auth/md5-sha1-password` — Password hashed with MD5 or SHA-1

**HIGH** · confirmed · ai

Both digest functions are fast enough for billions of candidates per second on commodity GPUs.

```diff
- <the offending line>
+ # use bcrypt/argon2: bcrypt.hashpw(pw, bcrypt.gensalt(12))
```

<sub>preset prompt: Both digest functions are fast enough for billions of candidates per second on commodity GPUs.</sub>

### `auth/weak-password-hash` — Password hash with a very low work factor

**MEDIUM** · needs_review · ai

A cost factor of 4 is exhausted in seconds by an offline attack.

```diff
- <the offending line>
+ bcrypt.hash(pw, 12)
```

<sub>preset prompt: A cost factor of 4 is exhausted in seconds by an offline attack.</sub>

### `authz/admin-route-unprotected` — Admin route checks login but not role

**HIGH** · needs_review · ai

The route requires authentication but no role, so any authenticated account reaches an administrative path.

```diff
- <the offending line>
+ Depends(require_admin)
```

<sub>preset prompt: The route requires authentication but no role, so any authenticated account reaches an administrative path.</sub>

### `authz/mass-assignment` — Request model lets the caller set a privileged field

**HIGH** · needs_review · ai

The request body binds directly onto the model, including fields that carry privilege.

```diff
- <the offending line>
+ # keep is_admin out of the input model; set it server-side
```

<sub>preset prompt: The request body binds directly onto the model, including fields that carry privilege.</sub>

### `authz/partial-role-check` — Ownership check only applies to one role

**HIGH** · needs_review · ai

The ownership check is inside one role branch; other roles do not pass through it.

```diff
- <the offending line>
+ owner_id=user.id
```

<sub>preset prompt: At <file>:<line> the ownership check only runs inside a role branch. Move the constraint into the query so every role shares it, or add the check to each branch.</sub>

### `authz/query-without-owner` — Query loads an object without an ownership check

**HIGH** · needs_review · ai

A caller-supplied identifier reaches the database with no owner or tenant constraint in this function.

```diff
- <the offending line>
+ owner_id=user.id
```

<sub>preset prompt: At <file>:<line> an object is loaded by a caller-supplied id with no ownership constraint. Add owner_id/tenant_id to the query, or confirm the check exists in a service layer, and add a test proving another user's object returns 404.</sub>

### `authz/route-without-auth` — Route has no authentication in its dependency chain

**HIGH** · confirmed · ai

No Depends, router-level dependency or middleware attaches an identity to this route.

```diff
- <the offending line>
+ user=Depends(get_current_user)
```

<sub>preset prompt: The route at <file>:<line> has no authentication in its dependency chain. Add Depends(get_current_user) or a router-level dependency, unless it is intentionally public.</sub>

### `code/command-injection` — Caller-supplied value reaches a command

**HIGH** · confirmed · ai

The shell interprets metacharacters in the value, so ; or $() starts a second command.

```diff
- <the offending line>
+ subprocess.run([cmd, *args], shell=False)
```

<sub>preset prompt: At <file>:<line> a value reaches a command sink. Pass an argument list with shell=False and validate it against an allowlist.</sub>

### `code/dynamic-eval` — eval/exec runs a string as code

**HIGH** · confirmed · ai

The value is evaluated as source code.

```diff
- <the offending line>
+ json.loads(value)  # or an explicit dispatch table
```

<sub>preset prompt: The value is evaluated as source code.</sub>

### `code/fail-open` — Verification fails open

**HIGH** · needs_review · ai

The except branch returns True, so an error inside the check is treated as a pass.

```diff
- <the offending line>
+ except Exception: return False
```

<sub>preset prompt: The except branch returns True, so an error inside the check is treated as a pass.</sub>

### `code/nosql-injection` — Request data used as a query filter

**HIGH** · needs_review · ai

The query filter is built from request data and can carry operators such as $gt or $where.

```diff
- <the offending line>
+ collection.find({'user_id': user.id})
```

<sub>preset prompt: The query filter is built from request data and can carry operators such as $gt or $where.</sub>

### `code/open-redirect` — Redirect target comes from the request

**MEDIUM** · needs_review · ai

The redirect target comes from the request, so a link on this domain can land on another.

```diff
- <the offending line>
+ redirect(next_path if next_path.startswith("/") else "/")
```

<sub>preset prompt: The redirect target comes from the request, so a link on this domain can land on another.</sub>

### `code/sql-string-built` — SQL string built from a caller-supplied value

**HIGH** · confirmed · ai

The value reaches the database as SQL text rather than as a bound parameter.

```diff
- <the offending line>
+ execute("... WHERE id = ?", (value,))
```

<sub>preset prompt: The query at <file>:<line> interpolates a value into SQL. Use a bound parameter and pass the value separately.</sub>

### `code/ssrf` — Outbound request uses a caller-supplied URL

**MEDIUM** · needs_review · ai

The URL reaches the HTTP client without a host allowlist, so it can address internal services.

```diff
- <the offending line>
+ requests.get(url, allow_redirects=False)  # after host allowlist check
```

<sub>preset prompt: At <file>:<line> a caller-supplied URL reaches an HTTP client. Parse the URL, check the scheme and host against an allowlist, and disable redirects.</sub>

### `code/ssti` — Request value used as a template

**HIGH** · confirmed · ai

The request value is compiled as a template, so template syntax is evaluated.

```diff
- <the offending line>
+ render_template("page.html", value=user)
```

<sub>preset prompt: The request value is compiled as a template, so template syntax is evaluated.</sub>

### `code/unsafe-deserialization` — Unsafe deserialization of untrusted data

**HIGH** · confirmed · ai

pickle and yaml.load invoke constructors during parsing.

```diff
- <the offending line>
+ json.loads(payload)
```

<sub>preset prompt: At <file>:<line> untrusted bytes reach an unsafe deserializer. Use JSON, or yaml.safe_load, or a signed payload.</sub>

### `code/weak-crypto` — Broken or misused cipher

**HIGH** · confirmed · ai

The algorithm or mode is deprecated or leaks structure; a key literal is stored in the source.

```diff
- <the offending line>
+ # AES-GCM with a key from the environment
```

<sub>preset prompt: The algorithm or mode is deprecated or leaks structure; a key literal is stored in the source.</sub>

### `code/xss-output` — Request data rendered into HTML without escaping

**HIGH** · needs_review · ai

The value is emitted as markup, so a tag in it becomes script.

```diff
- <the offending line>
+ {fix_escape}
```

<sub>preset prompt: At <file>:<line> a request value reaches an HTML response. Escape it with the framework's own filter ({{ }} in Jinja, textContent in the DOM), or keep it out of the markup entirely.</sub>

### `config/allowed-hosts-wildcard` — Host header check accepts any host

**HIGH** · confirmed · ai

With a wildcard any Host header is accepted, including one controlled by an attacker.

```diff
- <the offending line>
+ + ALLOWED_HOSTS = ["app.example.com"]
```

<sub>preset prompt: With a wildcard any Host header is accepted, including one controlled by an attacker.</sub>

### `config/api-docs-public` — API docs and schema left open

**MEDIUM** · needs_review · ai

The OpenAPI document and the documentation UI are served without authentication.

```diff
- <the offending line>
+ FastAPI(docs_url=None, openapi_url=None)
```

<sub>preset prompt: The OpenAPI document and the documentation UI are served without authentication.</sub>

### `config/autoescape-off` — Template autoescaping disabled

**HIGH** · needs_review · ai

Autoescaping is disabled, so every interpolated value is emitted as markup.

```diff
- <the offending line>
+ autoescape=True
```

<sub>preset prompt: Autoescaping is disabled, so every interpolated value is emitted as markup.</sub>

### `config/cookie-flags` — Session cookie missing Secure or HttpOnly

**MEDIUM** · needs_review · ai

Without HttpOnly the cookie is readable by script; without Secure it is sent over plain HTTP.

```diff
- <the offending line>
+ secure: true, httpOnly: true
```

<sub>preset prompt: Without HttpOnly the cookie is readable by script; without Secure it is sent over plain HTTP.</sub>

### `config/cors-wildcard-credentials` — CORS allows any origin with credentials

**HIGH** · confirmed · ai

Wildcard origins combined with credentials allow any site to read authenticated responses.

```diff
- <the offending line>
+ allow_origins=["https://app.example.com"]
```

<sub>preset prompt: CORS at <file>:<line> combines wildcard origins with credentials. List the exact origins that need access.</sub>

### `config/csrf-exempt` — CSRF protection turned off for a view

**MEDIUM** · needs_review · ai

A browser holding the session cookie can be made to submit this request from any site.

```diff
- <the offending line>
+ # remove @csrf_exempt, or add a narrow, reviewed control
```

<sub>preset prompt: A browser holding the session cookie can be made to submit this request from any site.</sub>

### `config/debug-enabled` — Debug mode enabled

**HIGH** · confirmed · ai

Debug mode exposes an interactive traceback and, depending on the framework, a console.

```diff
- <the offending line>
+ DEBUG = os.getenv("DEBUG", "false") == "true"
```

<sub>preset prompt: Debug mode is enabled at <file>:<line>. Read it from an environment variable that is false in production.</sub>

### `config/host-check-disabled` — Host header protection disabled

**HIGH** · confirmed · ai

The Host header check is disabled, so any hostname is accepted.

```diff
- <the offending line>
+ # list the hosts you serve: ALLOWED_HOSTS = ['app.example.com']
```

<sub>preset prompt: The Host header check is disabled, so any hostname is accepted.</sub>

### `config/object-storage-public-acl` — Object storage ACL allows public writes

**CRITICAL** · confirmed · ai

The bucket ACL permits public write, so any holder of the URL can modify or delete objects.

```diff
- <the offending line>
+ ACL: "private"
```

<sub>preset prompt: The bucket ACL permits public write, so any holder of the URL can modify or delete objects.</sub>

### `config/rate-limit-key` — Rate limit keyed on the proxy address

**MEDIUM** · needs_review · ai

Keyed on the proxy address, all clients share one quota.

```diff
- <the offending line>
+ # key on the authenticated identity, or the first X-Forwarded-For hop you trust
```

<sub>preset prompt: <file>:<line> builds the rate-limit key from the connection address. Behind a proxy or tunnel that is the proxy's address for every user.</sub>

### `config/tls-verification-off` — TLS certificate verification disabled

**HIGH** · confirmed · ai

Certificate verification is disabled, so any intermediary is trusted.

```diff
- <the offending line>
+ verify=True  # or point at a trusted CA bundle
```

<sub>preset prompt: Certificate verification is disabled, so any intermediary is trusted.</sub>

### `deps/insecure-source` — Dependency installed over plain HTTP

**HIGH** · confirmed · ai

The dependency is fetched over plain HTTP, where any intermediary can replace the archive.

```diff
- <the offending line>
+ git+https://... or https://...
```

<sub>preset prompt: The dependency is fetched over plain HTTP, where any intermediary can replace the archive.</sub>

### `deps/lockfile-integrity` — Lockfile entries carry no integrity hash

**MEDIUM** · confirmed · ai

Without an integrity hash, a registry or mirror can substitute the package undetected.

```diff
- <the offending line>
+ npm install --package-lock-only   # regenerate with integrity hashes
```

<sub>preset prompt: <file> has <count> entry(ies) without an integrity or resolved field. Regenerate the lockfile rather than editing it, and keep it in version control.</sub>

### `deps/new-package` — Dependency published very recently

**MEDIUM** · needs_review · ai

The package first appeared recently; slopsquatting registers an invented name ahead of its use.

```diff
- <the offending line>
+ # check the maintainer and download count before installing
```

<sub>preset prompt: The package first appeared recently; slopsquatting registers an invented name ahead of its use.</sub>

### `deps/package-not-found` — Dependency does not exist on PyPI

**HIGH** · confirmed · ai

The name does not exist on the registry; installing it executes whoever registered it first.

```diff
- <the offending line>
+ - {name}
```

<sub>preset prompt: The dependency at <file>:<line> could not be found on PyPI. Confirm the intended package name before installing; do not run pip install against a guessed name.</sub>

### `deps/typosquat` — Dependency name looks misspelled

**MEDIUM** · needs_review · ai

The name is one edit distance from a popular package, the shape used for impersonation.

```diff
- <the offending line>
+ - {name}
```

<sub>preset prompt: The dependency at <file>:<line> is one edit away from a popular package. Confirm which one was intended before installing.</sub>

### `deps/undeclared-import` — Third-party module imported but not declared

**MEDIUM** · needs_review · ai

The module is imported but no manifest declares it, so a clean install fails.

```diff
- <the offending line>
+ # add {module} to requirements / pyproject
```

<sub>preset prompt: <file>:<line> imports <module>, which no manifest declares. Add it with a version range, or it will be missing in a clean install.</sub>

### `deps/version-not-found` — Pinned version does not exist

**MEDIUM** · confirmed · ai

The package exists but the requested version was never published.

```diff
- <the offending line>
+ - {name}{spec}
```

<sub>preset prompt: The version pinned at <file>:<line> does not exist. Check the package's release page and pin an existing version.</sub>

### `input/untyped-body` — Request body read without a schema

**MEDIUM** · needs_review · ai

Fields are read directly from the request, bypassing model validation of type and range.

```diff
- <the offending line>
+ payload: UpdateUser
```

<sub>preset prompt: At <file>:<line> the handler reads raw request fields. Define a Pydantic model, declare it as the parameter, and read attributes from it.</sub>

### `license/mismatch` — Declared licence does not match the licence file

**MEDIUM** · needs_review · ai

The declaration and the LICENSE file disagree, which determines whether downstream use is permitted.

```diff
- <the offending line>
+ # make the declaration and LICENSE agree
```

<sub>preset prompt: <file>:<line> declares a licence that the LICENSE file does not support. Align them, or mark the code UNLICENSED if it is not open source.</sub>

### `log/injection` — Request value written into a log line

**MEDIUM** · needs_review · ai

A newline in the value produces a forged entry in the log used for incident review.

```diff
- <the offending line>
+ # logger.info("login %s", clean(user))
```

<sub>preset prompt: A newline in the value produces a forged entry in the log used for incident review.</sub>

### `net/ephemeral-host` — Endpoint points at a temporary tunnel or free dynamic domain

**HIGH** · confirmed · ai

The hostname is reclaimed after expiry; the next registrant receives the same traffic.

```diff
- <the offending line>
+ # use a domain you own and control
```

<sub>preset prompt: At <file>:<line> a host is a disposable tunnel or free dynamic DNS name. Point the client at a domain you control, and rotate any credential that has already been sent there.</sub>

### `net/request-without-timeout` — Outbound request has no timeout

**MEDIUM** · needs_review · ai

A request without a timeout holds its worker until the peer closes the connection.

```diff
- <the offending line>
+ requests.get(url, timeout=10)
```

<sub>preset prompt: A request without a timeout holds its worker until the peer closes the connection.</sub>

### `response/pii-fields` — Response model exposes strong PII

**MEDIUM** · needs_review · ai

The response carries identity or payment identifiers, which are retained outside the request.

```diff
- <the offending line>
+ # return a masked value: '****1234'
```

<sub>preset prompt: The response carries identity or payment identifiers, which are retained outside the request.</sub>

### `spring/cors-wildcard` — Spring CORS allows every origin

**HIGH** · confirmed · ai

A bare @CrossOrigin accepts any origin; with credentials it discloses authenticated sessions.

```diff
- <the offending line>
+ @CrossOrigin(origins = "https://app.example.com")
```

<sub>preset prompt: A bare @CrossOrigin accepts any origin; with credentials it discloses authenticated sessions.</sub>

### `spring/csrf-disabled` — Spring Security CSRF protection disabled

**HIGH** · confirmed · ai

CSRF protection is disabled, so a browser holding the session cookie can be made to submit state-changing requests.

```diff
- <the offending line>
+ # http.csrf(Customizer.withDefaults())
```

<sub>preset prompt: CSRF protection is disabled, so a browser holding the session cookie can be made to submit state-changing requests.</sub>

### `spring/permit-all` — Spring Security rule permits every request

**HIGH** · needs_review · ai

permitAll() removes authentication for every path the matcher covers.

```diff
- <the offending line>
+ .requestMatchers("/public/**").permitAll()  # and authenticated() elsewhere
```

<sub>preset prompt: permitAll() removes authentication for every path the matcher covers.</sub>
