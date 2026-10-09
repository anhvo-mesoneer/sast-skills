---
name: sast-index
description: >-
  Build a shared sinks index that all vulnerability detection skills can reuse
  to avoid re-scanning the whole codebase. Uses ripgrep to enumerate dangerous
  patterns once (SQL calls, exec/eval, template renders, XML parsers, HTTP
  clients, file I/O, JWT libs, upload handlers, hardcoded secret markers,
  crypto primitives, security config, dependency manifests, business
  operations, bulk binding, CI pipelines, log calls) and writes file:line
  references to sast/sinks-index.md. Run after sast-analysis
  and before any detection skill. Outputs sast/sinks-index.md. Use when asked
  to index sinks, build a scan cache, or prepare for detection.
---

# Sinks Index

Your goal is to produce a **single shared index of security-relevant sinks** so downstream detection skills don't each re-scan the codebase. This is a *cheap* pass — use `rg` (ripgrep) with pattern batches rather than Read.

Read `sast/architecture.md` first to know which languages, frameworks, and libraries are actually in play. Skip pattern batches that don't apply.

Write results to `sast/sinks-index.md` with one section per skill. Each entry must be `path:line: matched_line` so a detection skill can jump straight to the site.

## Output format

```markdown
# Sinks Index

Generated against commit: <short SHA if available, else "n/a">
Languages detected: <from architecture.md>

## sast-sqli
- src/foo.py:42: cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
- ...

## sast-xss
- ...

(one section per skill, empty section allowed with note "no candidates")
```

## Pattern batches

Run these with `rg -n --no-heading -S` (case-insensitive), scoped by file globs matching the stack from `architecture.md`. Adjust language globs per project.

### sast-sqli
- `\b(execute|executemany|query|raw|exec_driver_sql)\s*\(` — SQL executors
- `f["'].*(SELECT|INSERT|UPDATE|DELETE|MERGE)` — f-string SQL
- `\+\s*["'].*(SELECT|INSERT|UPDATE|DELETE)` — string-concat SQL
- ORM raw: `\.raw\(`, `text\(`, `session\.execute\(`

### sast-xss
- Template escaping off: `\|\s*safe\b`, `\{\{\{`, `dangerouslySetInnerHTML`, `v-html\s*=`, `\.innerHTML\s*=`, `document\.write\(`
- Server-render sinks: `Markup\(`, `mark_safe\(`, `Html\.Raw\(`

### sast-rce
- `\b(exec|eval|Function|compile)\s*\(`
- `subprocess\.(Popen|call|run|check_output).*shell\s*=\s*True`
- `os\.system\(`, `child_process\.(exec|execSync|spawn)\(`
- Deserialization: `pickle\.loads?\(`, `yaml\.load\(`, `ObjectInputStream`, `Marshal\.load`

### sast-ssti
- `render_template_string\(`, `Template\(.*\+`, `env\.from_string\(`, `Handlebars\.compile\(`, `eval\(.*template`

### sast-xxe
- `XMLParser`, `DocumentBuilderFactory`, `SAXParser`, `etree\.parse\(`, `xml\.dom\.minidom`
- absence of `resolve_entities\s*=\s*False` / `FEATURE_SECURE_PROCESSING`

### sast-ssrf
- HTTP clients: `requests\.(get|post|put|delete|request)\(`, `urllib\.request\.urlopen\(`, `http\.get\(`, `fetch\(`, `axios\.(get|post|request)\(`, `WebClient`, `HttpClient`
- Flag calls whose URL argument looks user-derived (variable, not literal)

### sast-idor / sast-missingauth
- Route decorators: `@app\.route`, `@router\.(get|post|put|delete|patch)`, `@RequestMapping`, `app\.(get|post)\(`, `router\.(get|post)\(`
- Auth guards: `@login_required`, `@requires_auth`, `@PreAuthorize`, `isAuthenticated\(`, middleware names from architecture.md

### sast-pathtraversal
- `open\(`, `Path\(`, `os\.path\.join\(`, `fs\.readFile`, `File\(`, `readFileSync\(`, `sendFile\(`, `serveStatic`
- Look for concatenation with user input

### sast-fileupload
- `request\.files`, `multer\(`, `MultipartFile`, `@RequestPart`, `formidable\(`, `busboy`
- Extension checks: `\.endswith\(`, `path\.extname\(`, `mimetype`

### sast-jwt
- `jwt\.(encode|decode|sign|verify)\(`, `jsonwebtoken`, `PyJWT`, `io\.jsonwebtoken`
- `algorithms\s*=\s*\[`, `algorithm\s*:\s*['"]none['"]`

### sast-hardcodedsecrets
- Only scan **publicly reachable** paths per architecture.md (frontend bundles, mobile builds, HTML, JS shipped to clients)
- High-entropy assignments: `(api[_-]?key|secret|token|password|passwd|pwd|access[_-]?key)\s*[:=]\s*["'][A-Za-z0-9+/=_\-]{16,}["']`
- Provider prefixes: `AKIA[0-9A-Z]{16}`, `ghp_[A-Za-z0-9]{36}`, `sk-[A-Za-z0-9]{20,}`, `xox[baprs]-`, `-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----`

### sast-weakcrypto
- Weak hashes / password encoders: `\b(md5|sha1|MD5|SHA-?1)\b`, `MessageDigest\.getInstance\(`, `hashlib\.(md5|sha1|sha256)\(`, `createHash\(`, `NoOpPasswordEncoder`, `StandardPasswordEncoder`, `MessageDigestPasswordEncoder`
- Ciphers / modes / IVs: `Cipher\.getInstance\(`, `createCipheriv\(`, `AES\.new\(`, `\b(DES|DESede|3DES|RC4|Blowfish|RC2)\b`, `/ECB/`, `MODE_ECB`, `IvParameterSpec\(`, `GCMParameterSpec\(`, `SecretKeySpec\(`
- Insecure randomness: `Math\.random\(`, `new Random\(`, `java\.util\.Random`, `\brandom\.(random|randint|choice)\(`, `math/rand`, `\b(mt_)?rand\(`, `uniqid\(`, `new System\.Random\(`
- TLS verification off: `verify\s*=\s*False`, `rejectUnauthorized\s*:\s*false`, `NODE_TLS_REJECT_UNAUTHORIZED`, `InsecureSkipVerify\s*:\s*true`, `X509TrustManager`, `HostnameVerifier`, `NoopHostnameVerifier`, `ServerCertificateCustomValidationCallback`
- Non-constant-time compare / weak RSA: `PKCS1Padding`, `RSA/ECB/PKCS1`, `KeyPairGenerator.*initialize\((512|1024)\)`

### sast-businesslogic
- Money / quantity / state fields in handlers and DTOs: `\b(price|amount|total|discount|coupon|voucher|balance|credit|quantity|qty|refund|fee|points)\b`
- State transitions and workflows: `\b(status|state)\s*=|setStatus\(|transition|approve|checkout|confirm|capture`
- Locking / atomicity markers (presence or absence matters): `FOR UPDATE`, `@Lock\(`, `@Version`, `@Transactional`, `select_for_update`, `\.lock\(`
- Webhook / callback handlers: `webhook`, `callback`, `notify`, `ipn`

### sast-misconfig
- Config files to list (not grep content): `application*.yml`, `application*.properties`, `settings*.py`, `.env*`, `appsettings*.json`, `config/*.rb`, `nginx*.conf`, `docker-compose*.yml`, `Dockerfile*`, k8s manifests
- Debug / errors: `DEBUG\s*=\s*True`, `debug\s*=\s*True`, `APP_DEBUG`, `UseDeveloperExceptionPage`, `include-stacktrace`, `include-message`, `consider_all_requests_local`
- Management surfaces: `management\.endpoints`, `exposure\.include`, `h2\.console`, `springdoc|swagger-ui|graphiql|introspection`, `net/http/pprof`
- CORS / CSRF / headers: `allowedOrigins|allowedOriginPatterns|allowCredentials|Access-Control-Allow`, `cors\(`, `csrf\(\)\.disable|csrf\(AbstractHttpConfigurer::disable|csrf_exempt|skip_forgery_protection`, `headers\(\)\.disable|frameOptions`, `helmet`
- Exposure: `serveIndex|autoindex|Options \+Indexes`, `sourceMap`, `USER root|privileged|hostNetwork|docker\.sock`

### sast-sca
- Manifests and lockfiles (list paths only): `pom.xml`, `build.gradle*`, `gradle.lockfile`, `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `requirements*.txt`, `Pipfile.lock`, `poetry.lock`, `go.mod`, `composer.lock`, `*.csproj`, `packages.lock.json`, `Gemfile.lock`
- Runtime versions: `^FROM `, `\.nvmrc`, `"engines"`, `java\.version|<release>`, `python_requires`, `spring-boot-starter-parent`
- Vendored libraries: files matching `*.min.js` under `static/`, `public/`, `assets/`, `vendor/`

### sast-massassignment
- Entity / model bound from request: `@RequestBody`, `@ModelAttribute`, `BeanUtils\.copyProperties\(`, `readerForUpdating|updateValue\(`, `\.create\(req\.body|Object\.assign\([^,]+,\s*req\.body|\{\s*\.\.\.req\.body|findByIdAndUpdate\(|update\(\{\s*data:\s*req\.body`
- Framework allowlist config: `fields\s*=\s*['"]__all__['"]`, `\$guarded\s*=\s*\[\s*\]`, `fill\(\$request->all\(\)|create\(\$request->all\(\)`, `permit!`, `whitelist\s*:\s*true|forbidNonWhitelisted`
- Deep merge / path set (prototype pollution): `_\.merge\(|_\.defaultsDeep\(|\$\.extend\(true|deepmerge|lodash\.set|_\.set\(|__proto__`

### sast-cicd
- Pipeline files (list paths only): `.github/workflows/*.yml`, `action.yml`, `.gitlab-ci.yml`, `Jenkinsfile`, `azure-pipelines.yml`, `bitbucket-pipelines.yml`, `.circleci/config.yml`
- Injection / dangerous triggers: `\$\{\{\s*github\.(event|head_ref)`, `pull_request_target`, `workflow_run`, `issue_comment`, `\$CI_MERGE_REQUEST_`, `sh\s+"[^"]*\$\{params\.`
- Unpinned actions: `uses:\s*[^./][^@]+@(v?\d[\w.]*|main|master)\s*$`
- Unverified downloads / SRI: `curl[^|]*\|\s*(ba)?sh`, `wget[^|]*\|\s*(ba)?sh`, `^ADD https?://`, `<script[^>]+src=["']https?://`, `<link[^>]+href=["']https?://`

### sast-logging
- Log calls with sensitive names or whole objects: `(log|logger|LOG|console)\.(trace|debug|info|warn|error|log)\(.*(password|passwd|secret|token|authorization|cookie|apiKey|otp|cvv|card|iban|ssn|req\.body|request|headers)`
- Request/wire logging: `CommonsRequestLoggingFilter|setIncludePayload|setIncludeHeaders`, `HttpLoggingInterceptor|wiretap|logging\.level\.org\.apache\.http\.wire`, `show-sql|org\.hibernate\.(SQL|orm\.jdbc\.bind|type\.descriptor)`, `morgan\(`, `filter_parameters`
- Log layouts (CRLF handling): `logback*.xml`, `log4j2*.xml`, `%msg|%m\b|%enc\{`, `LogstashEncoder`
- Swallowed errors: `catch\s*\([^)]*\)\s*\{\s*\}`, `except[^:]*:\s*pass`

## Rules

- **Do not Read** source files during indexing except to sanity-check a handful of matches. Ripgrep output is the payload.
- Skip a section entirely (with note "no candidates") if the tech stack makes it inapplicable (e.g. no XML parsing → skip XXE).
- Cap each section at 200 entries; if a batch overflows, emit a "TRUNCATED — narrow globs" note so the downstream skill knows to refine.
- Do not attempt to verify exploitability — that is each detection skill's job.
- If `.git` is present, capture `git rev-parse --short HEAD` and include it at the top so re-runs can detect drift.
