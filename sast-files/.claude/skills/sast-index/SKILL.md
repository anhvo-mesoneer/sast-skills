---
name: sast-index
description: >-
  Build a shared sinks index that all vulnerability detection skills can reuse
  to avoid re-scanning the whole codebase. Uses ripgrep to enumerate dangerous
  patterns once (SQL calls, exec/eval, template renders, XML parsers, HTTP
  clients, file I/O, JWT libs, upload handlers, hardcoded secret markers) and
  writes file:line references to sast/sinks-index.md. Run after sast-analysis
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

## Rules

- **Do not Read** source files during indexing except to sanity-check a handful of matches. Ripgrep output is the payload.
- Skip a section entirely (with note "no candidates") if the tech stack makes it inapplicable (e.g. no XML parsing → skip XXE).
- Cap each section at 200 entries; if a batch overflows, emit a "TRUNCATED — narrow globs" note so the downstream skill knows to refine.
- Do not attempt to verify exploitability — that is each detection skill's job.
- If `.git` is present, capture `git rev-parse --short HEAD` and include it at the top so re-runs can detect drift.
