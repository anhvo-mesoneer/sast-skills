---
description: Run the SAST security scan. Optionally pass OWASP categories or skill names to narrow scope (e.g. `/scan xss rce`, `/scan A01 A03`, `/scan owasp-top-10`). Add `--fresh` to rebuild all caches.
argument-hint: [--fresh] [category|skill ...]  e.g. xss rce | A01 A03 | owasp-top-10 | --fresh A03
---

Run a SAST security assessment against the current codebase following the orchestration in `CLAUDE.md`.

**Requested scope:** `$ARGUMENTS`

Resolve the scope using the rules below, then follow `CLAUDE.md` (analysis → sinks index → parallel detection → report). Report the resolved scope back to me in one line before starting.

## Fresh flag

If `$ARGUMENTS` contains `--fresh` or `fresh`, first delete `sast/architecture.md`, `sast/sinks-index.md`, all `sast/*-recon.md`, and all `sast/*-batch-*.md` so caches rebuild from scratch. Do NOT delete `sast/*-results.md` unless the user also asks to re-run detection. Then strip the flag and continue scope resolution with the remaining tokens.

## Scope resolution

If `$ARGUMENTS` is empty, or contains any of `all`, `full`, `owasp`, `owasp-top-10`, `owasp10`, `top10` → scan **all** skills.

Otherwise, tokenize `$ARGUMENTS` (split on whitespace, commas, and `+`) and for each token, expand as follows (case-insensitive):

### OWASP category tokens

| Token(s) | Skills |
|----------|--------|
| `A01`, `access-control`, `broken-access-control` | sast-idor, sast-missingauth, sast-pathtraversal |
| `A02`, `crypto`, `cryptographic-failures`, `secrets` | sast-hardcodedsecrets |
| `A03`, `injection` | sast-sqli, sast-xss, sast-rce, sast-ssti, sast-xxe |
| `A05`, `misconfig`, `security-misconfiguration` | sast-fileupload |
| `A07`, `auth`, `authentication` | sast-jwt |
| `A10`, `ssrf` | sast-ssrf |

### Individual skill tokens

Accept either the short name or the `sast-` prefixed form:

`idor`, `missingauth`, `pathtraversal`, `hardcodedsecrets` (or `secrets`), `sqli`, `xss`, `rce`, `ssti`, `xxe`, `fileupload`, `jwt`, `ssrf`

Deduplicate the resulting skill list. If any token cannot be resolved, stop and ask me to clarify — do not silently drop it.

## Execution

1. Run `sast-analysis` first (skip if `sast/architecture.md` already exists).
2. Launch one subagent per resolved skill **in parallel**, each following the instruction pattern in `CLAUDE.md` Step 2. Skip any whose `sast/<skill>-results.md` already exists.
3. When all detection subagents finish, run `sast-report` to produce `sast/final-report.md` (skip if it already exists).
