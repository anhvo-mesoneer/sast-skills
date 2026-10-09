---
name: sast-report
description: >-
  Consolidate all SAST vulnerability results from the sast/ folder into a single
  final report ranked by severity and confidentiality impact. Reads all
  *-results.md files and produces sast/final-report.md. Run after all
  vulnerability detection skills complete. Use when asked to generate a final
  report, consolidate findings, or summarize security results.
---

# Final Security Report Generation

You are consolidating all completed SAST vulnerability scan results into a single prioritized security report.

**Prerequisites**: At least one `sast/*-results.md` file must exist. Run the vulnerability detection skills first if they don't.

---

## What to Include

Only include findings with these classifications from each result file:
- `[VULNERABLE]`
- `[LIKELY VULNERABLE]`

Exclude `[NOT VULNERABLE]` and `[NEEDS MANUAL REVIEW]` findings from the main report body (count them only in the summary).

---

## Severity Ranking

Assign each finding a severity tier — **Critical**, **High**, **Medium**, or **Low** — using the table below as your baseline. Adjust up or down based on context (e.g., an IDOR that exposes financial records is High, not Medium).

| Vulnerability Class | Default Severity |
|---------------------|------------------|
| RCE via command injection, eval, or unsafe deserialization | Critical |
| SSTI (Server-Side Template Injection) | Critical |
| SQLi on authentication endpoints | Critical |
| JWT algorithm confusion (alg:none, RS256→HS256) | Critical |
| File upload leading to code execution (webshell) | Critical |
| CI/CD script injection or `pull_request_target` PR-head execution with secrets/write token | Critical |
| Debug console reachable in production (Werkzeug, JDWP/inspector port) | Critical |
| SQLi with full data extraction capability | High–Critical |
| Mass assignment of privilege, ownership, or tenant fields (role, isAdmin, tenantId) | High–Critical |
| Vulnerable dependency with reachable exploit path (known CVE, attacker input reaches it) | High–Critical |
| Exposed management endpoints leaking secrets (Actuator heapdump/env, H2 console) | High–Critical |
| Insecure password reset (predictable/reusable token, Host header poisoning) | High–Critical |
| GraphQL injection (user-controlled operation document enabling unauthorized fields or gateway abuse) | High–Critical |
| XXE with file read or internal SSRF | High–Critical |
| Missing authentication on sensitive endpoints | High–Critical |
| SSRF reaching internal services or cloud metadata | High |
| Path traversal reading sensitive or config files | High |
| File upload with stored content accessible to others | High |
| IDOR on PII, financial, or health data | High |
| XSS (stored/persistent) | High |
| Hardcoded secret in publicly accessible code (client bundle, mobile app) | High |
| Weak password hashing (plaintext, MD5/SHA-1, unsalted fast hash) | High |
| Insecure randomness for security tokens (session IDs, reset tokens, OTPs) | High |
| TLS certificate verification disabled on calls carrying credentials or PII | High |
| CORS reflecting arbitrary origins with credentials | High |
| Prototype pollution reachable from request input | High |
| MFA bypass or missing brute-force protection on login / OTP / reset | Medium–High |
| Race conditions on balances, stock, or single-use artifacts | Medium–High |
| Credentials, tokens, or secrets written to production logs | Medium–High |
| Broken cipher / ECB / static IV / nonce reuse on sensitive data | Medium–High |
| JWT with missing or bypassable claim validation | Medium–High |
| Missing authentication on lower-sensitivity endpoints | Medium |
| IDOR on non-sensitive data | Medium |
| XSS (reflected or DOM) | Medium |
| Business logic flaws (price manipulation, workflow bypass) | Medium |
| Session fixation / session not invalidated on logout or password change | Medium |
| Vulnerable dependency, reachability unconfirmed | Medium |
| Unpinned third-party CI actions, `curl \| sh` without checksum, missing SRI on CDN scripts | Medium |
| Security controls globally disabled (CSRF with cookie auth, security headers) | Medium |
| PII in logs, log injection (CRLF) into plaintext logs | Low–Medium |
| Missing security event logging (failed logins, access denials, privilege changes) | Low–Medium |
| User enumeration via login / registration / reset responses | Low–Medium |
| Verbose errors, stack traces, missing security headers, source maps in production | Low |
| Information disclosure of non-sensitive data | Low |

**Confidentiality as a tiebreaker**: When two findings share the same baseline severity, rank higher the one with greater confidentiality impact — i.e., the greater its potential to expose sensitive user data, credentials, or system internals.

---

## OWASP Top 10 (2021) Mapping

Tag every finding with the OWASP category of its source scan:

| Source scan | OWASP category |
|-------------|----------------|
| idor, missingauth, pathtraversal | A01 Broken Access Control |
| hardcodedsecrets, weakcrypto | A02 Cryptographic Failures |
| sqli, xss, rce, ssti, xxe, graphql | A03 Injection |
| businesslogic | A04 Insecure Design |
| fileupload, misconfig | A05 Security Misconfiguration |
| sca | A06 Vulnerable and Outdated Components |
| jwt | A07 Identification and Authentication Failures |
| massassignment, cicd | A08 Software and Data Integrity Failures |
| logging | A09 Security Logging and Monitoring Failures |
| ssrf | A10 Server-Side Request Forgery |

---

## Execution

Perform all steps in-session (no subagents needed).

### Step 1: Discover result files

Check which of these files exist in `sast/`:
- `idor-results.md`
- `sqli-results.md`
- `ssrf-results.md`
- `xss-results.md`
- `rce-results.md`
- `xxe-results.md`
- `fileupload-results.md`
- `pathtraversal-results.md`
- `ssti-results.md`
- `jwt-results.md`
- `missingauth-results.md`
- `hardcodedsecrets-results.md`
- `weakcrypto-results.md`
- `businesslogic-results.md`
- `misconfig-results.md`
- `sca-results.md`
- `massassignment-results.md`
- `cicd-results.md`
- `logging-results.md`
- `graphql-results.md`

Any other `sast/*-results.md` file present should also be included.

Also read `sast/architecture.md` if it exists (use it for the project name and context when writing severity rationale).

### Step 2: Read and extract findings

Read each existing result file. For every finding classified as `[VULNERABLE]` or `[LIKELY VULNERABLE]`, extract:
- Finding title
- Vulnerability type (derived from the source file)
- File / endpoint affected
- Issue description
- Impact description
- Proof / code path (the `Taint trace`, `Evidence trace`, `Attack path`, `Reachability trace`, or `Data flow` field — whichever the source scan uses)
- Remediation
- Dynamic test steps (if present)

### Step 3: Score and sort

Assign each finding a severity level (Critical / High / Medium / Low) using the table above. Sort all findings:

1. Critical first, then High, Medium, Low
2. Within each tier, sort by confidentiality impact (highest first)

### Step 4: Write `sast/final-report.md`

Use exactly this output format:

---

```markdown
# Security Assessment Final Report

**Project**: [name from architecture.md, or infer from codebase]
**Generated**: [current date]
**Scans completed**: [comma-separated list of scan types that had result files]

---

## Executive Summary

| Severity | Count |
|----------|-------|
| Critical | N |
| High     | N |
| Medium   | N |
| Low      | N |
| **Total confirmed findings** | **N** |

Scans with no confirmed vulnerabilities: [list]
Findings requiring manual review: N (see individual result files for details)

### By OWASP Category

| OWASP | Critical | High | Medium | Low |
|-------|----------|------|--------|-----|
| A01 Broken Access Control | N | N | N | N |
| ... (one row per category that was scanned) | | | | |

---

## Vulnerability Index

| # | Title | Type | OWASP | Severity | Endpoint / File |
|---|-------|------|-------|----------|----------------|
| 1 | ... | RCE | A03 | Critical | `POST /api/exec` |
| 2 | ... | SQLi | A03 | High | `GET /api/users` |

---

## Findings

### Critical

#### [Finding Title] — [Vuln Type]

- **Source scan**: `sast/[type]-results.md`
- **OWASP**: [A0x Category]
- **Classification**: Vulnerable *(or "Likely Vulnerable")*
- **Endpoint / File**: ...
- **Severity rationale**: [1–2 sentences explaining why this is Critical, with focus on confidentiality and integrity impact]
- **Issue**: ...
- **Impact**: ...
- **Proof**:
  ```
  [code path or evidence from original finding]
  ```
- **Remediation**: ...
- **Dynamic Test**:
  ```
  [curl command or step-by-step test instructions from original finding]
  ```

---

### High

[Same structure as Critical section]

---

### Medium

[Same structure]

---

### Low

[Same structure]

---

## Appendix: Scan Coverage

| Scan | OWASP | Result File | Status |
|------|-------|-------------|--------|
| IDOR | A01 | `sast/idor-results.md` | Completed / Not run |
| Missing Auth | A01 | `sast/missingauth-results.md` | Completed / Not run |
| Path Traversal | A01 | `sast/pathtraversal-results.md` | Completed / Not run |
| Hardcoded Secrets | A02 | `sast/hardcodedsecrets-results.md` | Completed / Not run |
| Weak Cryptography | A02 | `sast/weakcrypto-results.md` | Completed / Not run |
| SQLi | A03 | `sast/sqli-results.md` | Completed / Not run |
| XSS | A03 | `sast/xss-results.md` | Completed / Not run |
| RCE | A03 | `sast/rce-results.md` | Completed / Not run |
| SSTI | A03 | `sast/ssti-results.md` | Completed / Not run |
| XXE | A03 | `sast/xxe-results.md` | Completed / Not run |
| GraphQL injection | A03 | `sast/graphql-results.md` | Completed / Not run |
| Business Logic | A04 | `sast/businesslogic-results.md` | Completed / Not run |
| File Upload | A05 | `sast/fileupload-results.md` | Completed / Not run |
| Security Misconfiguration | A05 | `sast/misconfig-results.md` | Completed / Not run |
| Vulnerable Components (SCA) | A06 | `sast/sca-results.md` | Completed / Not run |
| JWT | A07 | `sast/jwt-results.md` | Completed / Not run |
| Mass Assignment / Prototype Pollution | A08 | `sast/massassignment-results.md` | Completed / Not run |
| CI/CD & Integrity | A08 | `sast/cicd-results.md` | Completed / Not run |
| Logging & Monitoring | A09 | `sast/logging-results.md` | Completed / Not run |
| SSRF | A10 | `sast/ssrf-results.md` | Completed / Not run |
```

---

## Important Reminders

- Include ONLY `[VULNERABLE]` and `[LIKELY VULNERABLE]` findings in the Findings section.
- Mark `[LIKELY VULNERABLE]` findings clearly: append **⚠ Likely Vulnerable** after the finding title.
- Preserve all details from the original findings — do not summarize or truncate Proof, Remediation, or Dynamic Test sections.
- If `sast/architecture.md` exists, use it to enrich the severity rationale with application-specific context (e.g., "this endpoint handles payment data, making confidentiality impact Critical").
- Omit severity sections entirely (e.g., the `### Low` heading) if no findings fall in that tier.
