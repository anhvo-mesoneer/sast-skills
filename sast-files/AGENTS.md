# SAST Security Assessment

Your goal is to identify security vulnerabilities in the codebase located in the current directory, focused on the **OWASP Top 10 (2021)**.

The workflow is designed to **reuse work across runs**: architecture map, sinks index, and per-skill recon files are all persisted and reused unless a `--fresh` scan is requested.

---

## Scan Scope Selection

Before running Step 2, determine which OWASP categories to scan.

- If the user names one or more categories (e.g. "scan A01 and A03", "only run injection checks", "check for SSRF"), scan **only** the matching groups from the table below.
- If the user names individual skills (e.g. "run sast-sqli and sast-xss"), scan **only** those skills.
- If the user says "full scan", "everything", or gives no scope, scan **all** groups.
- If the user says `fresh` / `--fresh` / "rebuild index", delete `sast/sinks-index.md`, `sast/architecture.md`, and all `sast/*-recon.md` before starting.

### OWASP Top 10 → Skill Groups

| Group | Category | Skills |
|-------|----------|--------|
| **A01** | Broken Access Control | sast-idor, sast-missingauth, sast-pathtraversal |
| **A02** | Cryptographic Failures | sast-hardcodedsecrets, sast-weakcrypto |
| **A03** | Injection | sast-sqli, sast-xss, sast-rce, sast-ssti, sast-xxe |
| **A04** | Insecure Design | sast-businesslogic |
| **A05** | Security Misconfiguration | sast-fileupload, sast-misconfig |
| **A06** | Vulnerable & Outdated Components | sast-sca |
| **A07** | Identification & Authentication Failures | sast-jwt |
| **A08** | Software & Data Integrity Failures | sast-massassignment, sast-cicd |
| **A09** | Security Logging & Monitoring Failures | sast-logging |
| **A10** | Server-Side Request Forgery | sast-ssrf |

State the selected scope back to the user in one line before starting Step 1.

---

## Step 1: Codebase Analysis & Threat Modeling

Skip if `sast/architecture.md` already exists.

Run the `sast-analysis` skill directly (it stays in-session since later steps read its output).

**Wait for this step to finish before proceeding.**

---

## Step 2: Sinks Index (shared cache)

Skip if `sast/sinks-index.md` already exists.

Run the `sast-index` skill directly. It uses `rg` to enumerate security-relevant sinks once and writes per-skill sections to `sast/sinks-index.md`. Detection skills read only their own section instead of re-scanning the tree — this is the main token-saver on repeat runs.

**Wait for this step to finish before proceeding.**

---

## Step 3: Vulnerability Detection (Parallel)

Run only the checks in the selected scope. Skip any task where the results file already exists.

Start **one subagent per selected check**, all **in parallel**. Give each subagent this instruction pattern:

> Read `sast/architecture.md` and the section for this skill in `sast/sinks-index.md` for context. If a `sast/<skill>-recon.md` file already exists, reuse it and skip recon. Otherwise run the skill's recon phase, then verification. Write findings to that skill's results file. **Preserve** `sast/<skill>-recon.md` so future runs can reuse it — do NOT delete it, even if the skill's own cleanup step says to. `sast/<skill>-batch-*.md` files may be deleted after the merge.

| Skill | Results file | Cache files |
|-------|--------------|-------------------------|
| sast-idor | `sast/idor-results.md` | `sast/idor-recon.md` |
| sast-missingauth | `sast/missingauth-results.md` | `sast/missingauth-recon.md`, `sast/missingauth-batch-*.md` |
| sast-pathtraversal | `sast/pathtraversal-results.md` | `sast/pathtraversal-recon.md`, `sast/pathtraversal-batch-*.md` |
| sast-hardcodedsecrets | `sast/hardcodedsecrets-results.md` | `sast/hardcodedsecrets-recon.md`, `sast/hardcodedsecrets-batch-*.md` |
| sast-sqli | `sast/sqli-results.md` | `sast/sqli-recon.md`, `sast/sqli-batch-*.md` |
| sast-xss | `sast/xss-results.md` | `sast/xss-recon.md` |
| sast-rce | `sast/rce-results.md` | `sast/rce-recon.md`, `sast/rce-batch-*.md` |
| sast-ssti | `sast/ssti-results.md` | `sast/ssti-recon.md` |
| sast-xxe | `sast/xxe-results.md` | `sast/xxe-recon.md` |
| sast-fileupload | `sast/fileupload-results.md` | `sast/fileupload-recon.md`, `sast/fileupload-batch-*.md` |
| sast-jwt | `sast/jwt-results.md` | `sast/jwt-recon.md` |
| sast-ssrf | `sast/ssrf-results.md` | `sast/ssrf-recon.md` |
| sast-weakcrypto | `sast/weakcrypto-results.md` | `sast/weakcrypto-recon.md`, `sast/weakcrypto-batch-*.md` |
| sast-businesslogic | `sast/businesslogic-results.md` | `sast/businesslogic-recon.md`, `sast/businesslogic-batch-*.md` |
| sast-misconfig | `sast/misconfig-results.md` | `sast/misconfig-recon.md`, `sast/misconfig-batch-*.md` |
| sast-sca | `sast/sca-results.md` | `sast/sca-recon.md`, `sast/sca-batch-*.md` |
| sast-massassignment | `sast/massassignment-results.md` | `sast/massassignment-recon.md`, `sast/massassignment-batch-*.md` |
| sast-cicd | `sast/cicd-results.md` | `sast/cicd-recon.md`, `sast/cicd-batch-*.md` |
| sast-logging | `sast/logging-results.md` | `sast/logging-recon.md`, `sast/logging-batch-*.md` |

Wait for all subagents to finish before proceeding.

---

## Step 4: Report Generation

After all subagents from Step 3 finish, generate the final consolidated report.

Skip this step if `sast/final-report.md` already exists.

Launch a single subagent:

> Read all available `sast/*-results.md` files and `sast/architecture.md` for context, then run the `sast-report` skill to generate `sast/final-report.md` with all findings ranked by severity and confidentiality impact.

---

## Cache invalidation

The cache is **reused across runs**. Invalidate manually when the codebase changes materially:

- `rm sast/final-report.md` — force report regeneration
- `rm sast/<skill>-results.md sast/<skill>-recon.md` — force one skill to re-run
- `rm sast/sinks-index.md` — rebuild the shared index (cheap; do this after large refactors)
- `rm -rf sast/` — full clean rebuild

Or ask for a `fresh` scan via the orchestrator / `/scan --fresh`.
