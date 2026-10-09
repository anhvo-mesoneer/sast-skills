# LLM SAST Skills

A collection of agent skills that turn your LLM coding assistant into a fully functional SAST scanner focused on the **OWASP Top 10 (2021)**. Works natively with Claude Code, Codex, Opencode, Cursor and any other assistant that supports agent skills. No third-party tools required.

Claude Code with Opus model is recommended. But if the cost is a concern, use any IDE and model you trust.

![Process in Claude Code](demo.gif)

## How It Works

`CLAUDE.md` (for Claude Code) or `AGENTS.md` (for Opencode and other IDEs) orchestrates the entire assessment workflow automatically:

1. **Scope selection** — the orchestrator picks which skills to run based on the OWASP categories you ask for (or runs everything by default).
2. **Codebase Analysis** — the `sast-analysis` skill maps the technology stack, architecture, entry points, data flows, and trust boundaries. Output: `sast/architecture.md`.
3. **Sinks Index (shared cache)** — the `sast-index` skill runs `rg` once across the tree to enumerate security-relevant sinks (SQL calls, exec/eval, template renders, XML parsers, HTTP clients, upload handlers, JWT usage, secret markers, crypto primitives, security config, manifests, CI pipelines, log calls, …) and writes per-skill sections to `sast/sinks-index.md`. Every detection skill reads only its section instead of re-scanning the codebase.
4. **Vulnerability Detection (parallel)** — the selected detection skills run in parallel as subagents. Each does a recon phase (reusing `sast/<skill>-recon.md` if present) then verifies exploitability. Results go to `sast/*-results.md`.
5. **Report Generation** — the `sast-report` skill consolidates all findings into a single `sast/final-report.md`, ranked by severity with full remediation guidance and dynamic test instructions.

### Caching / token efficiency

`architecture.md`, `sinks-index.md`, and per-skill `*-recon.md` files are **persisted** and reused across runs. A re-scan on an unchanged codebase does almost no reading — it just re-uses caches and jumps to verification. Use `/scan --fresh` (or delete files under `sast/`) to invalidate.

## OWASP Top 10 Coverage

| Group | Category | Skills |
|-------|----------|--------|
| **A01** | Broken Access Control | `sast-idor`, `sast-missingauth`, `sast-pathtraversal` |
| **A02** | Cryptographic Failures | `sast-hardcodedsecrets`, `sast-weakcrypto` |
| **A03** | Injection | `sast-sqli`, `sast-xss`, `sast-rce`, `sast-ssti`, `sast-xxe` |
| **A04** | Insecure Design | `sast-businesslogic` |
| **A05** | Security Misconfiguration | `sast-fileupload`, `sast-misconfig` |
| **A06** | Vulnerable & Outdated Components | `sast-sca` |
| **A07** | Identification & Authentication Failures | `sast-jwt` |
| **A08** | Software & Data Integrity Failures | `sast-massassignment`, `sast-cicd` |
| **A09** | Security Logging & Monitoring Failures | `sast-logging` |
| **A10** | Server-Side Request Forgery | `sast-ssrf` |

Plus `sast-analysis` (recon / threat modeling) and `sast-report` (final consolidated report).

## Installation

Copy your project into the `sast-files` folder, then open `sast-files` as your workspace in your AI coding assistant.

```bash
cp -r /path/to/your/project sast-files/
```

> **Note:** If your project already contains a `CLAUDE.md` or `AGENTS.md` file, remove it before running the assessment — otherwise it will conflict with the orchestration file provided by this toolkit.

## Usage

After copying the files, open your project in your AI coding assistant.

Run a full OWASP Top 10 scan:

> Run vulnerability scan

Scan a specific OWASP category (or several):

> Scan for A01 and A03 vulnerabilities

> Only check injection issues

Scan specific skills:

> Run sast-sqli and sast-xss

The entry point file (`CLAUDE.md` or `AGENTS.md`) orchestrates the workflow automatically. It skips any steps whose output files already exist, so you can safely re-run it after fixing issues.

## Output

All output is written to a `sast/` folder in your project root:

| File | Description |
|---|---|
| `sast/architecture.md` | Technology stack, architecture, entry points, data flows |
| `sast/*-results.md` | Per-vulnerability-class findings with proof and remediation |
| `sast/final-report.md` | Consolidated report ranked by severity |
