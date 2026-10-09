---
name: sast-misconfig
description: >-
  Detect security misconfigurations (OWASP A05:2021) using a three-phase approach:
  recon (find risky framework, server, and deployment settings), batched verify
  (resolve effective environment, reachability, and impact in parallel subagents,
  3 candidates each), and merge (consolidate batch results). Covers debug mode,
  verbose errors, exposed Actuator/admin/diagnostic endpoints, permissive CORS,
  disabled security controls, missing security headers, default credentials,
  file exposure, and container hardening. Requires sast/architecture.md (run
  sast-analysis first). Outputs findings to sast/misconfig-results.md. Use when
  asked to find security misconfigurations, exposed actuator/debug endpoints,
  CORS issues, missing security headers, or default credentials.
---

# Security Misconfiguration Detection

You are performing a focused security assessment to find security misconfigurations in a codebase. This skill uses a three-phase approach with subagents: **recon** (find risky configuration settings and exposed surfaces), **batched verify** (resolve the effective environment, reachability, and impact in parallel batches of 3), and **merge** (consolidate batch reports into one file).

**Prerequisites**: `sast/architecture.md` must exist. Run the analysis skill first if it doesn't.

---

## What is Security Misconfiguration

Security misconfiguration (OWASP A05:2021) occurs when a framework, server, or deployment component is configured in a way that weakens the application's security: development features left on in production, diagnostic endpoints exposed without authentication, security controls switched off globally, permissive cross-origin policies, or insecure defaults that were never changed. Unlike injection flaws, the bug lives in configuration rather than data flow — the same code is safe or exploitable depending on which profile, environment variable, or deployment file is active.

The core pattern: *an insecure setting or exposed surface is active in an environment that an attacker can reach.*

### What Security Misconfiguration IS

- Debug mode reachable in production: Django `DEBUG = True`, Flask `app.run(debug=True)` (Werkzeug interactive console → RCE), Laravel `APP_DEBUG=true`, ASP.NET `UseDeveloperExceptionPage()` outside `IsDevelopment()`, Rails `consider_all_requests_local = true` in `production.rb`, Keycloak `start-dev`
- Verbose errors returned to clients: Spring `server.error.include-stacktrace=always` / `include-message=always`, exception handlers returning `e.getMessage()`, stack traces, or SQL errors; `X-Powered-By` and server version banners
- Unauthenticated management and diagnostic surfaces: Spring Boot Actuator `exposure.include=*` (`heapdump`, `env`, `jolokia`, `gateway`, `shutdown`), H2 console, Swagger UI / GraphiQL / GraphQL introspection in production, `phpinfo()`, Go `net/http/pprof`
- Permissive CORS: reflecting any `Origin` with `Access-Control-Allow-Credentials: true`, `allowedOriginPatterns("*")` + `allowCredentials(true)`, suffix/substring origin checks that accept `evil-example.com`, allowing the `null` origin
- Security controls disabled globally: `csrf().disable()` on a cookie/session-authenticated app, `headers().disable()`, `anyRequest().permitAll()` as the fallback rule, `@csrf_exempt` / `skip_forgery_protection` on session-authenticated state-changing actions
- Missing security headers or transport hardening at framework or proxy level: no CSP, HSTS, `X-Content-Type-Options`, `frame-ancestors` / `X-Frame-Options`, `Referrer-Policy`; HTTP not redirected to HTTPS
- Default credentials and insecure defaults: seeded `admin/admin` accounts, Keycloak/Postgres/RabbitMQ/Grafana default passwords in deployment manifests, Postgres `trust` auth, Redis without `requirepass`, internal data stores published on `0.0.0.0`
- File and directory exposure: directory listing, serving the project root, `.git`, `.env`, or backups; source maps in production builds
- Container hardening gaps: running as root, `privileged: true`, mounted Docker socket, secrets baked into image layers, JDWP (5005) or Node inspector (9229) ports exposed

### What Security Misconfiguration is NOT

Do not flag these as misconfiguration — they are owned by sibling skills:

- **Upload handling** (extension checks, storage location, executable upload directories) — `sast-fileupload`
- **XML parser features** (`DocumentBuilderFactory`, external entities, `resolve_entities`) — `sast-xxe`
- **TLS verification disabled in outbound clients, weak ciphers or algorithms in code** — `sast-weakcrypto`
- **Session cookie flags (`Secure`, `HttpOnly`, `SameSite`) and authentication flow** (login, session fixation, password policy, OAuth redirect URIs) — `sast-authn`
- **Individual endpoints missing authorization** (one controller method without `@PreAuthorize`) — `sast-missingauth`. A global `anyRequest().permitAll()` fallback or an unauthenticated Actuator/H2 console IS in scope here.
- **Vulnerable dependency versions** — `sast-sca`; **CI/CD pipeline configuration** (GitHub Actions, GitLab CI, Jenkinsfile) — `sast-cicd`
- **Secrets hardcoded in client-side code** — `sast-hardcodedsecrets`
- **Angular `bypassSecurityTrust*` / sanitizer bypass, template autoescaping turned off** — `sast-xss`
- **JWT algorithm or signature validation settings** — `sast-jwt`

### Patterns That Prevent Security Misconfiguration

When you see these patterns, the setting is likely **not vulnerable**:

**1. Secure base configuration, development conveniences gated by profile or environment**
```
# Spring Boot (base application.yml secure; dev-only values in application-dev.yml / @Profile("dev")), Django, ASP.NET Core, NestJS
server.error.include-stacktrace: never
DEBUG = os.environ.get("DJANGO_DEBUG", "False") == "True"
if (app.Environment.IsDevelopment()) { app.UseDeveloperExceptionPage(); }
if (process.env.NODE_ENV !== 'production') { SwaggerModule.setup('docs', app, document); }
```

**2. Management surfaces minimized, isolated, and authenticated**
```
# Spring Boot Actuator — internal port, minimal exposure, a role required beyond health
management.server.port: 8081
management.endpoints.web.exposure.include: health,info,prometheus
# Go — pprof only on a loopback listener; the application uses its own mux
go http.ListenAndServe("127.0.0.1:6060", nil); http.ListenAndServe(":8080", appMux)
```

**3. Exact-match CORS allowlist, framework security defaults left on, headers set centrally**
```
cfg.setAllowedOrigins(List.of("https://app.example.com"));          // Spring
cors({ origin: ['https://app.example.com'], credentials: true })     // Express / NestJS
CORS_ALLOWED_ORIGINS = ["https://app.example.com"]                   # Django (django-cors-headers)
# Spring Security — CSRF disabled only for STATELESS bearer-token APIs; default headers left on
http.sessionManagement(s -> s.sessionCreationPolicy(STATELESS)).oauth2ResourceServer(o -> o.jwt(withDefaults()))
app.disable('x-powered-by'); app.use(helmet());                      // Express
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;   # nginx / ingress
```

**4. No default credentials, least-privilege containers**
```
KC_BOOTSTRAP_ADMIN_PASSWORD: ${KC_ADMIN_PASSWORD:?must be set}       # compose fails if the secret is missing
expose: ["5432"]                                                      # data store only on the compose network
USER 10001                                                            # Dockerfile
securityContext: { runAsNonRoot: true, allowPrivilegeEscalation: false }   # Kubernetes
```

---

## Vulnerable vs. Secure Examples

### Java — Spring Boot (application.yml / application.properties)

```yaml
# VULNERABLE: base application.yml (or .properties) applies to ALL profiles, including production
spring:
  profiles.active: dev                  # dev profile everywhere unless SPRING_PROFILES_ACTIVE overrides it
  h2.console:
    enabled: true                       # /h2-console → attacker-chosen JDBC URL → RCE
    settings.web-allow-others: true
server.error:
  include-stacktrace: always            # stack traces in every error response
  include-message: always               # exception messages (SQL errors, paths) to clients
management:
  endpoints.web.exposure.include: "*"   # heapdump, env, configprops, threaddump, loggers, gateway...
  endpoint:
    shutdown.enabled: true
    env.show-values: ALWAYS             # Boot 3: un-masks secrets in /actuator/env
springdoc.swagger-ui.enabled: ${SWAGGER_ENABLED:true}   # insecure unless the deployment overrides it

# SECURE: secure base config; dev conveniences only in application-dev.yml
server.error: { include-stacktrace: never, include-message: never }
management.server.port: 8081            # internal-only port, not published by compose / ingress
management.endpoints.web.exposure.include: health,info,prometheus
management.endpoint.health.show-details: when-authorized
springdoc.api-docs.enabled: ${SWAGGER_ENABLED:false}
springdoc.swagger-ui.enabled: ${SWAGGER_ENABLED:false}
```

### Java — Spring Boot (SecurityFilterChain, CORS, error handling)

```java
// VULNERABLE: cookie-session login (formLogin + JSESSIONID) with CSRF and headers off,
// any origin allowed with credentials, diagnostic surfaces public, and a permitAll() fallback
@Bean
SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    return http
        .csrf(AbstractHttpConfigurer::disable)
        .headers(AbstractHttpConfigurer::disable)         // drops HSTS, X-Frame-Options, nosniff
        .cors(c -> c.configurationSource(req -> {
            CorsConfiguration cfg = new CorsConfiguration();
            cfg.setAllowedOriginPatterns(List.of("*"));   // reflects ANY origin...
            cfg.setAllowCredentials(true);                // ...and lets it send cookies
            return cfg;
        }))
        .authorizeHttpRequests(a -> a
            .requestMatchers("/actuator/**", "/h2-console/**", "/swagger-ui/**").permitAll()
            .requestMatchers("/api/admin/**").hasRole("ADMIN")
            .anyRequest().permitAll())                    // everything not listed is public
        .formLogin(Customizer.withDefaults())
        .build();
}

// VULNERABLE: exception internals returned to the client (PSQLException text, file paths)
@ExceptionHandler(Exception.class)
ResponseEntity<?> handle(Exception e) { return ResponseEntity.status(500).body(Map.of("error", e.getMessage(), "trace", ExceptionUtils.getStackTrace(e))); }

// SECURE: stateless Keycloak resource server — disabling CSRF is correct here (no cookie auth)
@Bean
SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    return http
        .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .oauth2ResourceServer(o -> o.jwt(Customizer.withDefaults()))
        .csrf(AbstractHttpConfigurer::disable)
        .cors(c -> c.configurationSource(req -> {
            CorsConfiguration cfg = new CorsConfiguration();
            cfg.setAllowedOrigins(List.of("https://app.example.com"));   // exact origins only
            cfg.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE"));
            return cfg;
        }))
        .headers(h -> h.contentSecurityPolicy(csp -> csp.policyDirectives("default-src 'none'; frame-ancestors 'none'")))
        .authorizeHttpRequests(a -> a
            .requestMatchers(EndpointRequest.to(HealthEndpoint.class)).permitAll()
            .requestMatchers(EndpointRequest.toAnyEndpoint()).hasRole("OPS")
            .anyRequest().authenticated())                // deny-by-default fallback
        .build();
}

// SECURE: generic RFC 9457 body; details logged server-side with a correlation id
@ExceptionHandler(Exception.class)
ProblemDetail handle(Exception e) {
    String ref = UUID.randomUUID().toString(); log.error("Unhandled error ref={}", ref, e);
    return ProblemDetail.forStatusAndDetail(HttpStatus.INTERNAL_SERVER_ERROR, "Internal error, ref " + ref);
}
```

### TypeScript / Node.js — Express / NestJS

```typescript
// VULNERABLE: Express
const app = express();                                        // no helmet(), X-Powered-By: Express sent
app.use(cors({ origin: true, credentials: true }));           // reflects any Origin, cookies allowed
app.use(express.static(path.join(__dirname, '..')));          // serves project root: .env, .git, src/
app.use('/files', serveIndex('uploads'));                     // directory listing
app.use((err, req, res, next) => res.status(500).json({ message: err.message, stack: err.stack }));   // NODE_ENV unset: default handler leaks stacks too
// VULNERABLE: suffix check and "null" origin accepted with credentials (evil-example.com, sandboxed iframes)
cors({ origin: (o, cb) => cb(null, !o || o.endsWith('example.com') || o === 'null'), credentials: true });
// VULNERABLE: NestJS main.ts / app.module.ts — explorers and reflected CORS in every environment
app.enableCors({ origin: true, credentials: true });
SwaggerModule.setup('api-docs', app, SwaggerModule.createDocument(app, config));
GraphQLModule.forRoot<ApolloDriverConfig>({ driver: ApolloDriver, introspection: true, playground: true, debug: true });

// SECURE
const isProd = process.env.NODE_ENV === 'production';
app.disable('x-powered-by'); app.use(helmet());              // CSP, HSTS, nosniff, frame-ancestors, Referrer-Policy
app.use(cors({ origin: ['https://app.example.com'], credentials: true }));   // NestJS: app.enableCors({ same })
app.use(express.static(path.join(__dirname, 'public'), { dotfiles: 'deny', index: false }));
app.use((err, req, res, next) => { logger.error(err); res.status(500).json({ message: 'Internal Server Error' }); });
if (!isProd) SwaggerModule.setup('api-docs', app, SwaggerModule.createDocument(app, config));
GraphQLModule.forRoot<ApolloDriverConfig>({ driver: ApolloDriver, introspection: !isProd, playground: !isProd, debug: !isProd });
```

### TypeScript — Angular (build config and the nginx serving the bundle)

```jsonc
"production": { "sourceMap": true, "optimization": true }                            // VULNERABLE (low): angular.json ships source maps
"production": { "sourceMap": false, "optimization": true, "outputHashing": "all" }   // SECURE
```

```nginx
# VULNERABLE: nginx.conf in the frontend image — directory listing, version banner, no security headers
server { listen 80; root /usr/share/nginx/html; autoindex on; location / { try_files $uri $uri/ /index.html; } }

# SECURE (TLS and the HTTP→HTTPS redirect handled here or at the ingress)
server {
  listen 8080; server_tokens off; root /usr/share/nginx/html;
  add_header Content-Security-Policy "default-src 'self'; connect-src 'self' https://sso.example.com; frame-ancestors 'none'" always;
  add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
  add_header X-Content-Type-Options "nosniff" always;
  add_header Referrer-Policy "strict-origin-when-cross-origin" always;
  location ~ /\. { deny all; }
  location / { try_files $uri $uri/ /index.html; }
}
```

### Python — Django / Flask

```python
# VULNERABLE: Django settings.py (or settings/prod.py) used in production
DEBUG = True                                         # tracebacks, settings, SQL, URL patterns on error pages
DEBUG = os.environ.get('DEBUG', 'True') == 'True'    # equally vulnerable: insecure default when unset
ALLOWED_HOSTS = ['*']; CORS_ALLOW_ALL_ORIGINS = True
CORS_ALLOW_CREDENTIALS = True                        # django-cors-headers then reflects the request Origin
@csrf_exempt                                         # on a session-authenticated, state-changing view
def change_email(request): ...

# VULNERABLE: Flask — Werkzeug debugger /console = Python RCE (the PIN is derivable with any file-read bug)
app.run(host='0.0.0.0', debug=True)                  # Dockerfile runs: CMD ["python", "app.py"]
CORS(app, supports_credentials=True)                 # flask-cors default origins="*" → any origin reflected
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True)   # FastAPI: same for cookie requests

# SECURE
DEBUG = os.environ.get('DJANGO_DEBUG', 'False') == 'True'
ALLOWED_HOSTS = ['app.example.com']; CORS_ALLOWED_ORIGINS = ['https://app.example.com']
SECURE_SSL_REDIRECT = True; SECURE_HSTS_SECONDS = 31536000; SECURE_CONTENT_TYPE_NOSNIFF = True; X_FRAME_OPTIONS = 'DENY'
# Flask: CMD ["gunicorn", "app:app"] so app.run() never executes; CORS(app, origins=["https://app.example.com"], supports_credentials=True)
```

### Go

```go
// VULNERABLE: blank import registers /debug/pprof/* on http.DefaultServeMux, which is served publicly
import _ "net/http/pprof"
http.Handle("/static/", http.FileServer(http.Dir(".")))                  // directory listing + source files
log.Fatal(http.ListenAndServe(":8080", nil))                             // nil → DefaultServeMux (includes pprof)
w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin")); w.Header().Set("Access-Control-Allow-Credentials", "true")   // reflected + credentials

// SECURE
mux := http.NewServeMux()                                                // application mux, no pprof
mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("./public"))))
go func() { log.Println(http.ListenAndServe("127.0.0.1:6060", nil)) }()  // pprof on loopback only
c := cors.New(cors.Options{AllowedOrigins: []string{"https://app.example.com"}, AllowCredentials: true})
log.Fatal(http.ListenAndServe(":8080", c.Handler(mux)))
```

### PHP — Laravel

```php
# VULNERABLE: committed .env / deployment environment
APP_DEBUG=true           # Ignition page leaks env (APP_KEY, DB creds); Ignition < 2.5.2 → RCE (CVE-2021-3129)
// config/cors.php — wildcard + credentials makes the CORS middleware reflect the Origin
'allowed_origins' => ['*'], 'supports_credentials' => true,
Route::get('/info', fn () => phpinfo()); Gate::define('viewTelescope', fn ($user = null) => true);   // diagnostics open in production

// SECURE
APP_DEBUG=false
'allowed_origins' => ['https://app.example.com'], 'supports_credentials' => true,
Gate::define('viewTelescope', fn ($user) => in_array($user->email, config('ops.admins'), true));
```

### C# — ASP.NET Core

```csharp
// VULNERABLE: Program.cs — developer surfaces unconditional, any origin with credentials
builder.Services.AddCors(o => o.AddDefaultPolicy(p => p
    .SetIsOriginAllowed(_ => true).AllowCredentials()      // AllowAnyOrigin()+AllowCredentials() throws; this does not
    .AllowAnyHeader().AllowAnyMethod()));
app.UseDeveloperExceptionPage();                          // stack traces, source, headers to every client
app.UseSwagger(); app.UseSwaggerUI(); app.UseDirectoryBrowser();
// Dockerfile / compose: ENV ASPNETCORE_ENVIRONMENT=Development

// SECURE
builder.Services.AddCors(o => o.AddDefaultPolicy(p => p
    .WithOrigins("https://app.example.com").AllowCredentials().AllowAnyHeader().AllowAnyMethod()));
if (app.Environment.IsDevelopment()) { app.UseDeveloperExceptionPage(); app.UseSwagger(); app.UseSwaggerUI(); }
else { app.UseExceptionHandler("/error"); app.UseHsts(); app.UseHttpsRedirection(); }
```

### Ruby on Rails

```ruby
# VULNERABLE: config/environments/production.rb
config.consider_all_requests_local = true       # full exception pages with source and request env
config.force_ssl = false
skip_forgery_protection                         # VULNERABLE: in ApplicationController of a cookie-session app
# VULNERABLE: config/initializers/cors.rb — '*' + credentials raises, but an unanchored regex does not
allow do
  origins(/example\.com/)                        # matches https://example.com.evil.net
  resource '*', headers: :any, methods: :any, credentials: true
end

# SECURE
config.consider_all_requests_local = false; config.force_ssl = true
protect_from_forgery with: :exception
origins 'https://app.example.com'
```

### Containers / Kubernetes

```yaml
# VULNERABLE: docker-compose.yml used for shared, staging, or production environments
services:
  keycloak:
    command: start-dev                               # dev mode: plain HTTP, relaxed hostname checks, dev DB
    environment:
      KC_BOOTSTRAP_ADMIN_USERNAME: admin             # KEYCLOAK_ADMIN / KEYCLOAK_ADMIN_PASSWORD before v26
      KC_BOOTSTRAP_ADMIN_PASSWORD: admin
  postgres:
    environment: { POSTGRES_HOST_AUTH_METHOD: trust }   # no password required
    ports: ["5432:5432"]                             # published on all host interfaces
  redis:
    image: redis:7                                   # official image: no password, protected mode off
    ports: ["6379:6379"]
  backend:
    environment:
      SPRING_PROFILES_ACTIVE: dev
      JAVA_TOOL_OPTIONS: "-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=*:5005"
    ports: ["8081:8080", "5005:5005"]                # JDWP = unauthenticated remote code execution
    volumes: ["/var/run/docker.sock:/var/run/docker.sock"]   # host takeover from inside the container
# VULNERABLE: Kubernetes pod spec
hostNetwork: true
securityContext: { privileged: true, allowPrivilegeEscalation: true }

# SECURE: docker-compose
  keycloak: { command: start --optimized, environment: { KC_BOOTSTRAP_ADMIN_PASSWORD: "${KC_ADMIN_PASSWORD:?must be set}" } }
  postgres: { environment: { POSTGRES_PASSWORD_FILE: /run/secrets/pg_password }, expose: ["5432"] }   # compose network only
  redis: { command: ["redis-server", "--requirepass", "${REDIS_PASSWORD:?must be set}"] }
  backend: { environment: { SPRING_PROFILES_ACTIVE: prod } }   # no debug agent, no docker.sock mount
# SECURE: Kubernetes pod spec
securityContext: { runAsNonRoot: true, allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: { drop: ["ALL"] } }
```

```dockerfile
# VULNERABLE: no USER → runs as root; secret baked into the image (visible via `docker history`)
FROM eclipse-temurin:21-jre
ENV DB_PASSWORD=SuperSecret123
COPY app.jar /app.jar
ENTRYPOINT ["java", "-jar", "/app.jar"]

# SECURE: non-root user; secrets injected at runtime (env or mounted secret), never baked into layers
RUN useradd -r -u 10001 app
COPY --chown=app app.jar /app.jar
USER 10001
```

---

## Execution

This skill runs in three phases using subagents. Pass the contents of `sast/architecture.md` to all subagents as context.

**Cache reuse**: If `sast/misconfig-recon.md` already exists, skip Phase 1 and reuse it. If `sast/sinks-index.md` exists, pass its `## sast-misconfig` section to the Phase 1 subagent as a starting list of candidate sites — the subagent must still search beyond it, since the index is regex-based and incomplete.

### Phase 1: Recon — Find Risky Configuration Settings and Exposed Surfaces

Launch a subagent with the following instructions:

> **Goal**: Find every configuration setting, framework call, and deployment artifact that enables a development feature, exposes a management or diagnostic surface, relaxes a security control, or ships an insecure default — regardless of which profile or environment it applies to. Write results to `sast/misconfig-recon.md`.
>
> **Context**: You will be given the project's architecture summary. Use it to understand the tech stack, how configuration is layered (profiles, settings modules, env files), how the app is deployed (Dockerfile, docker-compose, Kubernetes/Helm, reverse proxy), and whether users authenticate with cookies/sessions or bearer tokens. If a `## sast-misconfig` section from `sast/sinks-index.md` is provided, start from it but search beyond it.
>
> **Where to look**: `application*.yml|yaml|properties`, `bootstrap*.yml`, `@Configuration` / `SecurityFilterChain` / `WebMvcConfigurer` classes, `settings*.py` and `settings/` packages, committed `.env*` files, `config/*.php`, `appsettings*.json`, `Program.cs` / `Startup.cs`, `config/environments/*.rb`, `config/initializers/*.rb`, Node bootstrap files (`main.ts`, `app.ts`, `server.ts`, `index.js`), `angular.json`, `nginx.conf` / `*.conf` / `.htaccess`, `Dockerfile*`, `docker-compose*.yml`, Kubernetes manifests and Helm `values*.yaml`, `pg_hba.conf`, `redis.conf`, seed/migration files (`data.sql`, `import.sql`, Flyway/Liquibase changelogs, seeders, fixtures), Keycloak realm exports (`*realm*.json`).
>
> **What to search for** — flag the setting wherever it appears and record which profile/environment it appears to apply to. Do NOT skip dev-profile files (`application-dev.yml`, `docker-compose.override.yml`, `settings/dev.py`) — Phase 2 decides whether they reach production. Group related settings from the same file and category into one candidate (e.g., all risky Actuator keys in one YAML file = one candidate).
>
> 1. **Debug / development mode**:
>    - Django / Flask: `DEBUG\s*=\s*True`, `os.environ.get('DEBUG', 'True')`, `debug_toolbar` without a `DEBUG` guard; `app.run(.*debug=True`, `app.debug = True`, `DebuggedApplication(`, `FLASK_DEBUG=1`, `FLASK_ENV=development`
>    - Node.js / Laravel: `app.set('env', 'development')`, `NODE_ENV=development` in deployment files, unconditional `errorhandler()`; `APP_DEBUG=true`, `'debug' => env('APP_DEBUG', true)`, `APP_ENV=local` in a committed `.env`, `TELESCOPE_ENABLED` / `DEBUGBAR_ENABLED`
>    - ASP.NET Core / Rails: `UseDeveloperExceptionPage(`, `UseDatabaseErrorPage(`, `UseMigrationsEndPoint(` outside `IsDevelopment()`, `ASPNETCORE_ENVIRONMENT=Development` in deployment files; `consider_all_requests_local = true` in `production.rb`
>    - Spring / Keycloak: `spring.profiles.active: dev|local` or `SPRING_PROFILES_ACTIVE=dev` in deployment files, `spring.devtools.remote.secret`, `@EnableWebSecurity(debug = true)`; Keycloak `start-dev` in compose/manifests
>
> 2. **Verbose error handling / information leakage**:
>    - Spring: `server.error.include-stacktrace` (`always`, `on_param`), `server.error.include-message: always`, `server.error.include-exception: true`, `server.error.include-binding-errors: always`
>    - Exception handlers that put internals in the response: `@ExceptionHandler` / `@RestControllerAdvice` / Express `(err, req, res, next)` / ASP.NET `UseExceptionHandler` lambdas returning `e.getMessage()`, `getStackTrace`, `printStackTrace(response.getWriter())`, `ExceptionUtils.getStackTrace`, `err.stack`, `err.message`, `traceback.format_exc()`, `ex.ToString()`, `$e->getTraceAsString()`
>    - Banners: Express without `app.disable('x-powered-by')` or helmet, nginx `server_tokens on` (or missing `server_tokens off`), Apache `ServerSignature On` / `ServerTokens Full`, PHP `expose_php = On`, Kestrel `AddServerHeader = true`
>
> 3. **Exposed management / admin / diagnostic surfaces**:
>    - Spring Boot Actuator: `management.endpoints.web.exposure.include` (`*` or lists containing `heapdump`, `env`, `configprops`, `threaddump`, `jolokia`, `gateway`, `shutdown`, `loggers`, `mappings`, `logfile`, `httpexchanges`), `management.endpoint.shutdown.enabled=true` / `access=unrestricted`, `show-values: ALWAYS`, `health.show-details: always`, `management.security.enabled=false` (Boot 1.x), `management.server.port` (note whether it differs from `server.port`), `"/actuator/**").permitAll()`, `EndpointRequest.toAnyEndpoint()).permitAll()`
>    - H2 console: `spring.h2.console.enabled=true`, `spring.h2.console.settings.web-allow-others=true`, `/h2-console/**` in `permitAll()`
>    - API explorers: `springdoc.swagger-ui.enabled`, `springdoc.api-docs.enabled`, `@EnableSwagger2`, `SwaggerModule.setup(`, `swagger-ui-express`, `UseSwaggerUI(`, `drf_spectacular` / `drf_yasg` URLs, GraphQL `introspection: true`, `playground: true`, `graphiql: true`, `spring.graphql.graphiql.enabled=true`
>    - Other diagnostics: `phpinfo(`, Laravel Telescope/Horizon gates returning `true`, Django `admin.site.urls` on the default `admin/` path (low), Go `_ "net/http/pprof"` / `pprof.Register(` / `expvar`, admin tools published in compose (pgAdmin, Adminer, RabbitMQ management 15672, Kibana, Grafana)
>
> 4. **CORS misconfiguration**:
>    - Spring: `@CrossOrigin` (no args or `origins = "*"`), `addCorsMappings(` → `allowedOrigins("*")` / `allowedOriginPatterns("*")`, `setAllowedOriginPatterns(`, `addAllowedOriginPattern("*")`, `allowCredentials(true)` / `setAllowCredentials(true)`, custom filters setting `Access-Control-Allow-Origin` from `request.getHeader("Origin")`, `spring.cloud.gateway.globalcors`
>    - Node.js: `cors()` with no options, `cors({ origin: true` / `origin: '*'` / `origin: (origin, cb) => cb(null, true)`, `credentials: true`, NestJS `enableCors(`, `res.header('Access-Control-Allow-Origin', req.headers.origin)`
>    - Python: `CORS_ALLOW_ALL_ORIGINS = True` / `CORS_ORIGIN_ALLOW_ALL = True`, `CORS_ALLOW_CREDENTIALS`, `CORS_ALLOWED_ORIGIN_REGEXES`, flask-cors `CORS(app, supports_credentials=True)`, FastAPI `CORSMiddleware(allow_origins=["*"], allow_credentials=True)` / `allow_origin_regex`
>    - Go / PHP / C# / Rails: `AllowOriginFunc` returning `true`, `AllowAllOrigins: true`, `Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))`; `config/cors.php` `'allowed_origins' => ['*']` / `allowed_origins_patterns` + `supports_credentials`, `$_SERVER['HTTP_ORIGIN']` echoed; `AllowAnyOrigin()`, `SetIsOriginAllowed(_ => true)`, `SetIsOriginAllowedToAllowWildcardSubdomains()`; `Rack::Cors` `origins '*'` or regex with `credentials: true`
>    - Weak origin validation logic: `endsWith(`, `includes(` / `contains(`, `startsWith(`, unanchored or unescaped regexes, allowlists containing `"null"`; nginx `add_header Access-Control-Allow-Origin $http_origin`; Keycloak realm export `"webOrigins": ["*"]`
>
> 5. **Security controls globally disabled** (note the app's authentication mechanism — `formLogin`, `oauth2Login`, sessions, `httpBasic` vs `oauth2ResourceServer` + `STATELESS` — for Phase 2):
>    - Spring Security: `csrf().disable()`, `csrf(AbstractHttpConfigurer::disable)`, `csrf(c -> c.disable())`, `ignoringRequestMatchers("/**")`, `headers().disable()`, `headers(AbstractHttpConfigurer::disable)`, `frameOptions().disable()` / `frameOptions(f -> f.disable())`, `contentTypeOptions().disable()`, `httpStrictTransportSecurity().disable()`, `anyRequest().permitAll()`, `requestMatchers("/**").permitAll()`, `web.ignoring().requestMatchers("/**")`, `spring.autoconfigure.exclude` containing `SecurityAutoConfiguration` / `ManagementWebSecurityAutoConfiguration`
>    - Django: `@csrf_exempt`, `CsrfViewMiddleware` or `SecurityMiddleware` missing from `MIDDLEWARE`
>    - Rails / Laravel / ASP.NET: `skip_forgery_protection`, `skip_before_action :verify_authenticity_token`, `allow_forgery_protection = false`, `protect_from_forgery with: :null_session` on cookie-authenticated controllers; `VerifyCsrfToken::$except = ['*']` / `validateCsrfTokens(except: ['*'])`; global `IgnoreAntiforgeryTokenAttribute` filter
>
> 6. **Missing security headers / transport hardening** — record ONE candidate per application or entry point, not one per header:
>    - Express / NestJS bootstrap without `helmet` (or `helmet({ contentSecurityPolicy: false, frameguard: false, hsts: false })`); Spring header defaults removed (category 5) or a backend serving HTML without `contentSecurityPolicy`
>    - Django: `SECURE_HSTS_SECONDS` absent/0, `SECURE_SSL_REDIRECT = False`, `SECURE_CONTENT_TYPE_NOSNIFF = False`, `X_FRAME_OPTIONS = 'ALLOWALL'`; ASP.NET: no `UseHsts()` / `UseHttpsRedirection()` in the non-development pipeline; Rails: `config.force_ssl = false` in `production.rb`, CSP initializer absent or commented out
>    - nginx / Apache / ingress: server blocks without `add_header Strict-Transport-Security|Content-Security-Policy|X-Frame-Options|X-Content-Type-Options|Referrer-Policy`, nested `location` blocks with their own `add_header` (drops inherited headers), `listen 80` with no `return 301 https://`, `nginx.ingress.kubernetes.io/ssl-redirect: "false"`, Keycloak realm `"sslRequired": "none"`. For Angular frontends, CSP and `frame-ancestors` belong in the nginx config that serves the bundle
>
> 7. **Insecure defaults and default credentials**:
>    - Seeded accounts: `data.sql`, `import.sql`, Flyway `V*__*.sql`, Liquibase changelogs, Django fixtures / `createsuperuser` scripts, Laravel seeders (`Hash::make('password')`), Rails `db/seeds.rb`, `CommandLineRunner` beans creating admin users, Keycloak realm exports with user `"credentials"`; Spring `spring.security.user.password`, `{noop}` passwords, `User.withDefaultPasswordEncoder()`
>    - Deployment env: `KEYCLOAK_ADMIN_PASSWORD`, `KC_BOOTSTRAP_ADMIN_PASSWORD`, `POSTGRES_PASSWORD`, `MYSQL_ROOT_PASSWORD`, `RABBITMQ_DEFAULT_PASS`, `GF_SECURITY_ADMIN_PASSWORD`, `MONGO_INITDB_ROOT_PASSWORD`, `MINIO_ROOT_PASSWORD`, `PGADMIN_DEFAULT_PASSWORD` set to `admin` / `password` / `postgres` / `guest` / `changeme` or defaulting to them (`${VAR:-admin}`)
>    - Data stores without auth: `POSTGRES_HOST_AUTH_METHOD=trust`, `trust` lines in `pg_hba.conf`, Redis without `requirepass` or with `protected-mode no`, MongoDB without `--auth`, `xpack.security.enabled=false`, `ALLOW_EMPTY_PASSWORD=yes`, `MYSQL_ALLOW_EMPTY_PASSWORD`
>    - Network binding: internal services published on all interfaces (`"5432:5432"`, `"6379:6379"`, `"9200:9200"`, `"27017:27017"`), `bind 0.0.0.0`, `listen_addresses = '*'`
>
> 8. **Static file / directory exposure**:
>    - Directory listing: `serveIndex(` / `serve-index`, `autoindex on`, `Options +Indexes` / `Options Indexes`, `UseDirectoryBrowser(`, `http.FileServer(http.Dir("."))`, Tomcat DefaultServlet `listings` = `true`
>    - Over-broad static roots: `express.static('.')`, `express.static(__dirname)`, `express.static(path.join(__dirname, '..'))`, `process.cwd()`, `spring.web.resources.static-locations` pointing at `file:./` or config directories, `addResourceLocations("file:`, `STATIC_ROOT = BASE_DIR`, nginx `root` at the project directory, `COPY . /usr/share/nginx/html`
>    - Sensitive files under web roots (`public/`, `static/`, `wwwroot/`, `src/main/resources/static/`): `.git/`, `.env`, `*.bak`, `*.sql`, `*.zip`, `*.log`; nginx without `location ~ /\. { deny all; }`
>    - Production source maps (low): Angular `"sourceMap": true` in the `production` configuration, webpack `devtool: 'source-map'` in prod config, Vite `build.sourcemap: true`, Next.js `productionBrowserSourceMaps: true`
>
> 9. **Container / IaC hardening** (lower priority — record them; Phase 2 notes severity):
>    - Dockerfile: no `USER` (or `USER root`) in the final stage, `ENV` / `ARG` with secret-like names (`PASSWORD`, `SECRET`, `TOKEN`, `KEY`) assigned literal values, `chmod 777`
>    - docker-compose: `privileged: true`, `network_mode: host`, `pid: host`, `cap_add` with `SYS_ADMIN` / `ALL`, `/var/run/docker.sock` volumes, `security_opt` with `seccomp:unconfined` / `apparmor:unconfined`; Kubernetes / Helm: `privileged: true`, `allowPrivilegeEscalation: true`, `runAsUser: 0` or no `runAsNonRoot`, `hostNetwork|hostPID|hostIPC: true`, `hostPath` volumes
>    - Debug ports and agents: `-agentlib:jdwp`, `-Xrunjdwp`, `address=*:5005`, `"5005:5005"`, `--inspect=0.0.0.0`, `--inspect-brk`, `"9229:9229"`, `NODE_OPTIONS=--inspect`, `debugpy --listen 0.0.0.0`, `dlv --headless --listen=:2345`, `-Dcom.sun.management.jmxremote.authenticate=false`
>
> **What to skip** (do not flag):
> - Test-only sources that never ship (`src/test/**`, `*_test.go`, `tests/`, `spec/`, `__tests__/`, Testcontainers setup) and files in `.git/`, `node_modules/`, `vendor/`, `target/`, `build/`, `dist/`
> - Settings already at their secure value (`include-stacktrace: never`, `DEBUG = False`, `exposure.include: health`)
> - Sibling-owned settings: cookie flags (sast-authn), XML parser features (sast-xxe), outbound TLS verification (sast-weakcrypto), per-endpoint auth annotations (sast-missingauth), CI pipeline files (sast-cicd), dependency versions (sast-sca)
>
> **Output format** — write to `sast/misconfig-recon.md`:
>
> ```markdown
> # Misconfiguration Recon: [Project Name]
>
> ## Summary
> Found [N] candidate security misconfigurations.
>
> ## Misconfiguration Candidates
>
> ### 1. [Descriptive name — e.g., "Actuator exposes all endpoints in base application.yml"]
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Setting / component**: [property key, method call, directive, or service — e.g., `management.endpoints.web.exposure.include`, `csrf(AbstractHttpConfigurer::disable)`, `keycloak` service in docker-compose]
> - **Category**: [Debug mode / Verbose errors / Management surface / CORS / Disabled security control / Missing headers / Default credentials / File exposure / Container hardening]
> - **Profile / environment**: [Where it appears to apply — e.g., "base application.yml (all profiles unless overridden)", "application-dev.yml (dev only)", "default of `${SWAGGER_ENABLED:true}`", "unconditional in Program.cs", "docker-compose.override.yml", "unknown"]
> - **Auth model note**: [CORS / CSRF candidates only: cookie/session, bearer token, or unknown — as seen in the security config]
> - **Code snippet**:
>   ```
>   [the setting or call plus surrounding lines that show profile guards or conditionals; redact credential values]
>   ```
>
> [Repeat for each candidate]
> ```

### After Phase 1: Check for Candidates Before Proceeding

After Phase 1 completes, read `sast/misconfig-recon.md`. If the recon found **zero candidates** (the summary reports "Found 0" or the "Misconfiguration Candidates" section is empty or absent), **skip Phase 2 entirely**. Instead, write the following content to `sast/misconfig-results.md` and stop:

```markdown
# Security Misconfiguration Analysis Results

No vulnerabilities found.
```

Only proceed to Phase 2 if Phase 1 found at least one candidate.

### Phase 2: Verify — Environment, Reachability, and Impact Analysis (Batched)

After Phase 1 completes, read `sast/misconfig-recon.md` and split the candidates into **batches of up to 3 candidates each**. Launch **one subagent per batch in parallel**. Each subagent verifies only its assigned candidates and writes results to its own batch file.

**Batching procedure** (you, the orchestrator, do this — not a subagent):

1. Read `sast/misconfig-recon.md` and count the numbered candidate sections under "Misconfiguration Candidates" (### 1., ### 2., etc.).
2. Divide them into batches of up to 3. For example, 8 candidates → 3 batches (1-3, 4-6, 7-8).
3. For each batch, extract the full text of those candidate sections from the recon file.
4. Launch all batch subagents **in parallel**, passing each one only its assigned candidates.
5. Each subagent writes to `sast/misconfig-batch-N.md` where N is the 1-based batch number.
6. Identify the project's primary language/framework and deployment tooling from `sast/architecture.md` and select **only the matching examples** from the "Vulnerable vs. Secure Examples" section above. For example, if the project uses Spring Boot with an Angular frontend and docker-compose, include both "Java — Spring Boot" subsections, "TypeScript — Angular", and "Containers / Kubernetes". Include these selected examples in each subagent's instructions where indicated by `[TECH-STACK EXAMPLES]` below.

Give each batch subagent the following instructions (substitute the batch-specific values):

> **Goal**: For each assigned misconfiguration candidate, determine whether the insecure setting is active in an environment an attacker can reach, what concrete impact it gives, and whether a compensating control neutralizes it. Our goal is to find security misconfiguration vulnerabilities. Write results to `sast/misconfig-batch-[N].md`.
>
> **Your assigned candidates** (from the recon phase):
>
> [Paste the full text of the assigned candidate sections here, preserving the original numbering]
>
> **Context**: You will be given the project's architecture summary. Use it to understand the deployment model (which artifacts reach production), how profiles and environment variables are set, what sits in front of the application (reverse proxy, ingress, API gateway), and whether users authenticate with cookies or bearer tokens.
>
> **For each candidate, answer THREE questions, then check mitigations:**
>
> **Question 1: Which environment does this setting apply to?** Resolve the effective configuration before judging:
> - **Spring Boot**: base `application.yml` / `.properties` applies to ALL profiles unless `application-<profile>.yml` overrides the same key; multi-document YAML sections apply only under `spring.config.activate.on-profile`; `@Profile("dev")` / `@ConditionalOnProperty` gate beans. Find `spring.profiles.active` / `SPRING_PROFILES_ACTIVE` in config files, Dockerfile `ENV`, compose `environment:`, Kubernetes/Helm values. Environment variables and command-line args override files.
> - **Placeholder defaults**: `${SWAGGER_ENABLED:true}`, `DEBUG=${DEBUG:true}`, `os.environ.get('DEBUG', 'True')`, `env('APP_DEBUG', true)`, `${VAR:-admin}` are insecure unless the deployment sets the variable — search the manifests for the override.
> - **Node.js / Angular**: Express treats an unset `NODE_ENV` as `development` — check that the Dockerfile/compose/manifest sets `NODE_ENV=production`. For Angular, read the `production` configuration in `angular.json`. **Django / Flask**: which settings module is loaded (`DJANGO_SETTINGS_MODULE` in `manage.py`, `wsgi.py`, `asgi.py`, Dockerfile); `app.run(debug=True)` under `if __name__ == '__main__':` only runs when the container starts `python app.py`, not under gunicorn/uwsgi.
> - **ASP.NET Core / Laravel / Rails**: `IsDevelopment()` guards and `ASPNETCORE_ENVIRONMENT` in deployment files (`launchSettings.json` is local-only); committed `.env` vs `.env.example` and `config/app.php` defaults; `config/environments/production.rb` vs `development.rb`.
> - **Containers**: `docker-compose.yml` vs `docker-compose.override.yml` (auto-merged for local runs) vs `docker-compose.prod.yml`; does `sast/architecture.md` say compose is the production/staging deployment or local dev only? Kubernetes manifests and Helm charts are production artifacts unless clearly under `local/`, `dev/`, or `kind/`.
> - Outcome: confined to dev/test with a secure production value → Not Vulnerable (name the guarding profile/file); insecure default with no production override found → Likely Vulnerable; active in production → continue.
>
> **Question 2: Can an attacker reach the surface?**
> - Port and binding: public application port vs a separate `management.server.port`; compose `ports:` (published) vs `expose:`; `127.0.0.1:` bindings; Kubernetes Service type (ClusterIP vs NodePort/LoadBalancer) and Ingress paths.
> - Path filtering: reverse proxy / ingress rules that deny `/actuator`, `/h2-console`, `/swagger-ui`, `/debug/pprof`, `/.git`.
> - Framework auth: which `SecurityFilterChain` matcher covers the path — `permitAll()`, `authenticated()`, or a role? With Spring Security on the classpath and no custom chain, Boot secures Actuator by default except `health`. H2 console `web-allow-others: false` (default) limits it to local connections — but a reverse proxy on the same host makes remote requests look local.
> - Auth model for CORS/CSRF: does the browser attach credentials automatically (session cookie, `formLogin`, `oauth2Login`, BFF/gateway session, HTTP Basic)? If the API only accepts `Authorization: Bearer` tokens held by the SPA, credentialed CORS and disabled CSRF have little or no impact.
>
> **Question 3: What concrete impact does the exposure give?** State the specific attacker outcome and whether it is directly exploitable or defense-in-depth:
> - `/actuator/heapdump` → memory dump with DB passwords, Keycloak client secrets, signing keys, live session and bearer tokens; `env` / `configprops` → configuration secrets (Boot 3 masks values unless `show-values: ALWAYS`; Boot 2 masks only key-name matches); `/actuator/jolokia`, `/actuator/gateway` (Spring Cloud Gateway route injection, CVE-2022-22947), `POST /actuator/env` + `/refresh` → RCE chains; `shutdown` → DoS; `loggers` → log tampering
> - H2 console → attacker-chosen JDBC URL / `CREATE ALIAS` → RCE; Werkzeug console → Python RCE; JDWP (5005), Node inspector (9229), `debugpy` → RCE; Laravel `APP_DEBUG` → env disclosure including `APP_KEY` (cookie forgery, deserialization RCE)
> - Django `DEBUG`, ASP.NET developer exception page, Rails local requests, verbose Spring errors → stack traces, SQL, file paths, settings, library versions (disclosure that eases other attacks)
> - Reflected origin + credentials + cookie auth → attacker site reads authenticated API responses (account data, CSRF tokens); disabled CSRF + cookie auth → forged state-changing requests
> - Missing CSP / HSTS / frame-ancestors / nosniff → clickjacking, SSL stripping, MIME sniffing; no CSP amplifies any XSS. Default credentials → admin takeover (Keycloak master-realm admin controls every realm and client); Postgres `trust`, Redis without auth, Elasticsearch without security on a reachable port → full data access (Redis can escalate to RCE)
> - `.git` / `.env` / backups served → source, history, secrets; source maps → readable frontend source (low); Swagger / GraphQL introspection → API map (low unless endpoints are also unauthenticated)
> - Root or privileged containers, Docker socket, `hostNetwork` → container escape or host takeover after an initial foothold (defense-in-depth); secrets in `ENV`/`ARG` → readable by anyone who can pull the image
>
> **Mitigations / compensating controls** (check even if the setting is active and reachable):
> - Authentication on the surface: Actuator restricted via `EndpointRequest` + role, Telescope/Horizon gates, Swagger behind auth. Network isolation: management port not published, loopback binding, NetworkPolicy, internal/VPN-only deployment documented in `sast/architecture.md`
> - Proxy or gateway rules that block the path or add the missing headers (if the ingress sets HSTS and CSP for this host, missing app-level headers are Not Vulnerable)
> - Partial controls are not enough: Basic auth with default credentials, IP allowlists containing `0.0.0.0/0`, origin checks using `endsWith` / `contains` → still Likely Vulnerable
>
> **Vulnerable vs. Secure examples for this project's tech stack**:
>
> [TECH-STACK EXAMPLES]
>
> **Classification**:
> - **Vulnerable**: The insecure setting is demonstrably active in a deployed environment (base config, production profile/manifest, or unconditional code), the surface is reachable, and no compensating control is in place.
> - **Likely Vulnerable**: The setting is insecure by default and no production override was found, the active profile or reachability is probable but not proven, or only a weak compensating control exists.
> - **Not Vulnerable**: The setting is confined to dev/test (name the guarding profile/file), is overridden securely for production, is unreachable, or is correct for the context (e.g., CSRF disabled on a stateless bearer-token API).
> - **Needs Manual Review**: Cannot determine the effective environment or reachability from the repository (production env vars, profiles, or proxy rules live outside the repo).
>
> **Output format** — write to `sast/misconfig-batch-[N].md`:
>
> ```markdown
> # Security Misconfiguration Batch [N] Results
>
> ## Findings
>
> ### [VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Setting / component**: [property key, method call, directive, or service]
> - **Issue**: [e.g., "`management.endpoints.web.exposure.include=*` in base application.yml exposes /actuator/heapdump unauthenticated on the public port"]
> - **Evidence trace**: [Step-by-step: where the setting is defined → how the effective profile/environment resolves (file:line of profile activation and any overrides) → why the surface is reachable (port, security matcher, ingress) → which compensating controls are absent]
> - **Impact**: [Concrete attacker outcome; say whether it is directly exploitable or defense-in-depth]
> - **Remediation**: [Exact config or code change, and in which file/profile]
> - **Dynamic Test**:
>   ```
>   [curl / nmap commands with the expected signal. Examples:
>    curl -s https://app.example.com/actuator/heapdump -o hd && strings hd | grep -iE 'password|secret|bearer'
>    curl -s -I -H "Origin: https://evil.example" -H "Cookie: SESSION=<valid>" https://app.example.com/api/me
>      → expect Access-Control-Allow-Origin: https://evil.example and Access-Control-Allow-Credentials: true
>    curl -s -X POST -H 'Content-Type: application/json' -d '{' https://app.example.com/api/orders → stack trace in body
>    curl -sI https://app.example.com/ | grep -iE 'strict-transport|content-security|x-frame|x-content-type|referrer-policy'
>    nmap -p 5005,9229,5432,6379,9200 app.example.com → open debug or data-store ports]
>   ```
>
> ### [LIKELY VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Setting / component**: [property key, method call, directive, or service]
> - **Issue**: [e.g., "Insecure default `${SWAGGER_ENABLED:true}` with no production override found in the repo"]
> - **Evidence trace**: [Best-effort trace; mark uncertain steps, e.g., "production profile not set in any manifest"]
> - **Concern**: [Why it remains a risk]
> - **Remediation**: [Secure the default and set the value explicitly for production]
> - **Dynamic Test**:
>   ```
>   [request that confirms whether the surface is live, e.g., curl -s https://app.example.com/v3/api-docs]
>   ```
>
> ### [NOT VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Setting / component**: [property key, method call, directive, or service]
> - **Reason**: [e.g., "Only in application-dev.yml; production profile set in k8s/deployment.yaml:23 does not enable it" or "CSRF disabled on a stateless JWT resource server — no cookie authentication"]
>
> ### [NEEDS MANUAL REVIEW] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Setting / component**: [property key, method call, directive, or service]
> - **Uncertainty**: [Why the effective environment or reachability could not be determined]
> - **Suggestion**: [What to check manually — e.g., "Confirm SPRING_PROFILES_ACTIVE in the production deployment pipeline"]
> ```

### Phase 3: Merge — Consolidate Batch Results

After **all** Phase 2 batch subagents complete, read every `sast/misconfig-batch-*.md` file and merge them into a single `sast/misconfig-results.md`. You (the orchestrator) do this directly — no subagent needed.

**Merge procedure**:

1. Read all `sast/misconfig-batch-1.md`, `sast/misconfig-batch-2.md`, ... files.
2. Collect all findings from each batch file and combine them into one list, preserving the original classification and all detail fields.
3. Count totals across all batches for the executive summary (candidates analyzed = total candidates from recon that were batched, i.e., sum of candidates across batches).
4. Write the merged report to `sast/misconfig-results.md` using this format:

```markdown
# Security Misconfiguration Analysis Results: [Project Name]

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

5. After writing `sast/misconfig-results.md`, **delete all intermediate batch files** (`sast/misconfig-batch-*.md`). Do not delete `sast/misconfig-recon.md`.

---

## Important Reminders

- Read `sast/architecture.md` and pass its content to all subagents as context.
- Phase 2 must run AFTER Phase 1 completes — it depends on the recon output.
- Phase 3 must run AFTER all Phase 2 batches complete — it depends on all batch outputs.
- Batch size is **3 candidates per subagent**. If there are 1-3 candidates total, use a single subagent. If there are 10, use 4 subagents (3+3+3+1).
- Launch all batch subagents **in parallel** — do not run them sequentially.
- Each batch subagent receives only its assigned candidates' text from the recon file, not the entire recon file. This keeps each subagent's context small and focused.
- **Phase 1 is purely structural**: flag every risky setting, call, or deployment artifact regardless of profile or environment. Do not decide whether it is active in production in Phase 1 — that is Phase 2's job.
- **Phase 2 is purely verification**: for each assigned candidate, resolve the effective environment, confirm reachability, state the concrete impact, and check for compensating controls.
- When in doubt, classify as "Needs Manual Review" rather than "Not Vulnerable". False negatives are worse than false positives in security assessment.
- **Always resolve the effective profile before judging.** A setting in base `application.yml` / `application.properties` applies to ALL profiles unless a profile-specific file overrides it; a setting in `application-dev.yml` applies only when `dev` is active. Find where `SPRING_PROFILES_ACTIVE`, `NODE_ENV`, `DJANGO_SETTINGS_MODULE`, `ASPNETCORE_ENVIRONMENT`, `APP_ENV`, or `RAILS_ENV` is set for the deployed artifact; if that lives outside the repository, classify Needs Manual Review (or Likely Vulnerable for insecure defaults) — never Not Vulnerable on assumption.
- **Insecure placeholder defaults are findings**: `${DEBUG:true}`, `os.environ.get('DEBUG', 'True')`, `env('APP_DEBUG', true)`, `${VAR:-admin}` are insecure unless the deployment sets the variable — classify Likely Vulnerable when no production override is found. Dev/test-only settings are Not Vulnerable, but say which profile or file confines them.
- **`csrf().disable()` is correct for pure bearer-token APIs** (`oauth2ResourceServer` + `STATELESS`, no cookie auth). It is a finding only when the app authenticates with cookies — `formLogin`, `oauth2Login`, server-side sessions, a BFF/gateway holding the Keycloak session, or browser HTTP Basic.
- **CORS impact depends on credentials**: `Access-Control-Allow-Origin: *` without credentials does not let an attacker read cookie-authenticated responses. Any/reflected origin + `Allow-Credentials: true` + cookie auth is the high-impact case. Spring rejects `allowedOrigins("*")` + `allowCredentials(true)` at runtime and ASP.NET rejects `AllowAnyOrigin()` + `AllowCredentials()`, but `allowedOriginPatterns("*")` and `SetIsOriginAllowed(_ => true)` silently reflect every origin — flag those.
- **Keycloak-fronted apps still need CORS checked on the resource server**: Keycloak handles login, but the Spring backend emits its own CORS headers on API responses. Check the backend `CorsConfigurationSource` / `@CrossOrigin` / gateway `globalcors` and the Keycloak client's `webOrigins` separately.
- **One finding per distinct misconfiguration**: group all missing headers for one application or entry point into a single finding, and treat one Actuator exposure property as one finding (name the most dangerous endpoints in Impact) — never one finding per header or per endpoint.
- **Container / IaC hardening is mostly defense-in-depth**: running as root, `privileged`, and missing `securityContext` matter after another foothold — say so in Impact. Exposed JDWP/inspector ports and unauthenticated data stores on published ports are directly exploitable — say that too.
- **Redact credential values** in snippets, except well-known defaults (`admin`, `postgres`, `guest`) whose presence is itself the finding.
- Clean up intermediate files: delete all `sast/misconfig-batch-*.md` files after the final `sast/misconfig-results.md` is written. **Preserve** `sast/misconfig-recon.md` — the orchestrator reuses it on later runs.
