---
name: sast-logging
description: >-
  Detect security logging and monitoring failures (OWASP A09:2021) in a
  codebase using a three-phase approach: recon (find logging sinks, request
  logging configuration, and security event handlers), batched verify
  (sensitivity, log-injection taint, and audit-coverage analysis in parallel
  subagents, 3 candidates each), and merge (consolidate batch results). Covers
  credentials, tokens and PII written to logs (CWE-532), CRLF log forging
  (CWE-117), missing or incomplete security-event logging (CWE-778, CWE-223),
  and swallowed errors in security-critical code. Requires sast/architecture.md
  (run sast-analysis first). Outputs findings to sast/logging-results.md. Use
  when asked to find sensitive data in logs, log injection, or missing audit
  logging.
---

# Security Logging & Monitoring Failure Detection

You are performing a focused security assessment to find security logging and monitoring failures in a codebase. This skill uses a three-phase approach with subagents: **recon** (find logging sinks, request/response logging configuration, and security event handlers), **batched verify** (sensitivity, log-injection taint, and audit-coverage analysis in parallel batches of 3), and **merge** (consolidate batch reports into one file).

**Prerequisites**: `sast/architecture.md` must exist. Run the analysis skill first if it doesn't.

---

## What is a Security Logging & Monitoring Failure

Security logging and monitoring failures (OWASP A09:2021) occur when an application writes data to its logs that must never be stored there, writes attacker-controlled data in a way that lets the attacker forge log entries, or fails to record the security events that defenders need to detect and investigate an attack. Logs are routinely shipped to ELK/Loki/Splunk, retained for months, and read by far more people than the production database — a password or token in a log line is a credential leak. Conversely, a brute-force attack or privilege escalation that leaves no log record cannot be detected or reconstructed. Relevant CWEs: CWE-532 (sensitive information in log file), CWE-117 (improper output neutralization for logs), CWE-778 (insufficient logging), CWE-223 (omission of security-relevant information).

The core pattern: *sensitive data or unneutralized user input reaches a log sink that is active in production, or a security-relevant event reaches no log sink at all.*

### What a Logging Failure IS

- Writing credentials, tokens, or secrets into a log call: `log.info("Login user={} password={}", user, password)`
- Logging whole request, DTO, entity, or `Authentication` objects whose `toString()` / serializer includes password, token, or card fields: `log.debug("Received {}", loginRequest)` on a Lombok `@Data` class
- Framework request/response logging that dumps bodies and headers (`Authorization`, `Cookie`): `CommonsRequestLoggingFilter` with `setIncludePayload(true)` / `setIncludeHeaders(true)`, morgan with a body token, OkHttp `Level.BODY`
- Production profiles that enable DEBUG/TRACE loggers emitting bound SQL values or HTTP wire data: `org.hibernate.orm.jdbc.bind=TRACE`, `org.apache.http.wire=DEBUG`, `logging.level.org.springframework.web=DEBUG`
- PII (national ID, IBAN, full PAN, date of birth, address, phone) written at INFO or above in production
- Log forging: user input containing CR/LF written into a plaintext (pattern layout) log, producing fake entries
- Missing audit logging for security events: login failure, authorization denial, password reset, role change, or admin action with no log record (CWE-778), or a record missing who/what/outcome (CWE-223)
- Swallowed errors in security-critical code: an empty `catch` around signature verification, token decoding, payment confirmation, or an audit write
- Log files written into web-served directories (`static/`, `public/`, `wwwroot/`)

### What a Logging Failure is NOT

Do not flag these as logging failures:

- **Verbose error responses / stack traces returned to the client**: information disclosure in HTTP responses — owned by **sast-misconfig**
- **Spring Boot Actuator `loggers` / `logfile` endpoint exposure**: misconfigured management endpoints — owned by **sast-misconfig**
- **Log4Shell (CVE-2021-44228) and other vulnerable logging library versions**: dependency vulnerabilities — owned by **sast-sca**
- **XSS in general**: owned by **sast-xss**. Exception: forged log entries rendered unescaped by an in-app HTML log viewer are reported here as the impact of log injection
- **Secrets hardcoded as literals in client-side code**: owned by **sast-hardcodedsecrets**. This skill flags secrets that flow into logs at runtime
- **Logging identifiers and request metadata**: user ID, order ID, correlation ID, HTTP method, path, status, duration — these are not sensitive; do not flag
- **DEBUG/TRACE statements whose level is disabled in every production profile**: report as Not Vulnerable with the resolved level, not as a finding

### Patterns That Prevent Logging Failures

When you see these patterns, the code is likely **not vulnerable** for the corresponding issue:

**1. Masking / redaction at the logging layer**
```
# Java — logstash-logback-encoder masking (path masks cover JSON fields; value masks cover text inside messages)
<encoder class="net.logstash.logback.encoder.LogstashEncoder">
  <jsonGeneratorDecorator class="net.logstash.logback.mask.MaskingJsonGeneratorDecorator">
    <defaultMask>****</defaultMask>
    <path>password</path>
    <path>authorization</path>
    <value>(?i)bearer\s+[A-Za-z0-9._~+/-]+=*</value>
  </jsonGeneratorDecorator>
</encoder>
# Node.js — pino({ redact: { paths: ['req.headers.authorization', '*.password', '*.token'], censor: '[REDACTED]' } })
# Python — a logging.Filter attached to handlers that rewrites record.msg / record.args with a redaction regex
# Rails — config.filter_parameters covering every sensitive key (applies to request parameter logs and inspect)
# C# — Serilog destructuring policy
.Destructure.ByTransforming<LoginRequest>(r => new { r.Username })
```

**2. Structured JSON logging or CR/LF encoding (prevents log forging)**
```
# Java — JSON encoder escapes \r and \n inside values: <encoder class="net.logstash.logback.encoder.LogstashEncoder"/>
# Java — plaintext Logback / Log4j2 patterns with CR/LF neutralized: %replace(%msg){'[\r\n]','_'}%n  /  %enc{%m}{CRLF}%n
# Node.js — pino / winston.format.json(); Python — structlog JSONRenderer; Go — slog.NewJSONHandler; C# — CompactJsonFormatter
```
JSON logging prevents forging, but **not** sensitive-data leakage — a password inside a JSON field is still a leak.

**3. Allowlisted MDC fields and identifiers instead of objects**
```java
MDC.put("userId", principal.getId().toString());   // an identifier, never the token or Authentication object
log.info("Order placed [orderId={}, amount={}]", order.getId(), order.getAmount());
// logback: <includeMdcKeyName>correlationId</includeMdcKeyName> on LogstashEncoder allowlists the MDC keys emitted
```

**4. `toString()` / serializers that exclude secrets**
```java
// Lombok — exclude from generated toString(); Jackson — never serialize back out
@Data
public class LoginRequest {
    private String username;
    @ToString.Exclude @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    private String password;
}
// Records include every component in toString() — override it
public record TokenResponse(String accessToken, String refreshToken) {
    @Override public String toString() { return "TokenResponse[****]"; }
}
```
```typescript
class UserEntity { password!: string; toJSON() { const { password, ...rest } = this; return rest; } }
```

**5. Centralized security-event audit logger**
```java
// Spring Boot auto-registers an AuthenticationEventPublisher; authorization events need an AuthorizationEventPublisher bean
@Component
class SecurityAuditListener {
    private static final Logger audit = LoggerFactory.getLogger("SECURITY_AUDIT");
    @EventListener void onFailure(AbstractAuthenticationFailureEvent e) {
        audit.warn("auth.failure [user={}, reason={}]", e.getAuthentication().getName(),
                   e.getException().getClass().getSimpleName());
    }
    @EventListener void onDenied(AuthorizationDeniedEvent<?> e) {
        audit.warn("authz.denied [user={}]", e.getAuthentication().get().getName());
    }
    // plus AuthenticationSuccessEvent, LogoutSuccessEvent, and domain events (role change, password reset)
}
```

---

## Vulnerable vs. Secure Examples

### Java — Spring Boot (SLF4J / Logback): log statements, DTOs, and MDC

```java
// VULNERABLE: credential written directly into the log message
@PostMapping("/auth/login")
public TokenResponse login(@RequestBody LoginRequest req) {
    log.info("Login attempt user={} password={}", req.getUsername(), req.getPassword());
    TokenResponse tokens = authService.login(req);
    log.debug("Issued {}", tokens);               // record toString(): accessToken + refreshToken
    return tokens;
}
// VULNERABLE: Lombok @Data generates toString() with every field
@Data
public class LoginRequest { private String username; private String password; }
log.debug("Received {}", loginRequest);           // LoginRequest(username=bob, password=...)
log.info("Saved {}", customer);                   // JPA entity: iban, nationalId, dateOfBirth
// VULNERABLE: secret placed in MDC is emitted on every subsequent log line
MDC.put("authToken", request.getHeader("Authorization"));
// VULNERABLE: message embeds the JDBC URL with credentials
catch (SQLException e) { log.error("Cannot connect to " + dataSourceUrl, e); }

// SECURE: identifiers only; LoginRequest.password has @ToString.Exclude (see "Patterns That Prevent" #4)
log.info("Login attempt [username={}]", req.getUsername());
log.info("Customer saved [customerId={}]", customer.getId());
MDC.put("userId", principal.getId().toString());
```

### Java — Spring Boot: request logging filters, HTTP client wire logging, production log levels

```java
// VULNERABLE: dumps request bodies (passwords, card data), headers (Authorization, Cookie), query strings (?token=)
@Bean
public CommonsRequestLoggingFilter requestLoggingFilter() {
    CommonsRequestLoggingFilter f = new CommonsRequestLoggingFilter();
    f.setIncludePayload(true);
    f.setMaxPayloadLength(10000);
    f.setIncludeHeaders(true);
    f.setIncludeQueryString(true);
    return f;
}
// VULNERABLE: custom OncePerRequestFilter (doFilterInternal) logs the cached body of every request
ContentCachingRequestWrapper wrapped = new ContentCachingRequestWrapper(req);
chain.doFilter(wrapped, res);
log.info("{} {} body={}", req.getMethod(), req.getRequestURI(), new String(wrapped.getContentAsByteArray(), UTF_8));
// VULNERABLE: full wire logging of outbound calls (bearer tokens, client_secret in token requests)
HttpClient.create().wiretap("reactor.netty.http.client.HttpClient", LogLevel.DEBUG, AdvancedByteBufFormat.TEXTUAL);
new HttpLoggingInterceptor().setLevel(HttpLoggingInterceptor.Level.BODY);         // OkHttp

// SECURE: no payload; sensitive headers masked; method/path/status/duration only
f.setIncludePayload(false);
f.setHeaderPredicate(h -> !Set.of("authorization", "cookie", "x-api-key").contains(h.toLowerCase()));
HttpLoggingInterceptor i = new HttpLoggingInterceptor().setLevel(HttpLoggingInterceptor.Level.BASIC);
i.redactHeader("Authorization");
```

```yaml
# VULNERABLE: application-prod.yml (or base application.yml with no prod override)
spring:
  jpa:
    show-sql: true                        # SQL to stdout, bypassing the logging configuration
  mvc:
    log-request-details: true             # unmasks parameters and headers in web DEBUG logs
logging:
  level:
    org.springframework.web: DEBUG        # logs deserialized @RequestBody via the DTO's toString()
    org.springframework.security: TRACE
    org.hibernate.orm.jdbc.bind: TRACE    # bound values: password hashes, PII, tokens (Hibernate 6)
    org.hibernate.type.descriptor.sql.BasicBinder: TRACE   # same, Hibernate 5
    org.apache.http.wire: DEBUG           # raw HTTP client traffic including Authorization headers

# SECURE: application-prod.yml
spring.jpa.show-sql: false
logging.level.root: INFO
logging.level.org.hibernate.orm.jdbc.bind: OFF
```

### TypeScript / Node.js — Express / NestJS

```typescript
// VULNERABLE: morgan custom token dumps the whole request body
morgan.token('body', (req: Request) => JSON.stringify(req.body));
app.use(morgan(':method :url :status :body'));
// VULNERABLE: winston / pino / console with no redaction
logger.info('login', { body: req.body, headers: req.headers });   // winston, no redact format
app.use(pinoHttp());       // default req serializer logs all headers, including authorization and cookie
console.log('login payload', req.body);
this.logger.debug(`register ${JSON.stringify(dto)}`);             // NestJS Logger: DTO with password
axios.interceptors.request.use((cfg) => { console.log('outbound', cfg); return cfg; });  // Authorization, client_secret

// SECURE: pino redact paths, identifiers instead of objects, morgan without body
app.use(pinoHttp({ redact: { paths: ['req.headers.authorization', 'req.headers.cookie', '*.password',
  '*.token', '*.refreshToken', '*.cardNumber'], censor: '[REDACTED]' } }));
app.use(morgan(':method :url :status :response-time ms'));
this.logger.log(`user registered userId=${user.id}`);
```

### TypeScript — Angular (frontend, lower severity)

```typescript
// VULNERABLE (lower severity): tokens / user objects in the prod console — seen by extensions, error-tracking SDKs
console.log('token', this.auth.getAccessToken());
console.log('current user', user);                      // iban, nationalId, dateOfBirth
console.debug('auth header', req.headers.get('Authorization'));   // inside an HttpInterceptor

// SECURE: environment-gated logger service that is only ever passed identifiers
@Injectable({ providedIn: 'root' })
export class LoggerService {
  debug(msg: string, ctx?: Record<string, string | number>): void { if (!environment.production) console.debug(msg, ctx); }
}
this.logger.debug('user loaded', { userId: user.id });
```

### Python — Django / Flask

```python
# VULNERABLE
logger.info(f"login {username} {password}")
logging.debug(request.headers)                            # Authorization, Cookie
app.logger.info("payment %s", request.get_json())         # card number, cvv
LOGGING = {"loggers": {"django.db.backends": {"level": "DEBUG", "handlers": ["console"]}}}
# with DEBUG=True in production settings: every SQL query is logged with its parameters
logger.info("Search query: %s", request.args["q"])      # plaintext Formatter: CR/LF log forging

# SECURE
logger.info("login attempt username=%s", username)
logger.info("Search query: %r", request.args["q"])      # repr() escapes \r and \n
logger.debug("headers %s", {k: v for k, v in request.headers.items() if k.lower() not in {"authorization", "cookie"}})
```

### Go — net/http

```go
// VULNERABLE: %+v prints every struct field, including Password and Token
log.Printf("login request: %+v", req)
log.Printf("headers: %v", r.Header)                       // Authorization, Cookie

// SECURE: slog with a LogValuer that redacts secrets
func (r LoginRequest) LogValue() slog.Value {
    return slog.GroupValue(slog.String("username", r.Username), slog.String("password", "[REDACTED]"))
}
slog.Info("login request", "req", req)
```

### PHP — Laravel

```php
// VULNERABLE
Log::info('Login attempt', $request->all());              // password, _token
Log::debug('Payment', ['card' => $request->input('card_number')]);

// SECURE
Log::info('Login attempt', $request->except(['password', 'password_confirmation', '_token']));
public function login(string $username, #[\SensitiveParameter] string $password) { /* hidden in stack traces */ }
```

### C# — ASP.NET Core

```csharp
// VULNERABLE: Serilog destructuring {@...} serializes every public property, including Password
_logger.LogInformation("Login {@Request}", request);
// VULNERABLE: HTTP logging of bodies, with Authorization added to the header allowlist
builder.Services.AddHttpLogging(o => { o.LoggingFields = HttpLoggingFields.All; o.RequestHeaders.Add("Authorization"); });

// SECURE
_logger.LogInformation("Login attempt for {Username}", request.Username);
builder.Services.AddHttpLogging(o => o.LoggingFields =
    HttpLoggingFields.RequestPropertiesAndHeaders | HttpLoggingFields.ResponsePropertiesAndHeaders);
```

### Ruby on Rails

```ruby
# VULNERABLE: filter list misses keys this app uses; otp_code, api_key, card_number appear in request logs
Rails.application.config.filter_parameters += [:password]
Rails.logger.info("Signup params: #{params.to_unsafe_h}")   # bypasses filter_parameters entirely

# SECURE
Rails.application.config.filter_parameters += [:passw, :secret, :token, :_key, :otp, :crypt, :ssn, :card_number, :cvv, :iban]
Rails.logger.info("Signup user_id=#{user.id}")
```

### Log Injection — Plaintext Pattern Layouts (all stacks)

```xml
<!-- VULNERABLE: logback-spring.xml plaintext pattern; %msg and %X{} are written raw -->
<encoder><pattern>%d %-5level [%X{correlationId}] %logger - %msg%n</pattern></encoder>
<!-- SECURE (plaintext): strip CR/LF from message and MDC values -->
<encoder><pattern>%d %-5level [%replace(%X{correlationId}){'[\r\n]','_'}] %logger - %replace(%msg){'[\r\n]','_'}%n</pattern></encoder>
<!-- SECURE (preferred): JSON encoder escapes control characters -->
<encoder class="net.logstash.logback.encoder.LogstashEncoder"/>
<PatternLayout pattern="%d %p %c - %m%n"/>                 <!-- VULNERABLE: log4j2.xml -->
<PatternLayout pattern="%d %p %c - %enc{%m}{CRLF}%n"/>     <!-- SECURE -->
```

```java
// VULNERABLE: request value in a plaintext log; SLF4J {} placeholders do NOT encode CR/LF
log.warn("Failed login for user {}", request.getParameter("username"));
// payload: username=admin%0d%0a2026-10-09 10:00:00 INFO AuthService - Login success user=admin
// VULNERABLE: unvalidated header copied into MDC, printed by %X{correlationId} on every line
MDC.put("correlationId", request.getHeader("X-Request-ID"));
```

### Missing Security Event Logging (all stacks)

```java
// VULNERABLE: failed login and authorization denial handled with no record of who, from where, or why
http.formLogin(f -> f.failureHandler((req, res, ex) -> res.sendError(401)))
    .exceptionHandling(e -> e.accessDeniedHandler((req, res, ex) -> res.sendError(403)));

// SECURE: outcome-rich audit record (or a central listener, see "Patterns That Prevent" #5)
audit.warn("auth.failure [username={}, ip={}, reason={}, correlationId={}]", sanitize(req.getParameter("username")),
           req.getRemoteAddr(), ex.getClass().getSimpleName(), MDC.get("correlationId"));
```

```typescript
// VULNERABLE: NestJS guard denies silently; privilege change is not audited
if (!user.roles.includes('ADMIN')) throw new ForbiddenException();
await this.users.update(id, { roles: dto.roles });

// SECURE
this.audit.record({ event: 'authz.denied', userId: user.id, resource: req.path, ip: req.ip });
this.audit.record({ event: 'user.roles.changed', actorId: admin.id, targetId: id, roles: dto.roles });
```

### Swallowed Errors in Security-Critical Code (all stacks)

```java
// VULNERABLE: verification exception swallowed — execution continues as if the signature were valid
boolean valid = true;
try { valid = verifier.verify(payload, signatureHeader); } catch (SignatureException e) { }
if (valid) { webhookService.process(payload); }

// SECURE: fail closed and log
try { if (!verifier.verify(payload, signatureHeader)) throw new SignatureException("mismatch"); }
catch (SignatureException e) {
    log.warn("webhook.signature.invalid [source={}]", req.getRemoteAddr());
    throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
}
webhookService.process(payload);
```

```python
# VULNERABLE: bare except — request proceeds without verified claims
try:
    claims = jwt.decode(token, key, algorithms=["RS256"])
except Exception:
    pass
return view(request)
# SECURE
except jwt.InvalidTokenError as e:
    logger.warning("token.invalid reason=%s ip=%s", type(e).__name__, request.META.get("REMOTE_ADDR"))
    return HttpResponse(status=401)
```

```typescript
// VULNERABLE: audit write failure silently discarded — the audit trail has gaps nobody notices
try { await this.audit.write(event); } catch {}
```

---

## Execution

This skill runs in three phases using subagents. Pass the contents of `sast/architecture.md` to all subagents as context.

**Cache reuse**: If `sast/logging-recon.md` already exists, skip Phase 1 and reuse it. If `sast/sinks-index.md` exists, pass its `## sast-logging` section to the Phase 1 subagent as a starting list of candidate sites — the subagent must still search beyond it, since the index is regex-based and incomplete.

### Phase 1: Recon — Find Logging Sinks and Security Event Handlers

Launch a subagent with the following instructions:

> **Goal**: Find every location in the codebase where a log call may write sensitive data or unneutralized user input, every framework-level setting that logs requests/responses or raw SQL/HTTP traffic, every security event handler (recording whether it logs), every silenced error in security-critical code, and every log file location. Write results to `sast/logging-recon.md`.
>
> **Context**: You will be given the project's architecture summary. Use it to understand the tech stack, logging framework (SLF4J/Logback, Log4j2, winston, pino, Python `logging`, Serilog, `slog`), configuration files and per-environment profiles, the authentication mechanism, and security-relevant flows. If you are given the `## sast-logging` section of `sast/sinks-index.md`, start from it but search beyond it — the index is regex-based and incomplete.
>
> **What to search for**:
>
> Flag candidates structurally. Do not decide yet whether a value is truly sensitive, whether the level is enabled in production, or whether input is user-controlled — that is Phase 2's job. Do NOT skip DEBUG/TRACE statements or dev-profile settings; record them with their level. Group an identical pattern repeated across many files (e.g., the same `log.debug("{}", dto)` in every controller) into one candidate that lists every location.
>
> First, record a **logging configuration overview**: logging framework(s), config files (`logback.xml`, `logback-spring.xml`, `log4j2*.xml`, `application*.yml|properties`, `appsettings*.json`, Django `LOGGING`, winston/pino setup), appenders/encoders and patterns, root and package levels per profile/environment, and redaction mechanisms present.
>
> 1. **Log calls with sensitive-named arguments or whole objects** — logger APIs: `log.*`/`logger.*`/`LOGGER.*` (SLF4J, Log4j2, Python), `console.*`, `System.out.println`, `print`, `log.Print*`/`slog.*`/zap/logrus, `Log::*`/`error_log`, `_logger.Log*`/`Log.Information`, `Rails.logger.*`. Flag when an argument, interpolated value, or MDC value:
>    - Has a name matching: `password`, `passwd`, `pwd`, `secret`, `token`, `accessToken`, `refreshToken`, `authorization`, `cookie`, `session`, `apiKey`, `otp`, `pin`, `cvv`, `cardNumber`, `pan`, `iban`, `ssn`, `nationalId`, `dob` (all casings)
>    - Is a whole object: `request`, `req`, `req.body`, `req.headers`, `request.POST`, `params`, `HttpServletRequest`, `Authentication`/`Principal`, any DTO, entity, or response object (`log.debug("{}", dto)`, `%+v`, `{@Obj}`, `JSON.stringify(obj)`)
>    - Is an exception or message that may embed credentials: connection setup errors with JDBC/connection URLs, outbound auth/token-exchange errors (`HttpClientErrorException.getResponseBodyAsString()`)
>
> 2. **Framework-level request/response logging**: `CommonsRequestLoggingFilter` / `AbstractRequestLoggingFilter` (`setIncludePayload`, `setIncludeHeaders`, `setIncludeQueryString`), custom `OncePerRequestFilter` / `HandlerInterceptor` / NestJS interceptors / Express middleware logging bodies or headers (`ContentCachingRequestWrapper`), `logging.level.*=DEBUG|TRACE` for `org.springframework.web`, `org.springframework.security`, `org.hibernate.SQL`, `org.hibernate.orm.jdbc.bind`, `org.hibernate.type.descriptor.sql`, `spring.jpa.show-sql`, `spring.mvc.log-request-details`, morgan formats/custom tokens, `pino-http` without `redact`, HTTP client wire logging (`org.apache.http.wire`, `org.apache.hc.client5.http.wire`, OkHttp `HttpLoggingInterceptor.Level.BODY|HEADERS`, WebClient/Reactor Netty `wiretap`, axios interceptors), ASP.NET `AddHttpLogging`, Rails `filter_parameters`, Django `django.db.backends` DEBUG.
>
> 3. **User-controlled input in plaintext logs (log forging / CRLF candidates)**: log calls whose arguments are request-derived (query/path/body params, username at login, `User-Agent`, `X-Forwarded-For`, `Referer`, `X-Request-ID` placed into MDC, request URI). Also record each log layout configuration — Logback/Log4j2 patterns, `logging.pattern.console|file`, winston `format.printf`, Python `Formatter` — as its own candidate. If many call sites log request values to the same appender, list the security-relevant ones (authentication, authorization, payment, admin) and note the total count.
>
> 4. **Security-relevant event handlers that should audit-log** — record whether a log/audit call exists in or around each:
>    - Login success/failure, logout: Spring Security `AuthenticationSuccessHandler`, `AuthenticationFailureHandler`, `AuthenticationEntryPoint`, `LogoutSuccessHandler`, custom `/login` / `/auth/token` controllers, passport callbacks, Django `LoginView` / `user_login_failed` receivers, Devise/Warden hooks, `JwtBearerEvents.OnAuthenticationFailed`
>    - Authorization denials: `AccessDeniedHandler`, `@ExceptionHandler(AccessDeniedException.class)`, NestJS guards returning false / throwing `ForbiddenException`, 401/403 exception filters, `rescue_from CanCan::AccessDenied`
>    - Password change/reset, MFA enrollment/verification, account lockout, role/permission changes, user/admin management, API key creation/revocation, high-value business transactions (payments, transfers, payout account changes)
>    - Existing audit infrastructure: `@EventListener` on `AbstractAuthenticationFailureEvent` / `AuthorizationDeniedEvent`, `AuditEventRepository`, audit services/aspects
>
> 5. **Silenced errors in security-critical code**: empty `catch (Exception e) {}`, `catch {}`, `.catch(() => {})`, `except: pass`, `except Exception: pass`, `rescue nil`, ignored `err` in Go (`_ = verify(...)`) around authentication, token/signature verification, permission checks, payment confirmation, and audit writes.
>
> 6. **Log storage location**: `logging.file.name|path`, `FileAppender`/`RollingFileAppender` paths, winston `transports.File`, Python `FileHandler`, Serilog `WriteTo.File` — flag paths under `static/`, `public/`, `wwwroot/`, `src/main/resources/static`, `webapp/`, or any directory served by `express.static` / a web server root, and world-readable file modes (`0o666`, `umask(0)`).
>
> **What to skip**:
> - Log calls whose arguments are only constants, identifiers (`userId`, `orderId`, `correlationId`), counts, durations, enum statuses, HTTP method/status
> - Test code (`src/test/`, `__tests__/`, `*.spec.ts`, `*_test.go`, `tests/`), fixtures, and mocks
> - Files in `.git/`, `node_modules/`, `vendor/`, `venv/`, `__pycache__/`, `dist/`, `build/`, `target/` directories
> - Actuator `loggers` / `logfile` exposure and verbose error responses (sast-misconfig); logging library versions / Log4Shell (sast-sca)
>
> **Output format** — write to `sast/logging-recon.md`:
>
> ```markdown
> # Logging Recon: [Project Name]
>
> ## Summary
> Found [N] logging candidates.
>
> ## Logging Configuration Overview
> - **Logging framework(s)**: [e.g., SLF4J + Logback with logstash-logback-encoder]
> - **Config files**: [paths]
> - **Appenders / encoders / patterns**: [per appender, e.g., "ConsoleAppender + LogstashEncoder (JSON)" or "RollingFileAppender, pattern `%d %-5level %logger - %msg%n`"]
> - **Levels per profile / environment**: [root and notable package levels per profile, or "not determinable from repo"]
> - **Redaction mechanisms**: [MaskingJsonGeneratorDecorator / pino redact / filter_parameters / none found]
>
> ## Candidates
>
> ### 1. [Descriptive name — e.g., "LoginRequest DTO logged at DEBUG in AuthController"]
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Function / endpoint**: [function name or route]
> - **Category**: [1 Sensitive data in log call / 2 Framework request logging / 3 User input in plaintext log / 4 Security event handler / 5 Silenced error / 6 Log storage exposure]
> - **Logged expression(s)**: `loginRequest` — [brief note, e.g., "Lombok @Data DTO, has password field" or "handler contains no log or audit call"]
> - **Logger + level**: [e.g., SLF4J `log.debug` / morgan `combined` / none]
> - **Code snippet**:
>   ```
>   [the log call, config, or handler — REDACT any literal secret values, e.g., "pass****"]
>   ```
>
> [Repeat for each candidate]
> ```

### After Phase 1: Check for Candidates Before Proceeding

After Phase 1 completes, read `sast/logging-recon.md`. If the recon found **zero candidates** (the summary reports "Found 0" or the "Candidates" section is empty or absent), **skip Phase 2 and Phase 3 entirely**. Instead, write the following content to `sast/logging-results.md` and stop:

```markdown
# Logging & Monitoring Analysis Results

No vulnerabilities found.
```

Only proceed to Phase 2 if Phase 1 found at least one candidate.

### Phase 2: Verify — Sensitivity, Taint and Coverage Analysis (Batched)

After Phase 1 completes, read `sast/logging-recon.md` and split the candidates into **batches of up to 3 candidates each**. Launch **one subagent per batch in parallel**. Each subagent analyzes only its assigned candidates and writes results to its own batch file.

**Batching procedure** (you, the orchestrator, do this — not a subagent):

1. Read `sast/logging-recon.md` and count the numbered candidate sections under "Candidates" (### 1., ### 2., etc.).
2. Divide them into batches of up to 3. For example, 8 candidates → 3 batches (1-3, 4-6, 7-8).
3. For each batch, extract the full text of those candidate sections from the recon file, plus the `## Logging Configuration Overview` section (shared by every batch).
4. Launch all batch subagents **in parallel**, passing each one only its assigned candidates and the configuration overview.
5. Each subagent writes to `sast/logging-batch-N.md` where N is the 1-based batch number.
6. Identify the project's primary language/framework from `sast/architecture.md` and select **only the matching examples** from the "Vulnerable vs. Secure Examples" section above. For example, if the project uses Spring Boot with an Angular frontend, include both "Java — Spring Boot" sections and the "TypeScript — Angular" section. Always include the three "(all stacks)" sections. Include these selected examples in each subagent's instructions where indicated by `[TECH-STACK EXAMPLES]` below.

Give each batch subagent the following instructions (substitute the batch-specific values):

> **Goal**: For each assigned logging candidate, determine whether it writes sensitive data to production logs, allows forged log entries, leaves a security event unrecorded, swallows an error in a security-critical path, or exposes log files. Our goal is to find security logging and monitoring failures. Write results to `sast/logging-batch-[N].md`.
>
> **Your assigned candidates** (from the recon phase):
>
> [Paste the full text of the assigned candidate sections here, preserving the original numbering]
>
> **Logging configuration overview** (from the recon phase):
>
> [Paste the `## Logging Configuration Overview` section here]
>
> **Context**: You will be given the project's architecture summary. Use it to understand request entry points, the authentication flow, deployment profiles, and how data flows through the application.
>
> **Apply the checks matching each candidate's category** (category 1-2 → Check 1, 3 → Check 2, 4 → Check 3, 5 → Check 4, 6 → Check 5; apply more than one check when relevant):
>
> **Check 1 — Sensitive data exposure**:
> - **Is the logged value actually sensitive?** Resolve what is really written. For objects, open the class: Lombok `@Data`/`@ToString`/`@Value` include every field unless `@ToString.Exclude`; Java records and Kotlin data classes include every component; a hand-written `toString()` may mask. When the object goes through a serializer instead (`StructuredArguments.kv`, Serilog `{@Obj}`, `JSON.stringify`, pino/winston object arguments), check `@JsonIgnore`, `@JsonProperty(access = WRITE_ONLY)`, `toJSON()`, destructuring policies. Spring's `AbstractAuthenticationToken.toString()` prints `Credentials=[PROTECTED]` but includes `WebAuthenticationDetails` with the session ID.
> - **Sensitivity tiers**: secrets — passwords, tokens (access/refresh/session/JWT/API keys), `Authorization`/`Cookie` headers, OTP/MFA codes, client secrets, private keys, full PAN, CVV, password-reset links with tokens; PII — national ID/SSN, IBAN, date of birth, address, phone, email, password hashes.
> - **Is redaction in place and does it actually cover this value?** Check `MaskingJsonGeneratorDecorator` (path masks only cover JSON fields, not text inside `message`), custom `MaskingPatternLayout` / message converters, pino `redact` paths, winston formats, Python `logging.Filter`, Rails `filter_parameters` (does not cover `params.to_unsafe_h` passed to the logger), `setHeaderPredicate`, ASP.NET header allowlists.
> - **Is the level enabled in production?** Resolve the effective level for this logger in the production profile: base `application.yml` plus `application-prod.yml` overrides, `<springProfile>` blocks in `logback-spring.xml`, `LOGGING_LEVEL_*` / `LOG_LEVEL` env in Dockerfile/Helm/Kubernetes manifests, `NODE_ENV`-based logger setup, Django `LOGGING`/`DEBUG`, `appsettings.Production.json`. Spring Boot's default root level is INFO. `CommonsRequestLoggingFilter` only emits when its own logger is at DEBUG.
>   - DEBUG/TRACE only, and disabled in production → **Not Vulnerable** — state the resolved level and the file that sets it.
>   - DEBUG/TRACE only, but the default/base configuration enables it and no production override is found → **Likely Vulnerable**.
>   - Level controlled by external configuration not in the repository → **Needs Manual Review**.
> - **Frontend console logging** (Angular, React, etc.): at most **Likely Vulnerable** (Low) unless tokens are logged unconditionally in production builds and an error-tracking SDK forwards console output.
>
> **Check 2 — Log injection (CWE-117)**:
> - **Is the value user-controlled?** Trace it backwards to its origin as in a taint analysis: query/path/body parameters, headers (`User-Agent`, `X-Forwarded-For`, `X-Request-ID`), cookies, the username submitted at login, or values read from the DB that were stored from user input. Server-side only → **Not Vulnerable**.
> - **Does the production appender neutralize CR/LF?** JSON encoders escape control characters: logstash-logback-encoder, Log4j2 `JsonTemplateLayout`/`JsonLayout`, pino, `winston.format.json()`, structlog `JSONRenderer`, `slog.NewJSONHandler`, Serilog `CompactJsonFormatter`. Plaintext layouts do not unless they encode: Logback `%replace(%msg){'[\r\n]','_'}`, Log4j2 `%enc{%m}{CRLF}`. MDC values in patterns (`%X{...}`) need the same treatment. SLF4J `{}` placeholders and Python `%s` do **not** encode CR/LF.
> - **Is there input validation** that rejects or strips CR/LF before logging (e.g., `@Pattern("^[A-Za-z0-9._@-]+$")` on the username)? If so → mitigated.
> - **Impact**: forged entries ("Login success user=admin"), misattribution, evasion of SIEM rules that parse line-oriented logs; if logs are displayed in an in-app HTML log viewer without escaping, stored XSS (report here and mention sast-xss).
>
> **Check 3 — Missing security event logging (CWE-778, CWE-223)**:
> - **Does a log/audit record exist** for this event — directly in the handler, or via an event listener, central audit service, AOP aspect, or framework audit (Spring Boot `AuthenticationAuditListener` only records when an `AuditEventRepository` bean exists; Spring Security publishes `AuthorizationDeniedEvent` only when an `AuthorizationEventPublisher` bean is registered; Django `user_login_failed` receivers)? Search the whole codebase for listeners before concluding the record is absent.
> - **Does the record contain who / what / when / outcome**: user ID or attempted username, event type, timestamp (from the logger), success/failure and reason, plus source IP and correlation ID? Missing who or outcome → CWE-223.
> - **Is it logged at a level enabled in production?** An audit record at DEBUG is effectively absent.
> - **Absent → Likely Vulnerable**: Medium for login failure, account lockout, authorization denials, privilege/role changes, admin actions, and high-value transactions; Low for logout and minor profile changes. State the severity in the Concern field.
> - Do not demand logging for every endpoint — only security events. Routine CRUD reads are not security events.
> - The audit record must not itself contain secrets — logging the attempted password on login failure is a Check 1 **Vulnerable** finding.
>
> **Check 4 — Swallowed errors in security-critical paths**:
> - Read the control flow after the catch. Does execution continue as if the check passed (a `valid` flag defaulting to true, the method returning normally, the filter chain proceeding, a payment marked complete)? → **Vulnerable**. Describe it explicitly as an authentication/authorization bypass and suggest cross-checking with sast-jwt / sast-missingauth.
> - Does it fail closed (returns 401/false) but without any log? → **Likely Vulnerable** (Low) — the detection signal is lost.
> - Is an audit write failure silently discarded? → **Likely Vulnerable** — the audit trail has invisible gaps.
> - Logged and rethrown, or mapped to an error response with a log → **Not Vulnerable**.
>
> **Check 5 — Log storage exposure**:
> - Is the log file inside a directory served by the web server or static handler? → **Vulnerable** if the logs contain any user or sensitive data.
> - Are permissions world-readable or is the path a shared volume? → **Likely Vulnerable**.
>
> **Vulnerable vs. Secure examples for this project's tech stack**:
>
> [TECH-STACK EXAMPLES]
>
> **Classification**:
> - **Vulnerable**: Credentials, tokens, session IDs, full PAN/CVV, or other secrets are written to logs at a level enabled in production; user-controlled input reaches a plaintext log without CR/LF neutralization; a swallowed error turns a failed security check into success; or logs with sensitive data are written to a publicly reachable location.
> - **Likely Vulnerable**: PII is logged at INFO or above; a sensitive object is logged and its `toString()`/serializer likely includes secrets but could not be fully verified; a security event handler has no audit record or one missing who/outcome; a security-critical error is swallowed but fails closed.
> - **Not Vulnerable**: The value is masked/redacted or excluded from `toString()`/the serializer; the level is disabled in production (state it); a JSON encoder or CR/LF encoding neutralizes forging; the value is server-side only; the event is recorded with adequate fields.
> - **Needs Manual Review**: The effective production log level is controlled by external configuration not in the repository (config server, environment variable with no default, Helm values outside the repo), or the sensitivity of a field cannot be determined.
>
> **Output format** — write to `sast/logging-batch-[N].md` (**never write real secret values** — redact them, e.g., `eyJh****`, `pass****`):
>
> ```markdown
> # Logging Batch [N] Results
>
> ## Findings
>
> ### [VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Issue**: [e.g., "LoginRequest.password written to production logs via Lombok toString() at INFO"]
> - **Data flow**: [source → log call → appender/encoder → destination, e.g., "POST /auth/login body → `log.info("Received {}", req)` AuthController:42 → ConsoleAppender, PatternLayout → container stdout → ELK". For missing events: event → handler → no log call]
> - **Impact**: [What an attacker or insider gains — credential harvesting from log storage, session hijacking, forged audit trail, undetected brute force, auth bypass]
> - **Remediation**: [Exclude/mask the field, log identifiers only, lower or disable the logger in prod, switch to a JSON encoder or add CR/LF encoding, add an audit record, fail closed]
> - **Dynamic Test**:
>   ```
>   [How to confirm. Examples:
>    - Log in with marker password `Pw-MARKER-123`, then `kubectl logs deploy/<app> | grep MARKER` (or `docker logs <container> 2>&1 | grep MARKER`)
>    - Send `username=admin%0d%0aINFO Login success user=admin` and check whether a separate forged line appears in the log output
>    - Fail login 10 times and confirm no `auth.failure` record exists]
>   ```
>
> ### [LIKELY VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Issue**: [e.g., "No audit record for failed logins" or "DTO toString() unverified"]
> - **Data flow**: [Best-effort flow; mark uncertain steps]
> - **Concern**: [Why it remains a risk, including severity for missing-event findings]
> - **Remediation**: [Fix recommendation]
> - **Dynamic Test**:
>   ```
>   [marker value or event to trigger, and where to look for it]
>   ```
>
> ### [NOT VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Reason**: [e.g., "DEBUG only; `application-prod.yml` sets root INFO" or "LogstashEncoder escapes CR/LF" or "password has @ToString.Exclude"]
>
> ### [NEEDS MANUAL REVIEW] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Uncertainty**: [e.g., "Production level set by LOG_LEVEL env var defined outside the repo"]
> - **Suggestion**: [What to check manually — deployed config, log samples, SIEM retention]
> ```

### Phase 3: Merge — Consolidate Batch Results

After **all** Phase 2 batch subagents complete, read every `sast/logging-batch-*.md` file and merge them into a single `sast/logging-results.md`. You (the orchestrator) do this directly — no subagent needed.

**Merge procedure**:

1. Read all `sast/logging-batch-1.md`, `sast/logging-batch-2.md`, ... files.
2. Collect all findings from each batch file and combine them into one list, preserving the original classification and all detail fields.
3. Count totals across all batches for the executive summary (candidates analyzed = total candidates from recon that were batched, i.e., sum of candidates across batches).
4. Write the merged report to `sast/logging-results.md` using this format:

```markdown
# Logging & Monitoring Analysis Results: [Project Name]

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

5. After writing `sast/logging-results.md`, **delete all intermediate batch files** (`sast/logging-batch-*.md`).

---

## Important Reminders

- Read `sast/architecture.md` and pass its content to all subagents as context.
- Phase 2 must run AFTER Phase 1 completes — it depends on the recon output.
- Phase 3 must run AFTER all Phase 2 batches complete — it depends on all batch outputs.
- Batch size is **3 candidates per subagent**. If there are 1-3 candidates total, use a single subagent. If there are 10, use 4 subagents (3+3+3+1).
- Launch all batch subagents **in parallel** — do not run them sequentially.
- Each batch subagent receives only its assigned candidates' text and the logging configuration overview from the recon file, not the entire recon file. This keeps each subagent's context small and focused.
- **Phase 1 is purely structural**: flag sensitive-named arguments, whole objects, request-logging settings, plaintext layouts, security handlers, and empty catches regardless of level or origin. Do not resolve production levels or trace user input in Phase 1 — that is Phase 2's job.
- **Phase 2 decides real impact**: resolve what the object actually prints, which level is active in production, whether the appender neutralizes CR/LF, and whether a security event is recorded anywhere.
- Logging the whole `Authentication`, `Principal`, `HttpServletRequest`, Express `req`, or Django `request` object often leaks credentials, session IDs, or cookies — treat whole-object logging as a candidate until its output is resolved.
- `logging.level.org.springframework.web=DEBUG` logs deserialized `@RequestBody` objects through their `toString()` — a Lombok `@Data` login DTO leaks the password without any explicit log statement in the application.
- JSON structured logging prevents CRLF forging but **not** sensitive-data leakage. Do not mark a sensitive-data candidate Not Vulnerable just because the encoder is JSON.
- MDC fields count as logged data: a token in MDC is printed on every line, and an unvalidated `X-Request-ID` copied into MDC is a log-injection source in plaintext layouts.
- Log4Shell-style JNDI lookups and vulnerable log4j versions belong to **sast-sca**; Actuator `loggers`/`logfile` exposure and stack traces in responses belong to **sast-misconfig** — do not report them here.
- Group repeated identical patterns (e.g., the same `log.debug("{}", dto)` in 20 controllers, or one plaintext layout used by every logger) into one finding listing all locations.
- **Redact secrets in output**: never write a real secret, token, or personal data value into recon, batch, or results files.
- When in doubt, classify as "Needs Manual Review" rather than "Not Vulnerable". False negatives are worse than false positives in security assessment.
- Clean up intermediate files: delete all `sast/logging-batch-*.md` files after the final `sast/logging-results.md` is written. **Preserve** `sast/logging-recon.md` — the orchestrator reuses it on later runs.
