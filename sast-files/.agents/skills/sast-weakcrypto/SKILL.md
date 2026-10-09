---
name: sast-weakcrypto
description: >-
  Detect weak cryptography (OWASP A02:2021 Cryptographic Failures) in a codebase
  using a three-phase approach: recon (find crypto primitive call sites —
  password hashing, ciphers/modes/IVs, keys, randomness, TLS verification,
  asymmetric params, cleartext transport), batched verify (determine what each
  primitive protects and whether the weakness is reachable, in parallel
  subagents, 3 sites each), and merge (consolidate batch results). Requires
  sast/architecture.md (run sast-analysis first). Outputs findings to
  sast/weakcrypto-results.md. Use when asked to find weak crypto, cryptographic
  failures, insecure hashing, broken ciphers, or disabled TLS verification.
---

# Weak Cryptography Detection

You are performing a focused security assessment to find weak cryptography in a codebase. This skill uses a three-phase approach with subagents: **recon** (find crypto primitive call sites — hashes, ciphers, keys, randomness, TLS verification, cleartext transport), **batched verify** (determine what each primitive protects and whether the weakness is attacker-reachable, in parallel batches of 3), and **merge** (consolidate batch reports into one file).

**Prerequisites**: `sast/architecture.md` must exist. Run the analysis skill first if it doesn't.

---

## What is Weak Cryptography

Weak cryptography (OWASP A02:2021 Cryptographic Failures) occurs when an application protects sensitive data — passwords, tokens, PII, payment data — or makes an integrity decision using a cryptographic primitive that is broken, misconfigured, or misused. The data can then be recovered, forged, or tampered with: password hashes are cracked offline, ciphertext is decrypted or malleated, predictable tokens are guessed, forged signatures pass verification, and traffic is intercepted on a connection whose certificate was never checked.

The core pattern: *a security-sensitive value is protected by a broken, misconfigured, or misused cryptographic primitive, and an attacker can reach or observe the result.*

### What Weak Crypto IS

- **Fast/unsalted password hashing**: storing passwords with MD5, SHA-1, or a single round of SHA-256/512, with no salt, or as reversible encryption / plaintext, instead of bcrypt, scrypt, Argon2id, or PBKDF2 with an adequate cost; Spring `NoOpPasswordEncoder`, `MessageDigestPasswordEncoder`, `StandardPasswordEncoder`; a bcrypt cost factor or PBKDF2 iteration count far below current guidance
- **Broken or weak algorithms**: DES, 3DES (DESede), RC4, Blowfish, RC2 for confidentiality; MD5 or SHA-1 for signatures or as the basis of an integrity decision
- **Insecure cipher modes and IV/nonce handling**: ECB mode (including Java `Cipher.getInstance("AES")`, whose default is ECB); CBC with no MAC where a padding oracle is reachable; a static, zero, or hardcoded IV; AES-GCM nonce reuse; a predictable IV
- **Hardcoded or weakly derived keys** passed into server-side crypto calls: a key literal handed to `SecretKeySpec`, `createCipheriv`, or `AES.new`; an encryption/HMAC key derived from a password with no KDF
- **Insecure randomness for security-sensitive values**: `Math.random`, `java.util.Random`, Python `random`, Go `math/rand`, PHP `rand`/`mt_rand`/`uniqid`, .NET `System.Random` used for session IDs, reset tokens, OTPs, API keys, CSRF tokens, nonces, or salts; UUIDv1 / timestamp-based tokens
- **Disabled or weakened TLS verification** on outbound connections: Python `verify=False`, Node `rejectUnauthorized: false` / `NODE_TLS_REJECT_UNAUTHORIZED=0`, Go `InsecureSkipVerify: true`, a trust-all Java `X509TrustManager` or `HostnameVerifier` that returns true / `NoopHostnameVerifier`, .NET `ServerCertificateCustomValidationCallback => true`; server config that still allows TLS 1.0/1.1 or weak cipher suites
- **Weak asymmetric parameters**: RSA keys below 2048 bits, RSA PKCS#1 v1.5 encryption padding (OAEP is preferred), DSA, custom/unvetted curves; non-constant-time comparison of MACs, signatures, or tokens (`==`, `.equals`, `strcmp`) instead of a constant-time compare
- **Sensitive data transmitted in cleartext**: hardcoded `http://` URLs for auth, payment, or PII APIs; cleartext protocols (`ftp`, `telnet`, `ldap://` without StartTLS) carrying sensitive data

### What Weak Crypto is NOT

Do not flag these as weak crypto — each is owned by a sibling skill or is simply out of scope:

- **Secrets exposed in public client code**: an API key or private key hardcoded into a frontend bundle or mobile app — that's **sast-hardcodedsecrets**. This skill cares about *how* a key is used in server-side crypto, not about a secret leaking to clients.
- **JWT signing secrets and JWT algorithm confusion**: a weak or hardcoded HMAC secret used to sign JWTs, `alg:none`, RS256→HS256 — that's **sast-jwt**. A generic HMAC/encryption key used outside the JWT lifecycle stays here.
- **SQL injection via a crypto-adjacent lookup** (e.g. a `kid` interpolated into a query): that's **sast-sqli** (the `kid` case is called out by **sast-jwt**).
- **Missing authorization / IDOR**: being able to read another user's record is **sast-idor**, not a crypto failure, even if that record is encrypted.
- **Non-security hashing**: MD5 or SHA-1 used for an ETag, cache key, checksum, content-addressing, dedupe, or sharding — these make no security claim and are **Not Vulnerable**.

### Patterns That Prevent Weak Crypto

When you see these patterns, the code is likely **not vulnerable**:

**1. Adaptive password hashing with adequate cost**
```
# Java — Spring Security (BCrypt is the framework default)
PasswordEncoder encoder = new BCryptPasswordEncoder(12);
PasswordEncoder delegating = PasswordEncoderFactories.createDelegatingPasswordEncoder();

# Node.js — bcrypt / argon2
await bcrypt.hash(password, 12);
await argon2.hash(password, { type: argon2.argon2id });

# Python — passlib / Django default hasher
from argon2 import PasswordHasher; PasswordHasher().hash(password)
# Django: PBKDF2PasswordHasher / Argon2PasswordHasher (framework default)

# Go — bcrypt
bcrypt.GenerateFromPassword(pw, bcrypt.DefaultCost)
```

**2. Authenticated encryption with a unique nonce per message**
```
# AES-GCM with a fresh random 96-bit nonce each time (never reused under one key)
nonce = os.urandom(12)                          # Python — cryptography
AESGCM(key).encrypt(nonce, plaintext, aad)

const iv = crypto.randomBytes(12);              // Node.js
crypto.createCipheriv('aes-256-gcm', key, iv);

Cipher c = Cipher.getInstance("AES/GCM/NoPadding");  // Java — explicit mode, random IV
```

**3. Cryptographically secure randomness**
```
java.security.SecureRandom              // Java
crypto.randomBytes(32)                  // Node.js
secrets.token_urlsafe(32)               // Python (the `secrets` module)
crypto/rand.Read(buf)                   // Go (NOT math/rand)
random_bytes(32)                        // PHP
RandomNumberGenerator.GetBytes(32)      // .NET
```

**4. Keys from a managed source, never hardcoded**
```
# Key material loaded from env / KMS / vault, not a string literal in source
byte[] key = Base64.getDecoder().decode(System.getenv("DATA_ENC_KEY"));
const key = await kms.decrypt(wrappedKey);   // AWS KMS / GCP KMS / Vault
```

**5. Verified TLS and constant-time comparison**
```
# Default (verification ON) — do not pass verify=False / rejectUnauthorized:false
requests.get(url)                              # Python — verifies by default
fetch(url)                                     # Node — verifies by default

# Constant-time comparison for MACs / tokens / signatures
hmac.compare_digest(expected, provided)        # Python
crypto.timingSafeEqual(a, b)                   // Node.js
MessageDigest.isEqual(a, b)                    // Java
```

---

## Vulnerable vs. Secure Examples

### Java — Spring Boot

```java
// VULNERABLE: plaintext / reversible password storage via NoOpPasswordEncoder
@Bean
public PasswordEncoder passwordEncoder() {
    return NoOpPasswordEncoder.getInstance();      // passwords stored as-is
}

// VULNERABLE: fast unsalted digest as a "password encoder"
@Bean
public PasswordEncoder passwordEncoder() {
    return new MessageDigestPasswordEncoder("SHA-1"); // deprecated, crackable
}

// VULNERABLE: ECB mode (getInstance("AES") defaults to AES/ECB/PKCS5Padding)
Cipher cipher = Cipher.getInstance("AES");
cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(KEY, "AES"));

// VULNERABLE: hardcoded key + static zero IV for CBC
private static final byte[] KEY = "0123456789abcdef".getBytes();
Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(KEY, "AES"),
       new IvParameterSpec(new byte[16]));          // all-zero IV, reused

// VULNERABLE: trust-all TrustManager disables certificate verification
TrustManager[] trustAll = new TrustManager[]{ new X509TrustManager() {
    public void checkClientTrusted(X509Certificate[] c, String a) {}
    public void checkServerTrusted(X509Certificate[] c, String a) {}   // accepts anything
    public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
}};

// VULNERABLE: insecure randomness for a password-reset token
String token = Long.toHexString(new java.util.Random().nextLong());

// SECURE: BCrypt password encoder (adequate cost)
@Bean
public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder(12);
}

// SECURE: explicit authenticated mode, random IV, key from env
byte[] key = Base64.getDecoder().decode(System.getenv("DATA_ENC_KEY"));
byte[] iv = new byte[12];
SecureRandom.getInstanceStrong().nextBytes(iv);
Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));

// SECURE: CSPRNG token + constant-time compare
byte[] raw = new byte[32];
new SecureRandom().nextBytes(raw);
boolean ok = MessageDigest.isEqual(expectedMac, providedMac);
```

### TypeScript / Node.js — Express / NestJS

```typescript
// VULNERABLE: MD5 for password storage
import { createHash } from 'crypto';
const hashed = createHash('md5').update(password).digest('hex');

// VULNERABLE: AES-ECB and a hardcoded key
import { createCipheriv } from 'crypto';
const KEY = Buffer.from('a'.repeat(32));            // hardcoded in source
const cipher = createCipheriv('aes-256-ecb', KEY, null); // ECB: identical blocks leak

// VULNERABLE: static IV reused across messages (CBC)
const iv = Buffer.alloc(16, 0);                     // zero IV, never rotated
createCipheriv('aes-256-cbc', KEY, iv);

// VULNERABLE: TLS verification disabled on an outbound call carrying credentials
import axios from 'axios';
import https from 'https';
const agent = new https.Agent({ rejectUnauthorized: false });  // MITM-able
await axios.post('https://payments.internal/charge', body, { httpsAgent: agent });

// VULNERABLE: Math.random for a session / reset token
const token = Math.random().toString(36).slice(2);  // predictable, not a CSPRNG

// VULNERABLE: non-constant-time token comparison
if (providedToken === storedToken) { grantAccess(); } // timing side channel

// SECURE: argon2id (or bcrypt) for passwords
import * as argon2 from 'argon2';
const hashed = await argon2.hash(password, { type: argon2.argon2id });

// SECURE: AES-GCM, random IV per message, key from env / KMS
import { createCipheriv, randomBytes } from 'crypto';
const key = Buffer.from(process.env.DATA_ENC_KEY!, 'base64');
const iv = randomBytes(12);
const cipher = createCipheriv('aes-256-gcm', key, iv);

// SECURE: CSPRNG token + timing-safe compare (verification left ON)
const token = randomBytes(32).toString('base64url');
const ok = crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
```

### Python — Django / Flask

```python
# VULNERABLE: MD5/SHA-1 for password storage
import hashlib
pw_hash = hashlib.md5(password.encode()).hexdigest()   # fast, unsalted, crackable

# VULNERABLE: AES-ECB with a hardcoded key (PyCryptodome)
from Crypto.Cipher import AES
KEY = b'0123456789abcdef'                              # hardcoded
cipher = AES.new(KEY, AES.MODE_ECB)                    # ECB leaks block patterns

# VULNERABLE: static IV reused for CBC
cipher = AES.new(KEY, AES.MODE_CBC, iv=b'\x00' * 16)

# VULNERABLE: TLS verification disabled on a sensitive outbound call
import requests
requests.get('https://api.partner.com/pii', verify=False)   # accepts any cert

# VULNERABLE: predictable token for password reset
import random
token = ''.join(random.choices('0123456789abcdef', k=32))   # random module, not secrets

# SECURE: Django's default hasher (PBKDF2 / Argon2) — do not override with a weak one
# settings.py: PASSWORD_HASHERS defaults to PBKDF2PasswordHasher / Argon2PasswordHasher
from django.contrib.auth.hashers import make_password
pw_hash = make_password(password)

# SECURE: AES-GCM, random nonce, key from env; CSPRNG token; constant-time compare
import os, hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
key = bytes.fromhex(os.environ['DATA_ENC_KEY'])
nonce = os.urandom(12)
ct = AESGCM(key).encrypt(nonce, plaintext, None)
import secrets
token = secrets.token_urlsafe(32)
ok = hmac.compare_digest(expected, provided)
requests.get(url)                                       # verify defaults to True
```

### Go

```go
// VULNERABLE: AES-ECB equivalent (manual block loop, no IV) + math/rand token
import ("crypto/aes"; "math/rand")
block, _ := aes.NewCipher(key)
for i := 0; i < len(pt); i += aes.BlockSize {          // ECB: encrypt each block alone
    block.Encrypt(ct[i:], pt[i:])
}
token := fmt.Sprintf("%d", rand.Int63())               // math/rand: predictable

// VULNERABLE: InsecureSkipVerify disables certificate checks
tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
client := &http.Client{Transport: tr}

// SECURE: AES-GCM with a random nonce, crypto/rand everywhere, bcrypt for passwords
import ("crypto/cipher"; "crypto/rand"; "golang.org/x/crypto/bcrypt")
gcm, _ := cipher.NewGCM(block)
nonce := make([]byte, gcm.NonceSize())
rand.Read(nonce)                                        // crypto/rand, not math/rand
ct := gcm.Seal(nil, nonce, pt, nil)
hashed, _ := bcrypt.GenerateFromPassword(pw, bcrypt.DefaultCost)
```

### PHP

```php
// VULNERABLE: md5() password storage, mcrypt DES, uniqid() token
$hash = md5($password);                                 // fast, unsalted
$token = uniqid();                                      // time-based, predictable
// DES / ECB via openssl
$ct = openssl_encrypt($data, 'des-ecb', $key);

// SECURE: password_hash (bcrypt/argon2), AES-GCM, random_bytes token
$hash = password_hash($password, PASSWORD_ARGON2ID);
$iv = random_bytes(12);
$ct = openssl_encrypt($data, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
$token = bin2hex(random_bytes(32));
$ok = hash_equals($expected, $provided);                // constant-time
```

### C# — ASP.NET Core

```csharp
// VULNERABLE: MD5 password hash, System.Random token, TLS callback that always trusts
using var md5 = MD5.Create();
var hash = md5.ComputeHash(Encoding.UTF8.GetBytes(password));
var token = new Random().Next().ToString();             // predictable
var handler = new HttpClientHandler {
    ServerCertificateCustomValidationCallback = (m, c, ch, e) => true  // accepts any cert
};

// VULNERABLE: ECB mode
using var aes = Aes.Create();
aes.Mode = CipherMode.ECB;                              // leaks block patterns

// SECURE: ASP.NET Identity password hasher, GCM, RNG, fixed-time compare
var hasher = new PasswordHasher<AppUser>();             // PBKDF2 under the hood
var hashed = hasher.HashPassword(user, password);
using var gcm = new AesGcm(key);                        // authenticated encryption
var token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
var ok = CryptographicOperations.FixedTimeEquals(expected, provided);
```

### Ruby on Rails

```ruby
# VULNERABLE: Digest::MD5 for passwords, SecureRandom not used for token
hash = Digest::MD5.hexdigest(password)                  # fast, unsalted
token = rand(10 ** 10).to_s                             # Kernel#rand: predictable

# SECURE: has_secure_password (bcrypt), SecureRandom token, AES-GCM
# model: has_secure_password   # bcrypt via BCrypt::Password
token = SecureRandom.urlsafe_base64(32)
cipher = OpenSSL::Cipher.new('aes-256-gcm')             # authenticated mode
cipher.encrypt; cipher.key = key; iv = cipher.random_iv
ok = ActiveSupport::SecurityUtils.secure_compare(a, b)  # constant-time
```

---

## Execution

This skill runs in three phases using subagents. Pass the contents of `sast/architecture.md` to all subagents as context.

**Cache reuse**: If `sast/weakcrypto-recon.md` already exists, skip Phase 1 and reuse it. If `sast/sinks-index.md` exists, pass its `## sast-weakcrypto` section to the Phase 1 subagent as a starting list of candidate sites — the subagent must still search beyond it, since the index is regex-based and incomplete.

### Phase 1: Recon — Find Crypto Primitive Call Sites

Launch a subagent with the following instructions:

> **Goal**: Find every location in the codebase where a cryptographic primitive is used in a potentially weak way — a hash, cipher, mode, IV, key, random source, TLS setting, asymmetric parameter, or cleartext transport call. Flag the site regardless of what it protects; determining the *purpose* and *reachability* is Phase 2's job. Write results to `sast/weakcrypto-recon.md`.
>
> **Context**: You will be given the project's architecture summary. Use it to understand the tech stack, authentication layer, the crypto libraries in use, and which outbound integrations exist. If a `## sast-weakcrypto` section from `sast/sinks-index.md` is provided, treat it as a starting list — still search beyond it.
>
> **What to search for — crypto primitive categories** (grep-able patterns per language):
>
> 1. **Weak password storage** — fast/unsalted hashes or reversible storage used for credentials:
>    - Spring: `NoOpPasswordEncoder`, `MessageDigestPasswordEncoder`, `StandardPasswordEncoder`, a `BCryptPasswordEncoder(<low cost>)` or `Pbkdf2PasswordEncoder` with few iterations
>    - Hashes applied to a password variable: `hashlib.md5(`, `hashlib.sha1(`, `hashlib.sha256(` (single round, no salt), `createHash('md5'|'sha1'|'sha256')`, `MessageDigest.getInstance("MD5"|"SHA-1")`, `Digest::MD5`, `md5(`, `sha1(` (PHP), `MD5.Create()`
>    - Reversible or plaintext: password written to the DB unhashed, or `encrypt(password)` for storage
>
> 2. **Broken or weak algorithms** for confidentiality/integrity:
>    - `\bDES\b`, `DESede`, `3DES`, `RC4`, `ARCFOUR`, `Blowfish`, `RC2`
>    - MD5/SHA-1 used for a signature or an integrity/HMAC decision (not for passwords)
>
> 3. **Insecure modes and IV/nonce handling**:
>    - ECB: `/ECB/`, `MODE_ECB`, `CipherMode.ECB`, `'aes-256-ecb'`, and Java `Cipher.getInstance("AES")` (the bare-algorithm default is ECB)
>    - CBC with no MAC: `/CBC/`, `MODE_CBC`, `'aes-256-cbc'` — note whether any authentication is applied afterward
>    - Static / zero / hardcoded IV: `IvParameterSpec(new byte[`, `Buffer.alloc(16`, `b'\x00' * 16`, an IV assigned a string/array literal or reused across calls
>    - GCM nonce reuse: a `GCMParameterSpec` / `createCipheriv('...-gcm')` where the nonce is constant or counter-derived rather than fresh-random
>
> 4. **Hardcoded or weakly derived keys** passed into a crypto call:
>    - `SecretKeySpec(<literal>`, `createCipheriv(alg, <literal-key>`, `AES.new(<literal-key>`, `new SecretKeySpec("...".getBytes()`
>    - A key derived from a password without a KDF (`key = sha256(password)` used as an AES key)
>
> 5. **Insecure randomness** for security-sensitive values:
>    - `Math.random(`, `new Random(`, `java.util.Random`, Python `random.` (`random`, `randint`, `choice`, `getrandbits`), Go `math/rand`, PHP `rand(`, `mt_rand(`, `uniqid(`, .NET `new Random(`
>    - `UUID.randomUUID` is fine, but flag timestamp/UUIDv1-based tokens
>    - Trace nearby names: `token`, `otp`, `session`, `csrf`, `nonce`, `salt`, `apiKey`, `reset` — these raise the stakes (Phase 2 confirms)
>
> 6. **Disabled or weakened TLS verification** on outbound connections:
>    - Python `verify=False`; Node `rejectUnauthorized: false`, `NODE_TLS_REJECT_UNAUTHORIZED`; Go `InsecureSkipVerify: true`
>    - Java trust-all `X509TrustManager` (empty `checkServerTrusted`), `HostnameVerifier` returning `true`, `NoopHostnameVerifier`, `ALLOW_ALL_HOSTNAME_VERIFIER`
>    - .NET `ServerCertificateCustomValidationCallback` returning `true`
>    - Server config allowing TLS 1.0/1.1 or weak cipher suites (`sslProtocols`, `ssl_protocols`, `enabled-protocols`)
>
> 7. **Weak asymmetric parameters / non-constant-time comparison**:
>    - RSA under 2048: `KeyPairGenerator...initialize(512|1024)`, `rsa.generate_private_key(key_size=1024)`, `generateKeyPair('rsa', { modulusLength: 1024 })`
>    - PKCS#1 v1.5 encryption padding: `RSA/ECB/PKCS1Padding`, `PKCS1v15` (prefer OAEP); DSA; custom/unknown curves
>    - Comparison of a MAC/signature/token with `==`, `===`, `.equals(`, `strcmp(` instead of a constant-time compare
>
> 8. **Sensitive data in cleartext transport**:
>    - Hardcoded `http://` URLs for auth/payment/PII endpoints
>    - `ftp://`, `telnet`, `ldap://` (without StartTLS) used for sensitive data
>
> **What to skip** (do not flag at recon):
> - CSPRNGs: `SecureRandom`, `crypto.randomBytes`, the Python `secrets` module, `crypto/rand`, `random_bytes`, `RandomNumberGenerator` — these are correct
> - Framework default password hashers left unchanged: Spring `BCryptPasswordEncoder` / delegating encoder, Django `PBKDF2`/`Argon2` hashers, ASP.NET `PasswordHasher` / Identity, Rails `has_secure_password`
> - Non-security hashing that is clearly an ETag, cache key, checksum, content hash, dedupe, or shard key (note it so Phase 2 can confirm)
> - Standard verified TLS (no `verify=False` / `rejectUnauthorized:false` / `InsecureSkipVerify`)
>
> **Output format** — write to `sast/weakcrypto-recon.md`:
>
> ```markdown
> # Weak Crypto Recon: [Project Name]
>
> ## Summary
> Found [N] crypto primitive sites that may be weak.
>
> ## Crypto Primitive Sites
>
> ### 1. [Descriptive name — e.g., "MD5 digest applied to password in UserService"]
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Function / endpoint**: [function name or route]
> - **Category**: [password-hashing / weak-algorithm / insecure-mode-iv / hardcoded-key / insecure-randomness / tls-verification / weak-asymmetric / cleartext-transport]
> - **Primitive**: [e.g., "hashlib.md5" / "Cipher.getInstance(\"AES\") -> ECB" / "Math.random" / "verify=False" / "X509TrustManager trust-all"]
> - **Apparent purpose**: [best guess — "password storage" / "token generation" / "outbound call to payment API" / "unknown — possibly an ETag"]
> - **Code snippet**:
>   ```
>   [the primitive call + enough surrounding context to see the IV/key/mode]
>   ```
>
> [Repeat for each site]
> ```

### After Phase 1: Check for Candidates Before Proceeding

After Phase 1 completes, read `sast/weakcrypto-recon.md`. If the recon found **zero crypto primitive sites** (the summary reports "Found 0" or the "Crypto Primitive Sites" section is empty or absent), **skip Phase 2 entirely**. Instead, write the following content to `sast/weakcrypto-results.md` and stop:

```markdown
# Weak Crypto Analysis Results

No vulnerabilities found.
```

Only proceed to Phase 2 if Phase 1 found at least one crypto primitive site.

### Phase 2: Verify — Purpose & Reachability Analysis (Batched)

After Phase 1 completes, read `sast/weakcrypto-recon.md` and split the primitive sites into **batches of up to 3 sites each**. Launch **one subagent per batch in parallel**. Each subagent analyzes only its assigned sites and writes results to its own batch file.

**Batching procedure** (you, the orchestrator, do this — not a subagent):

1. Read `sast/weakcrypto-recon.md` and count the numbered site sections under "Crypto Primitive Sites" (### 1., ### 2., etc.).
2. Divide them into batches of up to 3. For example, 8 sites → 3 batches (1-3, 4-6, 7-8).
3. For each batch, extract the full text of those site sections from the recon file.
4. Launch all batch subagents **in parallel**, passing each one only its assigned sites.
5. Each subagent writes to `sast/weakcrypto-batch-N.md` where N is the 1-based batch number.
6. Identify the project's primary language/framework from `sast/architecture.md` and select **only the matching examples** from the "Vulnerable vs. Secure Examples" section above. For example, if the project uses Spring Boot, include the "Java — Spring Boot" example; if it uses NestJS, include the "TypeScript / Node.js — Express / NestJS" example. Include these selected examples in each subagent's instructions where indicated by `[TECH-STACK EXAMPLES]` below.

Give each batch subagent the following instructions (substitute the batch-specific values):

> **Goal**: For each assigned crypto primitive site, determine whether it is a real cryptographic failure by analyzing (a) what the primitive protects, (b) whether the weakness is reachable or observable by an attacker, (c) whether it runs in production paths, and (d) what mitigations are present. Our goal is to find weak cryptography. Write results to `sast/weakcrypto-batch-[N].md`.
>
> **Your assigned crypto primitive sites** (from the recon phase):
>
> [Paste the full text of the assigned site sections here, preserving the original numbering]
>
> **Context**: You will be given the project's architecture summary. Use it to understand data sensitivity, request entry points, which services are internet-facing, and how outbound integrations are configured.
>
> **This verification is primarily purpose/context analysis, not just taint. For each site, answer four questions:**
>
> **(a) What does the primitive protect?** Determine the asset: a password, a session/reset/OTP/API token, a CSRF token, encrypted PII or payment data, an integrity/authentication decision, or a **non-security** value (ETag, cache key, checksum, content hash, dedupe/shard key, a random id that is never a secret). A weak primitive used for a non-security value is **Not Vulnerable** — say so.
>
> **(b) Is the weak value reachable or observable by an attacker?** For example: a predictable token is emailed/returned to users or used as a password-reset credential; ciphertext (or an ECB pattern) is exposed to clients or stored where an attacker can read it; an outbound TLS call with verification off carries credentials or PII over an attacker-reachable network; a hash is stored where offline cracking applies if the DB leaks. If the weak output is never exposed and never trusted across a trust boundary, the risk is lower.
>
> **(c) Does the code run in production paths?** Test-only code, fixtures, sample/demo code, or a dev-profile-only bean is **Not Vulnerable or lower**. Confirm the site is on a real request/runtime path, not a unit test or a `@Profile("dev")`/`if DEBUG` block.
>
> **(d) What mitigations are present?** Check for: the key being rotated from KMS/env rather than hardcoded; upgrade-on-login rehashing that re-hashes legacy MD5/SHA-1 passwords into bcrypt/Argon2 on next successful login; a MAC/HMAC applied after CBC (encrypt-then-MAC) that removes the padding-oracle; an allowlisted pinned cert where `InsecureSkipVerify` is paired with manual verification; a nonce that is actually fresh-random despite looking static.
>
> **Mitigations reference**:
> - A legacy weak hash with a documented migration path (rehash-on-login to a strong hasher, and the weak path is no longer used for new passwords) is **Likely Vulnerable** at most, and **Not Vulnerable** if fully retired.
> - `verify=False` / `rejectUnauthorized:false` / `InsecureSkipVerify` that reaches a hardcoded `localhost`/health-check with no sensitive payload is **lower risk but still note it**; the same against an external or credential-bearing endpoint is **Vulnerable**.
> - A hardcoded key that is actually loaded from env/KMS at runtime (the literal is only a dev fallback that production overrides) is lower; a literal with no override is **Vulnerable**.
>
> **Vulnerable vs. Secure examples for this project's tech stack**:
>
> [TECH-STACK EXAMPLES]
>
> **Classification**:
> - **Vulnerable**: The primitive protects a security-sensitive asset, the weakness is attacker-reachable/observable, the code runs in production, and no effective mitigation applies (e.g., MD5 for live password storage; ECB encrypting PII returned to clients; `Math.random` reset token; TLS verification off on a credentialed external call).
> - **Likely Vulnerable**: The weakness is present and probably matters, but one condition is unconfirmed (uncertain data sensitivity, a partial mitigation such as rehash-on-login, or reachability that depends on another path).
> - **Not Vulnerable**: The primitive protects a non-security value, OR it is test/dev-only, OR a strong mitigation fully addresses it, OR the code already uses a secure primitive/framework default.
> - **Needs Manual Review**: Cannot determine the purpose, reachability, or mitigation with confidence (opaque helpers, key source unclear, nonce freshness undeterminable from static analysis).
>
> **Output format** — write to `sast/weakcrypto-batch-[N].md`:
>
> ```markdown
> # Weak Crypto Batch [N] Results
>
> ## Findings
>
> ### [VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Issue**: [e.g., "User passwords stored with unsalted MD5; crackable offline if the DB leaks"]
> - **Evidence trace**: [What the primitive protects (a) → attacker reachability/observability (b) → production path (c) → absence of mitigation (d)]
> - **Impact**: [What an attacker achieves — recover all passwords, decrypt PII, forge tokens, MITM credentials, etc.]
> - **Remediation**: [Specific fix — migrate to bcrypt/Argon2id; switch to AES-GCM with random IV; use SecureRandom/secrets; remove verify=False / pin the cert; use OAEP; RSA ≥ 2048; constant-time compare]
> - **Dynamic Test**:
>   ```
>   [PoC command. Examples:
>    - hashcat -m 0 hashes.txt rockyou.txt            (MD5 password cracking; pick the mode for the hash)
>    - npx v8-randomness-predictor <observed tokens>  (predict Math.random output)
>    - mitmproxy --ssl-insecure  then point the app's outbound call through it with a self-signed cert
>    - testssl.sh https://host                         (enumerate allowed TLS protocols/ciphers)
>    - ECB check: encrypt a plaintext of repeated 16-byte blocks; confirm identical ciphertext blocks]
>   ```
>
> ### [LIKELY VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Issue**: [e.g., "SHA-1 password hash with a rehash-on-login migration, but legacy accounts still present"]
> - **Evidence trace**: [Best-effort (a)-(d); mark the uncertain condition]
> - **Concern**: [Why it remains a risk]
> - **Remediation**: [Fix]
> - **Dynamic Test**:
>   ```
>   [payload or command to attempt exploitation]
>   ```
>
> ### [NOT VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Reason**: [e.g., "MD5 used as an ETag / cache key — no security claim" or "BCryptPasswordEncoder, framework default, adequate cost" or "verify=False only on a localhost health check with no sensitive data" or "test fixture, not a production path"]
>
> ### [NEEDS MANUAL REVIEW] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Uncertainty**: [Why purpose/reachability/mitigation could not be determined]
> - **Suggestion**: [What to trace or confirm manually — e.g., "Confirm whether the GCM nonce counter is ever reset under the same key"]
> ```

### Phase 3: Merge — Consolidate Batch Results

After **all** Phase 2 batch subagents complete, read every `sast/weakcrypto-batch-*.md` file and merge them into a single `sast/weakcrypto-results.md`. You (the orchestrator) do this directly — no subagent needed.

**Merge procedure**:

1. Read all `sast/weakcrypto-batch-1.md`, `sast/weakcrypto-batch-2.md`, ... files.
2. Collect all findings from each batch file and combine them into one list, preserving the original classification and all detail fields.
3. Count totals across all batches for the executive summary (primitive sites analyzed = total sites from recon that were batched, i.e., sum of sites across batches).
4. Write the merged report to `sast/weakcrypto-results.md` using this format:

```markdown
# Weak Crypto Analysis Results: [Project Name]

## Executive Summary
- Primitive sites analyzed: [total across all batches]
- Vulnerable: [N]
- Likely Vulnerable: [N]
- Not Vulnerable: [N]
- Needs Manual Review: [N]

## Findings

[All findings from all batches, grouped by classification:
 VULNERABLE first, then LIKELY VULNERABLE, then NEEDS MANUAL REVIEW, then NOT VULNERABLE.
 Preserve every field from the batch results exactly as written.]
```

5. After writing `sast/weakcrypto-results.md`, **delete all intermediate batch files** (`sast/weakcrypto-batch-*.md`).

---

## Important Reminders

- Read `sast/architecture.md` and pass its content to all subagents as context.
- Phase 2 must run AFTER Phase 1 completes — it depends on the recon output.
- Phase 3 must run AFTER all Phase 2 batches complete — it depends on all batch outputs.
- Batch size is **3 primitive sites per subagent**. If there are 1-3 sites total, use a single subagent. If there are 10, use 4 subagents (3+3+3+1).
- Launch all batch subagents **in parallel** — do not run them sequentially.
- Each batch subagent receives only its assigned sites' text from the recon file, not the entire recon file. This keeps each subagent's context small and focused.
- **Phase 1 is purely structural**: flag any crypto primitive that could be weak, regardless of what it protects. Do not assess purpose or reachability in Phase 1 — that is Phase 2's job.
- **Phase 2 is purely verification**: for each assigned site, answer the four questions (purpose, reachability, production path, mitigations) before classifying. The classification follows from those answers, not from the primitive's name alone.
- **MD5/SHA-1 for a non-security purpose is not a finding**: ETags, cache keys, checksums, content-addressing, dedupe, and shard keys make no security claim. Only flag a weak hash when it protects passwords, tokens, or an integrity decision.
- **These primitives are safe**: `SecureRandom`, `crypto.randomBytes`, the Python `secrets` module, `crypto/rand`, `random_bytes`, `RandomNumberGenerator`. Do not flag randomness that already uses a CSPRNG.
- **Framework defaults are safe unless overridden**: Spring `BCryptPasswordEncoder` / delegating encoder, Django `PBKDF2PasswordHasher` / `Argon2PasswordHasher`, ASP.NET Identity's `PasswordHasher`, Rails `has_secure_password`. Only flag when the code swaps in a weak encoder (`NoOpPasswordEncoder`, `MessageDigestPasswordEncoder`, a low bcrypt cost) or hashes passwords by hand.
- **Check legacy-hash migration code**: a weak hash paired with rehash-on-login (re-hashing to a strong hasher on the next successful login) is at most Likely Vulnerable while legacy accounts remain, and Not Vulnerable once fully retired — read the login path before classifying.
- **`verify=False` / `rejectUnauthorized:false` / `InsecureSkipVerify` in a test or a localhost-only health check is lower risk but still note it.** The same disabled verification on an external or credential-bearing outbound call is Vulnerable.
- **Java `Cipher.getInstance("AES")` is ECB**: the bare-algorithm form defaults to `AES/ECB/PKCS5Padding`. Treat it as ECB even though "ECB" does not appear in the string.
- **A hardcoded key that production overrides from env/KMS is lower risk**; a literal with no override, or a key derived from a password without a KDF, is Vulnerable.
- When in doubt, classify as "Needs Manual Review" rather than "Not Vulnerable". False negatives are worse than false positives in security assessment.
- Clean up intermediate files: delete all `sast/weakcrypto-batch-*.md` files after the final `sast/weakcrypto-results.md` is written. **Preserve** `sast/weakcrypto-recon.md` — the orchestrator reuses it on later runs.
