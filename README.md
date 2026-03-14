# Odin: HTTP Security Header Linter

![mit license](https://img.shields.io/github/license/RyosukeDTomita/odin)
[![Test](https://github.com/RyosukeDTomita/odin/actions/workflows/test-coverage.yml/badge.svg)](https://github.com/RyosukeDTomita/odin/actions/workflows/test-coverage.yml)
[![codecov](https://codecov.io/gh/RyosukeDTomita/odin/branch/main/graph/badge.svg)](https://codecov.io/gh/RyosukeDTomita/odin)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/RyosukeDTomita/odin/badge)](https://securityscorecards.dev/viewer/?uri=github.com/RyosukeDTomita/odin)
[![Scorecard supply-chain security](https://github.com/RyosukeDTomita/odin/actions/workflows/scorecard.yml/badge.svg)](https://github.com/RyosukeDTomita/odin/actions/workflows/scorecard.yml)
[![CodeQL](https://github.com/RyosukeDTomita/odin/actions/workflows/codeql.yml/badge.svg)](https://github.com/RyosukeDTomita/odin/actions/workflows/codeql.yml)

## INDEX

- [ABOUT](#about)
- [HOW TO USE](#how-to-use)
- [ENVIRONMENT](#environment)
- [For Developers](#for-developers)

---

## ABOUT

**Odin** is a [Burp Suite](https://portswigger.net/burp) extension that passively inspects HTTP traffic and reports missing or misconfigured security headers.

It works with both **Community and Professional** editions via the [Montoya API](https://portswigger.net/burp/documentation/desktop/extend-burp/extensions/creating/api). Findings appear automatically as you browse — no manual triggering required.

- **Proxy > HTTP history** — color-coded highlight and note on each flagged request
- **Extensions > Odin > Output** — full findings log

### What Odin checks

| Category | Headers / Attributes |
|---|---|
| CORS | `Access-Control-Allow-Origin`, `Access-Control-Allow-Credentials`, `Access-Control-Allow-Methods`, `Access-Control-Allow-Headers` |
| Cookie attributes | `Secure`, `HttpOnly`, `SameSite`, `Expires` / `Max-Age`, `Path`, `Domain` |
| Security headers | `X-Content-Type-Options`, `Strict-Transport-Security`, `X-Frame-Options` / CSP `frame-ancestors`, `Content-Security-Policy`, `Referrer-Policy`, `Permissions-Policy` |

### Findings Reference

| Severity | Category | Finding | Trigger condition | Example (response header) | Reference |
|---|---|---|---|---|---|
| HIGH | CORS | CORS: Reflected Origin | `ACAO` value equals the request `Origin` header | `Access-Control-Allow-Origin: https://evil.com` (mirrors `Origin: https://evil.com`) | [OWASP](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html) |
| HIGH | CORS | CORS: Credentials + Reflected Origin | Reflected `ACAO` **and** `ACAC: true` | `Access-Control-Allow-Origin: https://evil.com`<br>`Access-Control-Allow-Credentials: true` | [OWASP](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html) |
| HIGH | CORS | CORS: Credentials + Wildcard Origin | `ACAO: *` **and** `ACAC: true` | `Access-Control-Allow-Origin: *`<br>`Access-Control-Allow-Credentials: true` | [OWASP](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html) |
| MEDIUM | CORS | CORS: Wildcard Origin | `ACAO: *` | `Access-Control-Allow-Origin: *` | [OWASP](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html) |
| MEDIUM | Cookie | Cookie: Missing Secure Flag | HTTPS response, `Set-Cookie` has no `Secure` attribute | `Set-Cookie: session=abc; HttpOnly` | [MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie) |
| MEDIUM | Cookie | Cookie: SameSite=None Without Secure | `SameSite=None` without `Secure` attribute | `Set-Cookie: session=abc; SameSite=None` | [MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie) |
| MEDIUM | Security | HSTS Missing | HTTPS response, `Strict-Transport-Security` header absent | _(header absent)_ | [MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security) |
| LOW | CORS | CORS: Dangerous Methods | `ACAM` contains `PUT`, `DELETE`, or `PATCH` | `Access-Control-Allow-Methods: GET, POST, PUT, DELETE` | [OWASP](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html) |
| LOW | Cookie | Cookie: Missing HttpOnly | `Set-Cookie` has no `HttpOnly` attribute | `Set-Cookie: session=abc; Secure` | [MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie) |
| LOW | Cookie | Cookie: Missing SameSite | `Set-Cookie` has no `SameSite` attribute | `Set-Cookie: session=abc; Secure; HttpOnly` | [MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie) |
| LOW | Cookie | Cookie: SameSite=None | `SameSite=None` (even with `Secure`) | `Set-Cookie: session=abc; Secure; SameSite=None` | [MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie) |
| LOW | Security | XFO Missing | `X-Frame-Options` absent **and** `Content-Security-Policy` has no `frame-ancestors` directive | _(both headers absent, or CSP present but without `frame-ancestors`)_ | [MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options) |
| LOW | Security | CSP Missing | `Content-Security-Policy` header absent | _(header absent)_ | [OWASP](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html) |
| LOW | Security | XCTO Missing | `X-Content-Type-Options` header absent | _(header absent)_ | [MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options) |
| LOW | Security | XCTO Invalid | `X-Content-Type-Options` value is not `nosniff` | `X-Content-Type-Options: sniff` | [MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options) |
| LOW | Security | HSTS Weak max-age | `max-age` < 31536000 (1 year) | `Strict-Transport-Security: max-age=3600` | [MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security) |
| LOW | Security | Referrer-Policy Unsafe | Value is `unsafe-url` or `no-referrer-when-downgrade` | `Referrer-Policy: unsafe-url`<br>`Referrer-Policy: no-referrer-when-downgrade` | [MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy) |
| INFORMATION | Cookie | Cookie: Session Cookie | `Set-Cookie` has neither `Expires` nor `Max-Age` | `Set-Cookie: session=abc; Secure; HttpOnly` | [MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie) |
| INFORMATION | Cookie | Cookie: Overly Broad Path | `Set-Cookie` has `Path=/` | `Set-Cookie: session=abc; Path=/` | [MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie) |
| INFORMATION | Cookie | Cookie: Domain Attribute Set | `Set-Cookie` has a `Domain=` attribute | `Set-Cookie: session=abc; Domain=.example.com` | [MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie) |
| INFORMATION | Security | HSTS: no includeSubDomains | `Strict-Transport-Security` has no `includeSubDomains` directive | `Strict-Transport-Security: max-age=31536000` | [MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security) |
| INFORMATION | Security | Referrer-Policy Missing | `Referrer-Policy` header absent | _(header absent)_ | [MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy) |
| INFORMATION | Security | Permissions-Policy Missing | `Permissions-Policy` header absent | _(header absent)_ | [MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy) |
| INFORMATION | CORS | CORS: Wildcard Headers | `ACAH: *` | `Access-Control-Allow-Headers: *` | [OWASP](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html) |

---

## HOW TO USE

1. Build the JAR (or download a release):
    ```shell
    ./gradlew shadowJar
    # Output: build/libs/odin-1.0.0.jar
    ```

2. Open Burp Suite and go to **Extensions > Add**.
   - Extension type: **Java**
   - Select file: `build/libs/odin-1.0.0.jar`

3. Browse the target application through Burp Proxy as usual.

4. Check findings in **Proxy > HTTP history** (color-coded highlights and notes) or **Extensions > Odin > Output** (full log).

> [!NOTE]
> Odin only performs **passive** analysis on already-captured traffic. It never sends additional requests to the target.

---

## ENVIRONMENT

- Java: 21
  - montoya-api: 2026.2
- Gradle: 8.7
- Shadow plugin: 8.3.5 (`com.gradleup.shadow`)
- Nix: managed via `flake.nix` + direnv (`use flake`)

---

## For Developers

### Setup

```shell
# Enter the dev shell (provides Java 21 + Gradle automatically via direnv)
direnv allow
# or manually:
nix develop
```

### Build

```shell
./gradlew shadowJar
# Output: build/libs/odin-1.0.0.jar
```

---

## BApp Store acceptance criteria (self check)

This extension is designed to meet the [acceptance criteria](https://portswigger.net/burp/documentation/desktop/extend-burp/extensions/creating/bapp-store-acceptance-criteria) for the **BApp Store**.

### 1. It performs a unique function

Yes.
There is no existing BApp that performs comprehensive passive linting of security response headers (CORS, Cookie attributes, HSTS, CSP, Referrer-Policy, Permissions-Policy) as scanner issues in a single extension.

### 2. It has a clear, descriptive name

Yes.
The extension name is set to `Odin - Security Header Linter` and clearly describes its function.

### 3. It operates securely

Yes.

- All HTTP header values are treated as untrusted input.
- Header values displayed in issue details are HTML-sanitized before use.
- No `eval`, reflection, or shell execution of header data.

### 4. It includes all dependencies

Yes.
`montoya-api` is declared `compileOnly` (Burp provides it at runtime). All other dependencies are bundled via the Shadow plugin into a single fat JAR. See [build.gradle](./build.gradle).

### 5. It uses threads to maintain responsiveness

Yes.
`passiveAudit()` is invoked by Burp on its own scanner background thread. The extension performs no Swing EDT operations and no blocking I/O.

### 6. It unloads cleanly

Yes.
`api.extension().registerUnloadingHandler()` is called in `OdinExtension.initialize()`.

### 7. It uses Burp networking

Out of scope.
This extension makes no outbound HTTP requests. It only inspects already-captured traffic.

### 8. It supports offline working

Yes.
The extension operates entirely offline — all checks are pure in-memory analysis of HTTP messages.

### 9. It can cope with large projects

Yes.

- No long-term references to `HttpRequestResponse` objects are held.
- Each `passiveAudit()` invocation is stateless.

### 10. It provides a parent for GUI elements

Out of scope.
This extension adds no custom GUI tabs or dialogs. All output is through Burp's native scanner issue panel.

### 11. Montoya API Artifact Usage

Yes.
`net.portswigger.burp.extensions:montoya-api` is referenced via Gradle as required.

### 12. Montoya API for AI Functionality

Out of scope.
This extension does not use AI features.
