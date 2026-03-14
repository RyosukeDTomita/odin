# Odin: HTTP Security Header Linter

![mit license](https://img.shields.io/github/license/RyosukeDTomita/odin)
[![Test](https://github.com/RyosukeDTomita/odin/actions/workflows/test-coverage.yml/badge.svg)](https://github.com/RyosukeDTomita/odin/actions/workflows/test-coverage.yml)
[![codecov](https://codecov.io/gh/RyosukeDTomita/odin/branch/main/graph/badge.svg)](https://codecov.io/gh/RyosukeDTomita/odin)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/RyosukeDTomita/odin/badge)](https://securityscorecards.dev/viewer/?uri=github.com/RyosukeDTomita/odin)
[![Scorecard supply-chain security](https://github.com/RyosukeDTomita/odin/actions/workflows/scorecard.yml/badge.svg)](https://github.com/RyosukeDTomita/odin/actions/workflows/scorecard.yml)
[![CodeQL](https://github.com/RyosukeDTomita/odin/actions/workflows/codeql.yml/badge.svg)](https://github.com/RyosukeDTomita/odin/actions/workflows/codeql.yml)

## INDEX

- [ABOUT](#about)
- [ENVIRONMENT](#environment)
- [HOW TO USE](#how-to-use)
- [For Developers](#for-developers)
- [BApp Store Acceptance Criteria Self-Check](#bapp-store-acceptance-criteria-self-check)

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

| Severity | Category | Trigger condition | Example (response header) | Reference |
|---|---|---|---|---|
| HIGH | CORS | `ACAO` reflects the request `Origin` | `Access-Control-Allow-Origin: https://evil.com` (mirrors `Origin: https://evil.com`) | [OWASP](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html) |
| HIGH | CORS | `ACAO` reflects `Origin` **and** `ACAC: true` | `Access-Control-Allow-Origin: https://evil.com`<br>`Access-Control-Allow-Credentials: true` | [OWASP](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html) |
| HIGH | CORS | `ACAO: *` **and** `ACAC: true` | `Access-Control-Allow-Origin: *`<br>`Access-Control-Allow-Credentials: true` | [OWASP](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html) |
| MEDIUM | CORS | `ACAO: *` | `Access-Control-Allow-Origin: *` | [OWASP](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html) |
| MEDIUM | Cookie | HTTPS response, `Set-Cookie` has no `Secure` | `Set-Cookie: session=abc; HttpOnly` | [MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie) |
| MEDIUM | Cookie | `SameSite=None` without `Secure` | `Set-Cookie: session=abc; SameSite=None` | [MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie) |
| MEDIUM | Security | HTTPS response, `Strict-Transport-Security` absent | _(header absent)_ | [MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security) |
| LOW | CORS | `ACAM` contains `PUT`, `DELETE`, or `PATCH` | `Access-Control-Allow-Methods: GET, POST, PUT, DELETE` | [OWASP](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html) |
| LOW | Cookie | `Set-Cookie` has no `HttpOnly` | `Set-Cookie: session=abc; Secure` | [MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie) |
| LOW | Cookie | `Set-Cookie` has no `SameSite` | `Set-Cookie: session=abc; Secure; HttpOnly` | [MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie) |
| LOW | Cookie | `SameSite=None` (even with `Secure`) | `Set-Cookie: session=abc; Secure; SameSite=None` | [MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie) |
| LOW | Security | `X-Frame-Options` absent **and** CSP has no `frame-ancestors` | _(both absent, or CSP present but without `frame-ancestors`)_ | [MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options) |
| LOW | Security | `Content-Security-Policy` absent | _(header absent)_ | [OWASP](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html) |
| LOW | Security | `X-Content-Type-Options` absent | _(header absent)_ | [MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options) |
| LOW | Security | `X-Content-Type-Options` value is not `nosniff` | `X-Content-Type-Options: sniff` | [MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options) |
| LOW | Security | `max-age` < 31536000 (1 year) | `Strict-Transport-Security: max-age=3600` | [MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security) |
| LOW | Security | `Referrer-Policy` is `unsafe-url` or `no-referrer-when-downgrade` | `Referrer-Policy: unsafe-url`<br>`Referrer-Policy: no-referrer-when-downgrade` | [MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy) |
| INFORMATION | Cookie | `Set-Cookie` has neither `Expires` nor `Max-Age` | `Set-Cookie: session=abc; Secure; HttpOnly` | [MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie) |
| INFORMATION | Cookie | `Set-Cookie` has `Path=/` | `Set-Cookie: session=abc; Path=/` | [MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie) |
| INFORMATION | Cookie | `Set-Cookie` has a `Domain=` attribute | `Set-Cookie: session=abc; Domain=.example.com` | [MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie) |
| INFORMATION | Security | `Strict-Transport-Security` has no `includeSubDomains` | `Strict-Transport-Security: max-age=31536000` | [MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security) |
| INFORMATION | Security | `Referrer-Policy` absent | _(header absent)_ | [MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy) |
| INFORMATION | Security | `Permissions-Policy` absent | _(header absent)_ | [MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy) |
| INFORMATION | CORS | `ACAH: *` | `Access-Control-Allow-Headers: *` | [OWASP](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html) |

---

## ENVIRONMENT

- Nix Flake
  - Java: 21
  - Gradle: 8.7
    - montoya-api: 2026.2
    - Shadow plugin: 8.3.5 (`com.gradleup.shadow`)
    - jacoco
- tested on [Burp Suite Community Edition 2026.2.3 Linux(x64)](https://portswigger.net/burp/releases/professional-community-edition-2026-2-3)

---

## HOW TO USE

1. Build the JAR (or download a release):

    ```shell
    ./gradlew shadowJar
    # Output: build/libs/odin-0.0.1.jar
    ```

    > [!NOTE]
    > You can download `.jar` from [latest Releases](https://github.com/RyosukeDTomita/odin/releases)

2. Open Burp Suite and go to **Extensions > Add**.
   - Extension type: **Java**
   - Select file: `build/libs/odin-0.0.1.jar`

3. Browse the target application through Burp Proxy as usual.

4. Check findings in **Proxy > HTTP history** (color-coded highlights and notes) or **Extensions > Odin > Output** (full log).

> [!NOTE]
> Odin only performs **passive** analysis on already-captured traffic. It never sends additional requests to the target.

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
# Output: build/libs/odin-0.0.1.jar
```

### Release

1. Update the version in `build.gradle.kts`.
1. Update any version strings in `README.md` (JAR filename examples).
1. Run tests and build the JAR:

   ```shell
   ./gradlew test shadowJar
   ```

1. Commit the version bump:

   ```shell
   git add build.gradle.kts README.md
   git commit -m "Release vX.Y.Z"
   ```

1. Create a tag and push:

   ```shell
   git tag vX.Y.Z
   git push
   git push --tags
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
