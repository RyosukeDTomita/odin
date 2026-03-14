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

**Odin** is a [Burp Suite](https://portswigger.net/burp) extension that passively inspects HTTP history and reports missing or misconfigured security headers as scanner issues.

It hooks into Burp's passive scan engine via the [Montoya API](https://portswigger.net/burp/documentation/desktop/extend-burp/extensions/creating/api), so findings appear automatically in the **Scanner > Issue activity** tab as you browse — no manual triggering required.

### What Odin checks

| Category | Headers / Attributes |
|---|---|
| CORS | `Access-Control-Allow-Origin`, `Access-Control-Allow-Credentials`, `Access-Control-Allow-Methods`, `Access-Control-Allow-Headers` |
| Cookie attributes | `Secure`, `HttpOnly`, `SameSite`, `Expires` / `Max-Age`, `Path`, `Domain` |
| Security headers | `X-Content-Type-Options`, `Strict-Transport-Security`, `X-Frame-Options` / CSP `frame-ancestors`, `Content-Security-Policy`, `Referrer-Policy`, `Permissions-Policy` |

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

4. Check **Scanner > Issue activity** — Odin reports findings with severity and remediation guidance.

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
