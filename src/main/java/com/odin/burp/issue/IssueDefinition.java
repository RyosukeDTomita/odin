package com.odin.burp.issue;

import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

public enum IssueDefinition {

  // CORS
  CORS_WILDCARD_ORIGIN(
      "CORS: Wildcard Access-Control-Allow-Origin",
      "The response contains <b>Access-Control-Allow-Origin: *</b>, which allows any origin to read the response.",
      "Restrict Access-Control-Allow-Origin to specific trusted origins rather than using a wildcard.",
      AuditIssueSeverity.MEDIUM,
      AuditIssueConfidence.CERTAIN,
      AuditIssueSeverity.HIGH),
  CORS_CREDENTIALS_WITH_WILDCARD(
      "CORS: Access-Control-Allow-Credentials with Wildcard Origin",
      "The response sets <b>Access-Control-Allow-Credentials: true</b> alongside a wildcard origin. While browsers block this combination, it indicates a misconfigured CORS policy.",
      "Do not use wildcard origins when credentials are required. Specify explicit trusted origins.",
      AuditIssueSeverity.HIGH,
      AuditIssueConfidence.CERTAIN,
      AuditIssueSeverity.HIGH),
  CORS_REFLECTED_ORIGIN(
      "CORS: Reflected Origin in Access-Control-Allow-Origin",
      "The response reflects the request's Origin header value in <b>Access-Control-Allow-Origin</b> without validation. This may allow any origin to make credentialed cross-origin requests.",
      "Maintain an explicit allowlist of trusted origins and only reflect origins that are on the list.",
      AuditIssueSeverity.HIGH,
      AuditIssueConfidence.FIRM,
      AuditIssueSeverity.HIGH),
  CORS_CREDENTIALS_WITH_REFLECTED(
      "CORS: Access-Control-Allow-Credentials with Reflected Origin",
      "The response reflects the request's Origin header and also sets <b>Access-Control-Allow-Credentials: true</b>. This allows any origin to make credentialed cross-origin requests, enabling cross-origin data theft.",
      "Maintain an explicit allowlist of trusted origins. Never reflect arbitrary origins when credentials are allowed.",
      AuditIssueSeverity.HIGH,
      AuditIssueConfidence.CERTAIN,
      AuditIssueSeverity.HIGH),
  CORS_DANGEROUS_METHODS(
      "CORS: Dangerous Methods in Access-Control-Allow-Methods",
      "The response includes write methods (PUT, DELETE, or PATCH) in <b>Access-Control-Allow-Methods</b>, increasing the attack surface for cross-origin requests.",
      "Restrict CORS allowed methods to only those required by the application. Avoid exposing PUT, DELETE, or PATCH unless necessary.",
      AuditIssueSeverity.LOW,
      AuditIssueConfidence.CERTAIN,
      AuditIssueSeverity.MEDIUM),
  CORS_WILDCARD_HEADERS(
      "CORS: Wildcard Access-Control-Allow-Headers",
      "The response sets <b>Access-Control-Allow-Headers: *</b>, allowing cross-origin requests to include any header.",
      "Restrict Access-Control-Allow-Headers to only the headers required by the application.",
      AuditIssueSeverity.LOW,
      AuditIssueConfidence.CERTAIN,
      AuditIssueSeverity.LOW),

  // Cookie
  COOKIE_MISSING_SECURE(
      "Cookie: Missing Secure Flag",
      "A cookie is set without the <b>Secure</b> flag on an HTTPS response. The cookie may be transmitted over unencrypted HTTP connections.",
      "Add the Secure flag to all cookies set on HTTPS responses.",
      AuditIssueSeverity.MEDIUM,
      AuditIssueConfidence.CERTAIN,
      AuditIssueSeverity.MEDIUM),
  COOKIE_MISSING_HTTPONLY(
      "Cookie: Missing HttpOnly Flag",
      "A cookie is set without the <b>HttpOnly</b> flag. Client-side scripts can access this cookie, increasing the impact of XSS attacks.",
      "Add the HttpOnly flag to cookies that do not need to be accessed by JavaScript.",
      AuditIssueSeverity.LOW,
      AuditIssueConfidence.CERTAIN,
      AuditIssueSeverity.MEDIUM),
  COOKIE_SESSION_COOKIE(
      "Cookie: Session Cookie (No Expiry)",
      "A cookie is set without <b>Expires</b> or <b>Max-Age</b> attributes, making it a session cookie that expires when the browser closes.",
      "Consider whether persistent cookies are more appropriate. If session cookies are intentional, ensure proper session management is in place.",
      AuditIssueSeverity.INFORMATION,
      AuditIssueConfidence.CERTAIN,
      AuditIssueSeverity.INFORMATION),
  COOKIE_BROAD_PATH(
      "Cookie: Overly Broad Path (/)",
      "A cookie uses <b>Path=/</b>, making it available to all paths on the domain.",
      "Restrict the cookie Path to only the paths that require access to the cookie.",
      AuditIssueSeverity.INFORMATION,
      AuditIssueConfidence.CERTAIN,
      AuditIssueSeverity.INFORMATION),
  COOKIE_DOMAIN_ATTRIBUTE(
      "Cookie: Domain Attribute Set",
      "A cookie sets the <b>Domain</b> attribute, which may expose the cookie to all subdomains of the specified domain.",
      "Only set the Domain attribute if cookie sharing across subdomains is intentional and required.",
      AuditIssueSeverity.INFORMATION,
      AuditIssueConfidence.CERTAIN,
      AuditIssueSeverity.INFORMATION),
  COOKIE_SAMESITE_MISSING(
      "Cookie: Missing SameSite Attribute",
      "A cookie is set without the <b>SameSite</b> attribute. Without SameSite, the cookie may be sent with cross-site requests, increasing CSRF risk.",
      "Add SameSite=Strict or SameSite=Lax to cookies unless cross-site transmission is required.",
      AuditIssueSeverity.LOW,
      AuditIssueConfidence.CERTAIN,
      AuditIssueSeverity.LOW),
  COOKIE_SAMESITE_NONE_WITHOUT_SECURE(
      "Cookie: SameSite=None Without Secure Flag",
      "A cookie sets <b>SameSite=None</b> without the <b>Secure</b> flag. Modern browsers will reject this cookie.",
      "Add the Secure flag when using SameSite=None.",
      AuditIssueSeverity.MEDIUM,
      AuditIssueConfidence.CERTAIN,
      AuditIssueSeverity.MEDIUM),
  COOKIE_SAMESITE_NONE(
      "Cookie: SameSite=None",
      "A cookie uses <b>SameSite=None</b>, enabling cross-site transmission. This is weaker than SameSite=Strict or SameSite=Lax.",
      "Evaluate whether cross-site cookie transmission is required. Use SameSite=Strict or SameSite=Lax where possible.",
      AuditIssueSeverity.LOW,
      AuditIssueConfidence.FIRM,
      AuditIssueSeverity.LOW),

  // Security headers
  XCTO_MISSING(
      "Missing X-Content-Type-Options Header",
      "The response does not include the <b>X-Content-Type-Options</b> header. Browsers may MIME-sniff the response content type, which can lead to security vulnerabilities.",
      "Add the header: X-Content-Type-Options: nosniff",
      AuditIssueSeverity.LOW,
      AuditIssueConfidence.CERTAIN,
      AuditIssueSeverity.LOW),
  XCTO_INVALID(
      "Invalid X-Content-Type-Options Header",
      "The response includes <b>X-Content-Type-Options</b> but with an invalid value. Only 'nosniff' is a valid value.",
      "Set the header to: X-Content-Type-Options: nosniff",
      AuditIssueSeverity.LOW,
      AuditIssueConfidence.CERTAIN,
      AuditIssueSeverity.LOW),
  HSTS_MISSING(
      "Missing Strict-Transport-Security Header",
      "The HTTPS response does not include the <b>Strict-Transport-Security</b> header. Without HSTS, browsers may be tricked into connecting via HTTP.",
      "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
      AuditIssueSeverity.MEDIUM,
      AuditIssueConfidence.CERTAIN,
      AuditIssueSeverity.MEDIUM),
  HSTS_WEAK_MAX_AGE(
      "Strict-Transport-Security: Short max-age",
      "The <b>Strict-Transport-Security</b> header has a max-age below 1 year (31536000 seconds), providing limited protection.",
      "Set max-age to at least 31536000 (1 year). Consider submitting to the HSTS preload list.",
      AuditIssueSeverity.LOW,
      AuditIssueConfidence.CERTAIN,
      AuditIssueSeverity.LOW),
  HSTS_NO_INCLUDE_SUBDOMAINS(
      "Strict-Transport-Security: Missing includeSubDomains",
      "The <b>Strict-Transport-Security</b> header does not include the <b>includeSubDomains</b> directive, leaving subdomains unprotected.",
      "Add includeSubDomains to the HSTS header if all subdomains support HTTPS.",
      AuditIssueSeverity.INFORMATION,
      AuditIssueConfidence.CERTAIN,
      AuditIssueSeverity.INFORMATION),
  XFO_MISSING(
      "Missing X-Frame-Options and CSP frame-ancestors",
      "The response includes neither <b>X-Frame-Options</b> nor a <b>Content-Security-Policy</b> with a frame-ancestors directive. The page may be embeddable in frames, enabling clickjacking attacks.",
      "Add X-Frame-Options: DENY or SAMEORIGIN, or use Content-Security-Policy: frame-ancestors 'none' or 'self'.",
      AuditIssueSeverity.LOW,
      AuditIssueConfidence.CERTAIN,
      AuditIssueSeverity.LOW),
  CSP_MISSING(
      "Missing Content-Security-Policy Header",
      "The response does not include a <b>Content-Security-Policy</b> header. Without CSP, browsers apply no restrictions on resource loading, increasing XSS risk.",
      "Implement a Content-Security-Policy header appropriate for the application's resource requirements.",
      AuditIssueSeverity.LOW,
      AuditIssueConfidence.TENTATIVE,
      AuditIssueSeverity.MEDIUM),
  REFERRER_POLICY_MISSING(
      "Missing Referrer-Policy Header",
      "The response does not include a <b>Referrer-Policy</b> header. The browser's default referrer behavior may leak URL information to third parties.",
      "Add a Referrer-Policy header such as: Referrer-Policy: strict-origin-when-cross-origin",
      AuditIssueSeverity.INFORMATION,
      AuditIssueConfidence.CERTAIN,
      AuditIssueSeverity.INFORMATION),
  REFERRER_POLICY_UNSAFE(
      "Unsafe Referrer-Policy",
      "The response sets <b>Referrer-Policy</b> to an unsafe value that may leak full URLs to cross-origin destinations.",
      "Use a restrictive Referrer-Policy such as 'strict-origin-when-cross-origin', 'strict-origin', or 'no-referrer'.",
      AuditIssueSeverity.LOW,
      AuditIssueConfidence.CERTAIN,
      AuditIssueSeverity.LOW),
  PERMISSIONS_POLICY_MISSING(
      "Missing Permissions-Policy Header",
      "The response does not include a <b>Permissions-Policy</b> header. Browser features (camera, microphone, geolocation, etc.) are not explicitly restricted.",
      "Add a Permissions-Policy header to restrict access to browser features not required by the application.",
      AuditIssueSeverity.INFORMATION,
      AuditIssueConfidence.CERTAIN,
      AuditIssueSeverity.INFORMATION);

  private final String name;
  private final String background;
  private final String remediation;
  private final AuditIssueSeverity severity;
  private final AuditIssueConfidence confidence;
  private final AuditIssueSeverity typicalSeverity;

  IssueDefinition(
      String name,
      String background,
      String remediation,
      AuditIssueSeverity severity,
      AuditIssueConfidence confidence,
      AuditIssueSeverity typicalSeverity) {
    this.name = name;
    this.background = background;
    this.remediation = remediation;
    this.severity = severity;
    this.confidence = confidence;
    this.typicalSeverity = typicalSeverity;
  }

  public String getName() {
    return name;
  }

  public String getBackground() {
    return background;
  }

  public String getRemediation() {
    return remediation;
  }

  public AuditIssueSeverity getSeverity() {
    return severity;
  }

  public AuditIssueConfidence getConfidence() {
    return confidence;
  }

  public AuditIssueSeverity getTypicalSeverity() {
    return typicalSeverity;
  }
}
