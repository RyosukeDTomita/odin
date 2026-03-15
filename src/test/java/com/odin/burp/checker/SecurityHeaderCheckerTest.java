package com.odin.burp.checker;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.odin.burp.Finding;
import com.odin.burp.issue.IssueDefinition;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class SecurityHeaderCheckerTest {

  private SecurityHeaderChecker checker;
  private HttpRequestResponse reqRes;
  private HttpResponse response;
  private HttpRequest request;

  @BeforeEach
  void setUp() {
    checker = new SecurityHeaderChecker();
    reqRes = mock(HttpRequestResponse.class);
    response = mock(HttpResponse.class);
    request = mock(HttpRequest.class);
    when(reqRes.response()).thenReturn(response);
    when(reqRes.request()).thenReturn(request);
    when(request.url()).thenReturn("https://example.com/");
    when(response.headerValue(anyString())).thenReturn(null);
  }

  // ---- X-Content-Type-Options ----

  @Test
  void xctoMissing_reportsXctoMissing() {
    assertContains(checker.check(reqRes), IssueDefinition.XCTO_MISSING);
  }

  @Test
  void xctoNosniff_noXctoFindings() {
    when(response.headerValue("X-Content-Type-Options")).thenReturn("nosniff");
    List<Finding> f = checker.check(reqRes);
    assertNotContains(f, IssueDefinition.XCTO_MISSING);
    assertNotContains(f, IssueDefinition.XCTO_INVALID);
  }

  @Test
  void xctoNosniffUppercase_treatedAsValid() {
    when(response.headerValue("X-Content-Type-Options")).thenReturn("NOSNIFF");
    assertNotContains(checker.check(reqRes), IssueDefinition.XCTO_INVALID);
  }

  @Test
  void xctoInvalidValue_reportsXctoInvalid() {
    when(response.headerValue("X-Content-Type-Options")).thenReturn("sniff");
    List<Finding> f = checker.check(reqRes);
    assertContains(f, IssueDefinition.XCTO_INVALID);
    assertNotContains(f, IssueDefinition.XCTO_MISSING);
  }

  // ---- Strict-Transport-Security ----

  @Test
  void httpsWithoutHsts_reportsHstsMissing() {
    assertContains(checker.check(reqRes), IssueDefinition.HSTS_MISSING);
  }

  @Test
  void httpWithoutHsts_noHstsFinding() {
    when(request.url()).thenReturn("http://example.com/");
    assertNotContains(checker.check(reqRes), IssueDefinition.HSTS_MISSING);
  }

  @Test
  void hstsWeakMaxAge_reportsWeakMaxAge() {
    when(response.headerValue("Strict-Transport-Security")).thenReturn("max-age=86400");
    assertContains(checker.check(reqRes), IssueDefinition.HSTS_WEAK_MAX_AGE);
  }

  @Test
  void hstsMaxAgeZero_reportsWeakMaxAge() {
    when(response.headerValue("Strict-Transport-Security")).thenReturn("max-age=0");
    assertContains(checker.check(reqRes), IssueDefinition.HSTS_WEAK_MAX_AGE);
  }

  @Test
  void hstsMaxAgeNoPattern_reportsWeakMaxAge() {
    // max-age が存在しない場合は 0 扱い
    when(response.headerValue("Strict-Transport-Security")).thenReturn("includeSubDomains");
    assertContains(checker.check(reqRes), IssueDefinition.HSTS_WEAK_MAX_AGE);
  }

  @Test
  void hstsMaxAgeExactlyOneYear_noWeakMaxAgeFinding() {
    when(response.headerValue("Strict-Transport-Security"))
        .thenReturn("max-age=31536000; includeSubDomains");
    assertNotContains(checker.check(reqRes), IssueDefinition.HSTS_WEAK_MAX_AGE);
  }

  @Test
  void hstsMaxAgeAboveOneYear_noWeakMaxAgeFinding() {
    when(response.headerValue("Strict-Transport-Security"))
        .thenReturn("max-age=63072000; includeSubDomains");
    assertNotContains(checker.check(reqRes), IssueDefinition.HSTS_WEAK_MAX_AGE);
  }

  @Test
  void hstsWithoutIncludeSubDomains_reportsNoIncludeSubDomains() {
    when(response.headerValue("Strict-Transport-Security")).thenReturn("max-age=31536000");
    assertContains(checker.check(reqRes), IssueDefinition.HSTS_NO_INCLUDE_SUBDOMAINS);
  }

  @Test
  void hstsWithIncludeSubDomains_noNoIncludeSubDomainsFinding() {
    when(response.headerValue("Strict-Transport-Security"))
        .thenReturn("max-age=31536000; includeSubDomains");
    assertNotContains(checker.check(reqRes), IssueDefinition.HSTS_NO_INCLUDE_SUBDOMAINS);
  }

  @Test
  void hstsIncludeSubDomainsCaseInsensitive_noFinding() {
    when(response.headerValue("Strict-Transport-Security"))
        .thenReturn("max-age=31536000; IncludeSubDomains");
    assertNotContains(checker.check(reqRes), IssueDefinition.HSTS_NO_INCLUDE_SUBDOMAINS);
  }

  // ---- X-Frame-Options / CSP frame-ancestors ----

  @Test
  void noXfoNoCsp_reportsXfoMissing() {
    assertContains(checker.check(reqRes), IssueDefinition.XFO_MISSING);
  }

  @Test
  void xfoPresent_noXfoMissingFinding() {
    when(response.headerValue("X-Frame-Options")).thenReturn("DENY");
    assertNotContains(checker.check(reqRes), IssueDefinition.XFO_MISSING);
  }

  @Test
  void cspWithFrameAncestors_noXfoMissingFinding() {
    when(response.headerValue("Content-Security-Policy")).thenReturn("frame-ancestors 'none'");
    assertNotContains(checker.check(reqRes), IssueDefinition.XFO_MISSING);
  }

  @Test
  void cspWithoutFrameAncestors_reportsXfoMissing() {
    when(response.headerValue("Content-Security-Policy")).thenReturn("default-src 'self'");
    assertContains(checker.check(reqRes), IssueDefinition.XFO_MISSING);
  }

  // ---- Content-Security-Policy ----

  @Test
  void cspMissing_reportsCspMissing() {
    assertContains(checker.check(reqRes), IssueDefinition.CSP_MISSING);
  }

  @Test
  void cspPresent_noCspMissingFinding() {
    when(response.headerValue("Content-Security-Policy")).thenReturn("default-src 'self'");
    assertNotContains(checker.check(reqRes), IssueDefinition.CSP_MISSING);
  }

  // ---- Referrer-Policy ----

  @Test
  void referrerPolicyMissing_reportsReferrerPolicyMissing() {
    assertContains(checker.check(reqRes), IssueDefinition.REFERRER_POLICY_MISSING);
  }

  @Test
  void referrerPolicyUnsafeUrl_reportsUnsafe() {
    when(response.headerValue("Referrer-Policy")).thenReturn("unsafe-url");
    List<Finding> f = checker.check(reqRes);
    assertContains(f, IssueDefinition.REFERRER_POLICY_UNSAFE);
    assertNotContains(f, IssueDefinition.REFERRER_POLICY_MISSING);
  }

  @Test
  void referrerPolicyNoReferrerWhenDowngrade_reportsUnsafe() {
    when(response.headerValue("Referrer-Policy")).thenReturn("no-referrer-when-downgrade");
    assertContains(checker.check(reqRes), IssueDefinition.REFERRER_POLICY_UNSAFE);
  }

  @Test
  void referrerPolicyStrictOrigin_noReferrerFindings() {
    when(response.headerValue("Referrer-Policy")).thenReturn("strict-origin-when-cross-origin");
    List<Finding> f = checker.check(reqRes);
    assertNotContains(f, IssueDefinition.REFERRER_POLICY_MISSING);
    assertNotContains(f, IssueDefinition.REFERRER_POLICY_UNSAFE);
  }

  @Test
  void referrerPolicyNoReferrer_noUnsafeFinding() {
    when(response.headerValue("Referrer-Policy")).thenReturn("no-referrer");
    assertNotContains(checker.check(reqRes), IssueDefinition.REFERRER_POLICY_UNSAFE);
  }

  // ---- Permissions-Policy ----

  @Test
  void permissionsPolicyMissing_reportsPermissionsPolicyMissing() {
    assertContains(checker.check(reqRes), IssueDefinition.PERMISSIONS_POLICY_MISSING);
  }

  @Test
  void permissionsPolicyPresent_noPermissionsPolicyMissingFinding() {
    when(response.headerValue("Permissions-Policy")).thenReturn("camera=(), microphone=()");
    assertNotContains(checker.check(reqRes), IssueDefinition.PERMISSIONS_POLICY_MISSING);
  }

  // ---- helpers ----

  private void assertContains(List<Finding> findings, IssueDefinition expected) {
    assertTrue(
        findings.stream().anyMatch(f -> f.definition() == expected),
        "Expected finding " + expected + " not present");
  }

  private void assertNotContains(List<Finding> findings, IssueDefinition unexpected) {
    assertFalse(
        findings.stream().anyMatch(f -> f.definition() == unexpected),
        "Unexpected finding " + unexpected + " present");
  }
}
