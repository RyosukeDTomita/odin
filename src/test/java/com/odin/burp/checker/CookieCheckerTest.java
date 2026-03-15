package com.odin.burp.checker;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.odin.burp.Finding;
import com.odin.burp.issue.IssueDefinition;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class CookieCheckerTest {

    private CookieChecker checker;
    private HttpRequestResponse reqRes;
    private HttpResponse response;
    private HttpRequest request;

    @BeforeEach
    void setUp() {
        checker  = new CookieChecker();
        reqRes   = mock(HttpRequestResponse.class);
        response = mock(HttpResponse.class);
        request  = mock(HttpRequest.class);
        when(reqRes.response()).thenReturn(response);
        when(reqRes.request()).thenReturn(request);
        when(request.url()).thenReturn("https://example.com/");
        when(response.headers()).thenReturn(List.of());
    }

    /** Cookie 1つをモックして check() を実行するヘルパー */
    private List<Finding> check(String url, String cookieValue) {
        when(request.url()).thenReturn(url);
        HttpHeader h = mock(HttpHeader.class);
        when(h.name()).thenReturn("Set-Cookie");
        when(h.value()).thenReturn(cookieValue);
        when(response.headers()).thenReturn(List.of(h));
        return checker.check(reqRes);
    }

    // ---- no cookies ----

    @Test
    void noCookies_returnsEmpty() {
        assertTrue(checker.check(reqRes).isEmpty());
    }

    @Test
    void nonCookieHeadersIgnored() {
        HttpHeader h = mock(HttpHeader.class);
        when(h.name()).thenReturn("Content-Type");
        when(h.value()).thenReturn("text/html");
        when(response.headers()).thenReturn(List.of(h));
        assertTrue(checker.check(reqRes).isEmpty());
    }

    // ---- Secure flag ----

    @Test
    void https_missingSecure_reportsMissingSecure() {
        List<Finding> f = check("https://example.com", "s=1; HttpOnly; SameSite=Lax; Max-Age=3600");
        assertContains(f, IssueDefinition.COOKIE_MISSING_SECURE);
    }

    @Test
    void http_missingSecure_noMissingSecureFinding() {
        List<Finding> f = check("http://example.com", "s=1; HttpOnly; SameSite=Lax; Max-Age=3600");
        assertNotContains(f, IssueDefinition.COOKIE_MISSING_SECURE);
    }

    @Test
    void https_withSecure_noMissingSecureFinding() {
        List<Finding> f = check("https://example.com", "s=1; HttpOnly; Secure; SameSite=Lax; Max-Age=3600");
        assertNotContains(f, IssueDefinition.COOKIE_MISSING_SECURE);
    }

    // ---- HttpOnly flag ----

    @Test
    void missingHttpOnly_reportsMissingHttpOnly() {
        List<Finding> f = check("http://example.com", "s=1; Secure; SameSite=Lax; Max-Age=3600");
        assertContains(f, IssueDefinition.COOKIE_MISSING_HTTPONLY);
    }

    @Test
    void withHttpOnly_noMissingHttpOnlyFinding() {
        List<Finding> f = check("http://example.com", "s=1; HttpOnly; SameSite=Lax; Max-Age=3600");
        assertNotContains(f, IssueDefinition.COOKIE_MISSING_HTTPONLY);
    }

    // ---- Expiry ----

    @Test
    void noExpiresNoMaxAge_reportsSessionCookie() {
        List<Finding> f = check("http://example.com", "s=1; HttpOnly; SameSite=Lax");
        assertContains(f, IssueDefinition.COOKIE_SESSION_COOKIE);
    }

    @Test
    void withMaxAge_noSessionCookieFinding() {
        List<Finding> f = check("http://example.com", "s=1; HttpOnly; SameSite=Lax; Max-Age=3600");
        assertNotContains(f, IssueDefinition.COOKIE_SESSION_COOKIE);
    }

    @Test
    void withExpires_noSessionCookieFinding() {
        List<Finding> f = check("http://example.com",
                "s=1; HttpOnly; SameSite=Lax; Expires=Thu, 01 Jan 2099 00:00:00 GMT");
        assertNotContains(f, IssueDefinition.COOKIE_SESSION_COOKIE);
    }

    // ---- Path ----

    @Test
    void pathSlash_reportsBroadPath() {
        List<Finding> f = check("http://example.com", "s=1; HttpOnly; SameSite=Lax; Path=/");
        assertContains(f, IssueDefinition.COOKIE_BROAD_PATH);
    }

    @Test
    void pathNonRoot_noBroadPathFinding() {
        List<Finding> f = check("http://example.com", "s=1; HttpOnly; SameSite=Lax; Path=/api");
        assertNotContains(f, IssueDefinition.COOKIE_BROAD_PATH);
    }

    @Test
    void noPath_noBroadPathFinding() {
        List<Finding> f = check("http://example.com", "s=1; HttpOnly; SameSite=Lax");
        assertNotContains(f, IssueDefinition.COOKIE_BROAD_PATH);
    }

    // ---- Domain ----

    @Test
    void withDomain_reportsDomainAttribute() {
        List<Finding> f = check("http://example.com", "s=1; HttpOnly; SameSite=Lax; Domain=example.com");
        assertContains(f, IssueDefinition.COOKIE_DOMAIN_ATTRIBUTE);
    }

    @Test
    void noDomain_noDomainAttributeFinding() {
        List<Finding> f = check("http://example.com", "s=1; HttpOnly; SameSite=Lax");
        assertNotContains(f, IssueDefinition.COOKIE_DOMAIN_ATTRIBUTE);
    }

    // ---- SameSite ----

    @Test
    void missingSameSite_reportsMissingSameSite() {
        List<Finding> f = check("http://example.com", "s=1; HttpOnly; Max-Age=3600");
        assertContains(f, IssueDefinition.COOKIE_SAMESITE_MISSING);
    }

    @Test
    void sameSiteNoneWithoutSecure_reportsSameSiteNoneWithoutSecure() {
        List<Finding> f = check("http://example.com", "s=1; HttpOnly; SameSite=None; Max-Age=3600");
        assertContains(f, IssueDefinition.COOKIE_SAMESITE_NONE_WITHOUT_SECURE);
        assertNotContains(f, IssueDefinition.COOKIE_SAMESITE_MISSING);
        assertNotContains(f, IssueDefinition.COOKIE_SAMESITE_NONE);
    }

    @Test
    void sameSiteNoneWithSecure_reportsSameSiteNone() {
        List<Finding> f = check("https://example.com", "s=1; HttpOnly; Secure; SameSite=None; Max-Age=3600");
        assertContains(f, IssueDefinition.COOKIE_SAMESITE_NONE);
        assertNotContains(f, IssueDefinition.COOKIE_SAMESITE_NONE_WITHOUT_SECURE);
        assertNotContains(f, IssueDefinition.COOKIE_SAMESITE_MISSING);
    }

    @Test
    void sameSiteLax_noSameSiteFindings() {
        List<Finding> f = check("http://example.com", "s=1; HttpOnly; SameSite=Lax; Max-Age=3600");
        assertNotContains(f, IssueDefinition.COOKIE_SAMESITE_MISSING);
        assertNotContains(f, IssueDefinition.COOKIE_SAMESITE_NONE);
        assertNotContains(f, IssueDefinition.COOKIE_SAMESITE_NONE_WITHOUT_SECURE);
    }

    @Test
    void sameSiteStrict_noSameSiteFindings() {
        List<Finding> f = check("http://example.com", "s=1; HttpOnly; SameSite=Strict; Max-Age=3600");
        assertNotContains(f, IssueDefinition.COOKIE_SAMESITE_MISSING);
        assertNotContains(f, IssueDefinition.COOKIE_SAMESITE_NONE);
    }

    // ---- multiple cookies ----

    @Test
    void multipleCookies_eachAnalyzedIndependently() {
        HttpHeader c1 = cookie("a=1; HttpOnly; SameSite=Lax; Max-Age=3600");
        HttpHeader c2 = cookie("b=2; HttpOnly; SameSite=Lax; Max-Age=3600");
        when(request.url()).thenReturn("https://example.com");
        when(response.headers()).thenReturn(List.of(c1, c2));

        long count = checker.check(reqRes).stream()
                .filter(f -> f.definition() == IssueDefinition.COOKIE_MISSING_SECURE)
                .count();
        assertEquals(2, count);
    }

    // ---- sanitization ----

    @Test
    void xssInCookieName_detailIsSanitized() {
        List<Finding> findings = check("https://example.com", "<script>=1; SameSite=Lax");
        assertFalse(findings.isEmpty());
        findings.forEach(f -> assertFalse(f.detail().contains("<script>"),
                "detail must not contain raw HTML: " + f.detail()));
    }

    // ---- helpers ----

    private HttpHeader cookie(String value) {
        HttpHeader h = mock(HttpHeader.class);
        when(h.name()).thenReturn("Set-Cookie");
        when(h.value()).thenReturn(value);
        return h;
    }

    private void assertContains(List<Finding> findings, IssueDefinition expected) {
        assertTrue(findings.stream().anyMatch(f -> f.definition() == expected),
                "Expected finding " + expected + " not present");
    }

    private void assertNotContains(List<Finding> findings, IssueDefinition unexpected) {
        assertFalse(findings.stream().anyMatch(f -> f.definition() == unexpected),
                "Unexpected finding " + unexpected + " present");
    }
}
