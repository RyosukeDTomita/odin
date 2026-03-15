package com.odin.burp.checker;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.odin.burp.Finding;
import com.odin.burp.issue.IssueDefinition;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

class CorsCheckerTest {

    private CorsChecker checker;
    private HttpRequestResponse reqRes;
    private HttpResponse response;
    private HttpRequest request;

    @BeforeEach
    void setUp() {
        checker = new CorsChecker();
        reqRes   = mock(HttpRequestResponse.class);
        response = mock(HttpResponse.class);
        request  = mock(HttpRequest.class);
        when(reqRes.response()).thenReturn(response);
        when(reqRes.request()).thenReturn(request);
        when(request.url()).thenReturn("https://example.com/");
        when(request.headerValue(anyString())).thenReturn(null);
        when(response.headerValue(anyString())).thenReturn(null);
    }

    // ---- Access-Control-Allow-Origin ----

    @Test
    void noAcao_returnsEmpty() {
        assertTrue(checker.check(reqRes).isEmpty());
    }

    @Test
    void wildcardAcao_reportsWildcardOrigin() {
        when(response.headerValue("Access-Control-Allow-Origin")).thenReturn("*");
        assertContains(checker.check(reqRes), IssueDefinition.CORS_WILDCARD_ORIGIN);
    }

    @Test
    void wildcardAcaoWithWhitespace_reportsWildcardOrigin() {
        when(response.headerValue("Access-Control-Allow-Origin")).thenReturn("  *  ");
        assertContains(checker.check(reqRes), IssueDefinition.CORS_WILDCARD_ORIGIN);
    }

    @Test
    void wildcardAcaoWithCredentials_reportsBothIssues() {
        when(response.headerValue("Access-Control-Allow-Origin")).thenReturn("*");
        when(response.headerValue("Access-Control-Allow-Credentials")).thenReturn("true");
        List<Finding> findings = checker.check(reqRes);
        assertContains(findings, IssueDefinition.CORS_WILDCARD_ORIGIN);
        assertContains(findings, IssueDefinition.CORS_CREDENTIALS_WITH_WILDCARD);
    }

    @Test
    void wildcardAcaoWithCredentialsCaseInsensitive_reportsCredentials() {
        when(response.headerValue("Access-Control-Allow-Origin")).thenReturn("*");
        when(response.headerValue("Access-Control-Allow-Credentials")).thenReturn("True");
        assertContains(checker.check(reqRes), IssueDefinition.CORS_CREDENTIALS_WITH_WILDCARD);
    }

    @Test
    void wildcardAcaoWithCredentialsFalse_noCredentialsFinding() {
        when(response.headerValue("Access-Control-Allow-Origin")).thenReturn("*");
        when(response.headerValue("Access-Control-Allow-Credentials")).thenReturn("false");
        assertNotContains(checker.check(reqRes), IssueDefinition.CORS_CREDENTIALS_WITH_WILDCARD);
    }

    @Test
    void reflectedOrigin_reportsReflectedOrigin() {
        when(request.headerValue("Origin")).thenReturn("https://attacker.com");
        when(response.headerValue("Access-Control-Allow-Origin")).thenReturn("https://attacker.com");
        assertContains(checker.check(reqRes), IssueDefinition.CORS_REFLECTED_ORIGIN);
    }

    @Test
    void reflectedOriginWithCredentials_reportsBothReflectedIssues() {
        when(request.headerValue("Origin")).thenReturn("https://attacker.com");
        when(response.headerValue("Access-Control-Allow-Origin")).thenReturn("https://attacker.com");
        when(response.headerValue("Access-Control-Allow-Credentials")).thenReturn("true");
        List<Finding> findings = checker.check(reqRes);
        assertContains(findings, IssueDefinition.CORS_REFLECTED_ORIGIN);
        assertContains(findings, IssueDefinition.CORS_CREDENTIALS_WITH_REFLECTED);
    }

    @Test
    void acaoDoesNotMatchRequestOrigin_noReflectedFinding() {
        when(request.headerValue("Origin")).thenReturn("https://legitimate.com");
        when(response.headerValue("Access-Control-Allow-Origin")).thenReturn("https://other.com");
        assertNotContains(checker.check(reqRes), IssueDefinition.CORS_REFLECTED_ORIGIN);
    }

    @Test
    void noRequestOriginHeader_noReflectedFinding() {
        when(request.headerValue("Origin")).thenReturn(null);
        when(response.headerValue("Access-Control-Allow-Origin")).thenReturn("https://example.com");
        assertNotContains(checker.check(reqRes), IssueDefinition.CORS_REFLECTED_ORIGIN);
    }

    // ---- Access-Control-Allow-Methods ----

    @Test
    void acamContainsPut_reportsDangerousMethods() {
        when(response.headerValue("Access-Control-Allow-Origin")).thenReturn("https://example.com");
        when(response.headerValue("Access-Control-Allow-Methods")).thenReturn("GET, POST, PUT");
        assertContains(checker.check(reqRes), IssueDefinition.CORS_DANGEROUS_METHODS);
    }

    @Test
    void acamContainsDelete_reportsDangerousMethods() {
        when(response.headerValue("Access-Control-Allow-Origin")).thenReturn("https://example.com");
        when(response.headerValue("Access-Control-Allow-Methods")).thenReturn("GET, DELETE");
        assertContains(checker.check(reqRes), IssueDefinition.CORS_DANGEROUS_METHODS);
    }

    @Test
    void acamContainsPatchLowercase_reportsDangerousMethods() {
        when(response.headerValue("Access-Control-Allow-Origin")).thenReturn("https://example.com");
        when(response.headerValue("Access-Control-Allow-Methods")).thenReturn("get, patch");
        assertContains(checker.check(reqRes), IssueDefinition.CORS_DANGEROUS_METHODS);
    }

    @Test
    void acamReadMethodsOnly_noDangerousMethodsFinding() {
        when(response.headerValue("Access-Control-Allow-Origin")).thenReturn("https://example.com");
        when(response.headerValue("Access-Control-Allow-Methods")).thenReturn("GET, POST, HEAD");
        assertNotContains(checker.check(reqRes), IssueDefinition.CORS_DANGEROUS_METHODS);
    }

    // ---- Access-Control-Allow-Headers ----

    @Test
    void wildcardAcah_reportsWildcardHeaders() {
        when(response.headerValue("Access-Control-Allow-Origin")).thenReturn("https://example.com");
        when(response.headerValue("Access-Control-Allow-Headers")).thenReturn("*");
        assertContains(checker.check(reqRes), IssueDefinition.CORS_WILDCARD_HEADERS);
    }

    @Test
    void specificAcah_noWildcardHeadersFinding() {
        when(response.headerValue("Access-Control-Allow-Origin")).thenReturn("https://example.com");
        when(response.headerValue("Access-Control-Allow-Headers")).thenReturn("Content-Type, Authorization");
        assertNotContains(checker.check(reqRes), IssueDefinition.CORS_WILDCARD_HEADERS);
    }

    // ---- XSS sanitization ----

    @Test
    void xssInReflectedOrigin_detailIsSanitized() {
        String malicious = "<script>alert(1)</script>";
        when(request.headerValue("Origin")).thenReturn(malicious);
        when(response.headerValue("Access-Control-Allow-Origin")).thenReturn(malicious);
        List<Finding> findings = checker.check(reqRes);
        assertContains(findings, IssueDefinition.CORS_REFLECTED_ORIGIN);
        findings.forEach(f -> assertFalse(f.detail().contains("<script>"),
                "detail should not contain raw HTML: " + f.detail()));
    }

    // ---- helpers ----

    private void assertContains(List<Finding> findings, IssueDefinition expected) {
        assertTrue(findings.stream().anyMatch(f -> f.definition() == expected),
                "Expected finding " + expected + " not present in " + findings);
    }

    private void assertNotContains(List<Finding> findings, IssueDefinition unexpected) {
        assertFalse(findings.stream().anyMatch(f -> f.definition() == unexpected),
                "Unexpected finding " + unexpected + " present in " + findings);
    }
}
