package io.github.odin.checker;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.headers.HttpHeader;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import io.github.odin.issue.IssueBuilder;
import io.github.odin.issue.IssueDefinition;

import java.util.ArrayList;
import java.util.List;

public class CookieChecker implements HeaderChecker {

    @Override
    public List<AuditIssue> check(HttpRequestResponse requestResponse) {
        List<AuditIssue> issues = new ArrayList<>();

        var response = requestResponse.response();
        boolean isHttps = requestResponse.request().url().toLowerCase().startsWith("https://");

        for (HttpHeader header : response.headers()) {
            if (!"Set-Cookie".equalsIgnoreCase(header.name())) {
                continue;
            }

            String raw = header.value();
            String cookieName = parseCookieName(raw);
            String[] parts = raw.split(";");

            boolean hasSecure   = false;
            boolean hasHttpOnly = false;
            boolean hasExpires  = false;
            boolean hasMaxAge   = false;
            String  path        = null;
            String  domain      = null;
            String  sameSite    = null;

            for (String part : parts) {
                String p = part.trim();
                String pLower = p.toLowerCase();

                if (pLower.equals("secure")) {
                    hasSecure = true;
                } else if (pLower.equals("httponly")) {
                    hasHttpOnly = true;
                } else if (pLower.startsWith("expires=")) {
                    hasExpires = true;
                } else if (pLower.startsWith("max-age=")) {
                    hasMaxAge = true;
                } else if (pLower.startsWith("path=")) {
                    path = p.substring("path=".length()).trim();
                } else if (pLower.startsWith("domain=")) {
                    domain = p.substring("domain=".length()).trim();
                } else if (pLower.startsWith("samesite=")) {
                    sameSite = p.substring("samesite=".length()).trim();
                }
            }

            String nameLabel = sanitize(cookieName);

            if (isHttps && !hasSecure) {
                issues.add(IssueBuilder.build(
                    IssueDefinition.COOKIE_MISSING_SECURE,
                    "Cookie <b>" + nameLabel + "</b> is missing the Secure flag on an HTTPS response.",
                    requestResponse
                ));
            }

            if (!hasHttpOnly) {
                issues.add(IssueBuilder.build(
                    IssueDefinition.COOKIE_MISSING_HTTPONLY,
                    "Cookie <b>" + nameLabel + "</b> is missing the HttpOnly flag.",
                    requestResponse
                ));
            }

            if (!hasExpires && !hasMaxAge) {
                issues.add(IssueBuilder.build(
                    IssueDefinition.COOKIE_SESSION_COOKIE,
                    "Cookie <b>" + nameLabel + "</b> has no Expires or Max-Age attribute (session cookie).",
                    requestResponse
                ));
            }

            if ("/".equals(path)) {
                issues.add(IssueBuilder.build(
                    IssueDefinition.COOKIE_BROAD_PATH,
                    "Cookie <b>" + nameLabel + "</b> uses Path=/, making it available to all paths.",
                    requestResponse
                ));
            }

            if (domain != null && !domain.isEmpty()) {
                issues.add(IssueBuilder.build(
                    IssueDefinition.COOKIE_DOMAIN_ATTRIBUTE,
                    "Cookie <b>" + nameLabel + "</b> sets Domain=" + sanitize(domain) + ", which may expose it to all subdomains.",
                    requestResponse
                ));
            }

            if (sameSite == null || sameSite.isEmpty()) {
                issues.add(IssueBuilder.build(
                    IssueDefinition.COOKIE_SAMESITE_MISSING,
                    "Cookie <b>" + nameLabel + "</b> has no SameSite attribute.",
                    requestResponse
                ));
            } else if ("None".equalsIgnoreCase(sameSite) && !hasSecure) {
                issues.add(IssueBuilder.build(
                    IssueDefinition.COOKIE_SAMESITE_NONE_WITHOUT_SECURE,
                    "Cookie <b>" + nameLabel + "</b> uses SameSite=None without the Secure flag.",
                    requestResponse
                ));
            } else if ("None".equalsIgnoreCase(sameSite)) {
                issues.add(IssueBuilder.build(
                    IssueDefinition.COOKIE_SAMESITE_NONE,
                    "Cookie <b>" + nameLabel + "</b> uses SameSite=None, enabling cross-site transmission.",
                    requestResponse
                ));
            }
        }

        return issues;
    }

    private String parseCookieName(String rawCookieHeader) {
        if (rawCookieHeader == null || rawCookieHeader.isEmpty()) {
            return "";
        }
        String firstPart = rawCookieHeader.split(";")[0].trim();
        int eq = firstPart.indexOf('=');
        return eq > 0 ? firstPart.substring(0, eq).trim() : firstPart;
    }

    private String sanitize(String value) {
        if (value == null) return "";
        return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }
}
