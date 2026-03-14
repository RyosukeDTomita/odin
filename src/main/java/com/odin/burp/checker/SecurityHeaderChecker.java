package com.odin.burp.checker;

import burp.api.montoya.http.message.HttpRequestResponse;
import com.odin.burp.Finding;
import com.odin.burp.issue.IssueDefinition;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SecurityHeaderChecker implements HeaderChecker {

    private static final Pattern MAX_AGE_PATTERN = Pattern.compile("(?i)max-age\\s*=\\s*(\\d+)");
    private static final long MIN_HSTS_MAX_AGE = 31536000L; // 1 year

    @Override
    public List<Finding> check(HttpRequestResponse requestResponse) {
        List<Finding> issues = new ArrayList<>();

        var response = requestResponse.response();
        boolean isHttps = requestResponse.request().url().toLowerCase().startsWith("https://");

        // X-Content-Type-Options
        String xcto = response.headerValue("X-Content-Type-Options");
        if (xcto == null) {
            issues.add(new Finding(
                IssueDefinition.XCTO_MISSING,
                "The X-Content-Type-Options header is absent.",
                requestResponse
            ));
        } else if (!"nosniff".equalsIgnoreCase(xcto.trim())) {
            issues.add(new Finding(
                IssueDefinition.XCTO_INVALID,
                "X-Content-Type-Options is set to an invalid value: <b>" + sanitize(xcto) + "</b>. Only 'nosniff' is valid.",
                requestResponse
            ));
        }

        // Strict-Transport-Security (HTTPS only)
        if (isHttps) {
            String hsts = response.headerValue("Strict-Transport-Security");
            if (hsts == null) {
                issues.add(new Finding(
                    IssueDefinition.HSTS_MISSING,
                    "The Strict-Transport-Security header is absent on an HTTPS response.",
                    requestResponse
                ));
            } else {
                long maxAge = parseMaxAge(hsts);
                if (maxAge < MIN_HSTS_MAX_AGE) {
                    issues.add(new Finding(
                        IssueDefinition.HSTS_WEAK_MAX_AGE,
                        "Strict-Transport-Security max-age is " + maxAge + " seconds (minimum recommended: " + MIN_HSTS_MAX_AGE + ").",
                        requestResponse
                    ));
                }
                if (!hsts.toLowerCase().contains("includesubdomains")) {
                    issues.add(new Finding(
                        IssueDefinition.HSTS_NO_INCLUDE_SUBDOMAINS,
                        "Strict-Transport-Security does not include the includeSubDomains directive.",
                        requestResponse
                    ));
                }
            }
        }

        // X-Frame-Options + CSP frame-ancestors
        String xfo = response.headerValue("X-Frame-Options");
        String csp = response.headerValue("Content-Security-Policy");
        boolean hasFrameAncestors = csp != null && csp.toLowerCase().contains("frame-ancestors");
        if (xfo == null && !hasFrameAncestors) {
            issues.add(new Finding(
                IssueDefinition.XFO_MISSING,
                "Neither X-Frame-Options nor a Content-Security-Policy frame-ancestors directive is present.",
                requestResponse
            ));
        }

        // Content-Security-Policy
        if (csp == null) {
            issues.add(new Finding(
                IssueDefinition.CSP_MISSING,
                "The Content-Security-Policy header is absent.",
                requestResponse
            ));
        }

        // Referrer-Policy
        String rp = response.headerValue("Referrer-Policy");
        if (rp == null) {
            issues.add(new Finding(
                IssueDefinition.REFERRER_POLICY_MISSING,
                "The Referrer-Policy header is absent.",
                requestResponse
            ));
        } else {
            String rpLower = rp.trim().toLowerCase();
            if (rpLower.equals("unsafe-url") || rpLower.equals("no-referrer-when-downgrade")) {
                issues.add(new Finding(
                    IssueDefinition.REFERRER_POLICY_UNSAFE,
                    "Referrer-Policy is set to an unsafe value: <b>" + sanitize(rp.trim()) + "</b>.",
                    requestResponse
                ));
            }
        }

        // Permissions-Policy
        String pp = response.headerValue("Permissions-Policy");
        if (pp == null) {
            issues.add(new Finding(
                IssueDefinition.PERMISSIONS_POLICY_MISSING,
                "The Permissions-Policy header is absent.",
                requestResponse
            ));
        }

        return issues;
    }

    private long parseMaxAge(String hstsValue) {
        Matcher m = MAX_AGE_PATTERN.matcher(hstsValue);
        if (m.find()) {
            try {
                return Long.parseLong(m.group(1));
            } catch (NumberFormatException e) {
                return 0L;
            }
        }
        return 0L;
    }

    private String sanitize(String value) {
        if (value == null) return "";
        return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }
}
