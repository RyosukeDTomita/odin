package io.github.odin.checker;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import io.github.odin.issue.IssueBuilder;
import io.github.odin.issue.IssueDefinition;

import java.util.ArrayList;
import java.util.List;

public class CorsChecker implements HeaderChecker {

    @Override
    public List<AuditIssue> check(HttpRequestResponse requestResponse) {
        List<AuditIssue> issues = new ArrayList<>();

        var response = requestResponse.response();
        var request  = requestResponse.request();

        String acao = response.headerValue("Access-Control-Allow-Origin");
        if (acao == null) {
            return issues;
        }
        acao = acao.trim();

        String requestOrigin = request.headerValue("Origin");

        if ("*".equals(acao)) {
            issues.add(IssueBuilder.build(
                IssueDefinition.CORS_WILDCARD_ORIGIN,
                "Access-Control-Allow-Origin is set to wildcard (*).",
                requestResponse
            ));

            String acac = response.headerValue("Access-Control-Allow-Credentials");
            if ("true".equalsIgnoreCase(acac != null ? acac.trim() : "")) {
                issues.add(IssueBuilder.build(
                    IssueDefinition.CORS_CREDENTIALS_WITH_WILDCARD,
                    "Access-Control-Allow-Credentials: true is set alongside Access-Control-Allow-Origin: *.",
                    requestResponse
                ));
            }
        } else if (requestOrigin != null && acao.equals(requestOrigin.trim())) {
            issues.add(IssueBuilder.build(
                IssueDefinition.CORS_REFLECTED_ORIGIN,
                "Access-Control-Allow-Origin reflects the request Origin: " + sanitize(acao),
                requestResponse
            ));

            String acac = response.headerValue("Access-Control-Allow-Credentials");
            if ("true".equalsIgnoreCase(acac != null ? acac.trim() : "")) {
                issues.add(IssueBuilder.build(
                    IssueDefinition.CORS_CREDENTIALS_WITH_REFLECTED,
                    "Access-Control-Allow-Credentials: true is set alongside a reflected origin: " + sanitize(acao),
                    requestResponse
                ));
            }
        }

        String acam = response.headerValue("Access-Control-Allow-Methods");
        if (acam != null) {
            String upper = acam.toUpperCase();
            if (upper.contains("PUT") || upper.contains("DELETE") || upper.contains("PATCH")) {
                issues.add(IssueBuilder.build(
                    IssueDefinition.CORS_DANGEROUS_METHODS,
                    "Access-Control-Allow-Methods includes write methods: " + sanitize(acam),
                    requestResponse
                ));
            }
        }

        String acah = response.headerValue("Access-Control-Allow-Headers");
        if (acah != null && "*".equals(acah.trim())) {
            issues.add(IssueBuilder.build(
                IssueDefinition.CORS_WILDCARD_HEADERS,
                "Access-Control-Allow-Headers is set to wildcard (*).",
                requestResponse
            ));
        }

        return issues;
    }

    private String sanitize(String value) {
        if (value == null) return "";
        return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }
}
