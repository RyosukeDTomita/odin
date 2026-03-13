package io.github.odin.issue;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;

public class IssueBuilder {

    private IssueBuilder() {}

    public static AuditIssue build(IssueDefinition def, String detail, HttpRequestResponse requestResponse) {
        return AuditIssue.auditIssue(
            def.getName(),
            detail,
            def.getRemediation(),
            requestResponse.request().url(),
            def.getSeverity(),
            def.getConfidence(),
            def.getBackground(),
            null,
            def.getTypicalSeverity(),
            requestResponse
        );
    }
}
