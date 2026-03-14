package com.odin.burp.issue;

import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.odin.burp.Finding;

public class IssueBuilder {

    private IssueBuilder() {}

    public static AuditIssue build(Finding finding) {
        IssueDefinition def = finding.definition();
        return AuditIssue.auditIssue(
            def.getName(),
            finding.detail(),
            def.getRemediation(),
            finding.requestResponse().request().url(),
            def.getSeverity(),
            def.getConfidence(),
            def.getBackground(),
            null,
            def.getTypicalSeverity(),
            finding.requestResponse()
        );
    }
}
