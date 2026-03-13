package io.github.odin;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.ScanCheck;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import io.github.odin.checker.HeaderChecker;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class OdinScanCheck implements ScanCheck {

    private final MontoyaApi api;
    private final List<HeaderChecker> checkers;

    public OdinScanCheck(MontoyaApi api, List<HeaderChecker> checkers) {
        this.api      = api;
        this.checkers = List.copyOf(checkers);
    }

    @Override
    public AuditResult passiveAudit(HttpRequestResponse baseRequestResponse) {
        if (!baseRequestResponse.hasResponse()) {
            return AuditResult.auditResult(Collections.emptyList());
        }

        List<AuditIssue> issues = new ArrayList<>();
        for (HeaderChecker checker : checkers) {
            try {
                issues.addAll(checker.check(baseRequestResponse));
            } catch (Exception e) {
                api.logging().logToError("Odin: error in checker " + checker.getClass().getSimpleName() + ": " + e.getMessage());
            }
        }

        return AuditResult.auditResult(issues);
    }

    @Override
    public AuditResult activeAudit(HttpRequestResponse baseRequestResponse, AuditInsertionPoint auditInsertionPoint) {
        return AuditResult.auditResult(Collections.emptyList());
    }

    @Override
    public ConsolidationAction consolidateIssues(AuditIssue newIssue, AuditIssue existingIssue) {
        if (newIssue.name().equals(existingIssue.name())) {
            return ConsolidationAction.KEEP_EXISTING;
        }
        return ConsolidationAction.KEEP_BOTH;
    }
}
