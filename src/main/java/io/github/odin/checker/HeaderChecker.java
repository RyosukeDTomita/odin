package io.github.odin.checker;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;

import java.util.List;

public interface HeaderChecker {
    List<AuditIssue> check(HttpRequestResponse requestResponse);
}
