package com.odin.burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.proxy.http.InterceptedResponse;
import burp.api.montoya.proxy.http.ProxyResponseHandler;
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction;
import burp.api.montoya.proxy.http.ProxyResponseToBeSentAction;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.odin.burp.checker.HeaderChecker;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

public class OdinProxyHandler implements ProxyResponseHandler {

  private final MontoyaApi api;
  private final List<HeaderChecker> checkers;

  public OdinProxyHandler(MontoyaApi api, List<HeaderChecker> checkers) {
    this.api = api;
    this.checkers = List.copyOf(checkers);
  }

  @Override
  public ProxyResponseReceivedAction handleResponseReceived(
      InterceptedResponse interceptedResponse) {
    HttpRequestResponse requestResponse =
        HttpRequestResponse.httpRequestResponse(
            interceptedResponse.initiatingRequest(), interceptedResponse);

    List<Finding> findings = new ArrayList<>();
    for (HeaderChecker checker : checkers) {
      try {
        findings.addAll(checker.check(requestResponse));
      } catch (Exception e) {
        api.logging()
            .logToError(
                "Odin: error in checker "
                    + checker.getClass().getSimpleName()
                    + ": "
                    + e.getMessage());
      }
    }

    if (findings.isEmpty()) {
      return ProxyResponseReceivedAction.continueWith(interceptedResponse);
    }

    logFindings(interceptedResponse.initiatingRequest().url(), findings);

    String notes =
        findings.stream()
            .map(f -> "[" + severityLabel(f) + "] " + f.definition().getName())
            .collect(Collectors.joining("\n"));

    Annotations annotations = Annotations.annotations(notes, pickColor(findings));
    return ProxyResponseReceivedAction.continueWith(interceptedResponse, annotations);
  }

  @Override
  public ProxyResponseToBeSentAction handleResponseToBeSent(
      InterceptedResponse interceptedResponse) {
    return ProxyResponseToBeSentAction.continueWith(interceptedResponse);
  }

  private void logFindings(String url, List<Finding> findings) {
    api.logging().logToOutput("[Odin] " + url);
    for (Finding f : findings) {
      api.logging().logToOutput("  [" + severityLabel(f) + "] " + f.definition().getName());
    }
  }

  private String severityLabel(Finding f) {
    return f.definition().getSeverity().name();
  }

  private HighlightColor pickColor(List<Finding> findings) {
    for (Finding f : findings) {
      if (f.definition().getSeverity() == AuditIssueSeverity.HIGH) return HighlightColor.RED;
    }
    for (Finding f : findings) {
      if (f.definition().getSeverity() == AuditIssueSeverity.MEDIUM) return HighlightColor.ORANGE;
    }
    for (Finding f : findings) {
      if (f.definition().getSeverity() == AuditIssueSeverity.LOW) return HighlightColor.YELLOW;
    }
    return HighlightColor.BLUE;
  }
}
