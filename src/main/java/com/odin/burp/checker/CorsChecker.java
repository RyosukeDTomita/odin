package com.odin.burp.checker;

import burp.api.montoya.http.message.HttpRequestResponse;
import com.odin.burp.Finding;
import com.odin.burp.issue.IssueDefinition;
import java.util.ArrayList;
import java.util.List;

public class CorsChecker implements HeaderChecker {

  @Override
  public List<Finding> check(HttpRequestResponse requestResponse) {
    List<Finding> issues = new ArrayList<>();

    var response = requestResponse.response();
    var request = requestResponse.request();

    String acao = response.headerValue("Access-Control-Allow-Origin");
    if (acao == null) {
      return issues;
    }
    acao = acao.trim();

    String requestOrigin = request.headerValue("Origin");

    if ("*".equals(acao)) {
      issues.add(
          new Finding(
              IssueDefinition.CORS_WILDCARD_ORIGIN,
              "Access-Control-Allow-Origin is set to wildcard (*).",
              requestResponse));

      String acac = response.headerValue("Access-Control-Allow-Credentials");
      if ("true".equalsIgnoreCase(acac != null ? acac.trim() : "")) {
        issues.add(
            new Finding(
                IssueDefinition.CORS_CREDENTIALS_WITH_WILDCARD,
                "Access-Control-Allow-Credentials: true is set alongside Access-Control-Allow-Origin: *.",
                requestResponse));
      }
    } else if (requestOrigin != null && acao.equals(requestOrigin.trim())) {
      issues.add(
          new Finding(
              IssueDefinition.CORS_REFLECTED_ORIGIN,
              "Access-Control-Allow-Origin reflects the request Origin: " + sanitize(acao),
              requestResponse));

      String acac = response.headerValue("Access-Control-Allow-Credentials");
      if ("true".equalsIgnoreCase(acac != null ? acac.trim() : "")) {
        issues.add(
            new Finding(
                IssueDefinition.CORS_CREDENTIALS_WITH_REFLECTED,
                "Access-Control-Allow-Credentials: true is set alongside a reflected origin: "
                    + sanitize(acao),
                requestResponse));
      }
    }

    String acam = response.headerValue("Access-Control-Allow-Methods");
    if (acam != null) {
      String upper = acam.toUpperCase();
      if (upper.contains("PUT") || upper.contains("DELETE") || upper.contains("PATCH")) {
        issues.add(
            new Finding(
                IssueDefinition.CORS_DANGEROUS_METHODS,
                "Access-Control-Allow-Methods includes write methods: " + sanitize(acam),
                requestResponse));
      }
    }

    String acah = response.headerValue("Access-Control-Allow-Headers");
    if (acah != null && "*".equals(acah.trim())) {
      issues.add(
          new Finding(
              IssueDefinition.CORS_WILDCARD_HEADERS,
              "Access-Control-Allow-Headers is set to wildcard (*).",
              requestResponse));
    }

    return issues;
  }

  private String sanitize(String value) {
    if (value == null) return "";
    return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
  }
}
