package com.odin.burp;

import burp.api.montoya.http.message.HttpRequestResponse;
import com.odin.burp.issue.IssueDefinition;

public record Finding(
    IssueDefinition definition, String detail, HttpRequestResponse requestResponse) {}
