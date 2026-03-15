package com.odin.burp.checker;

import burp.api.montoya.http.message.HttpRequestResponse;
import com.odin.burp.Finding;
import java.util.List;

public interface HeaderChecker {
  List<Finding> check(HttpRequestResponse requestResponse);
}
