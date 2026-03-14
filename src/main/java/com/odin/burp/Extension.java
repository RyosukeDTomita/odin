package com.odin.burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import com.odin.burp.checker.CookieChecker;
import com.odin.burp.checker.CorsChecker;
import com.odin.burp.checker.HeaderChecker;
import com.odin.burp.checker.SecurityHeaderChecker;

import java.util.List;

public class Extension implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("Odin - Security Header Linter");

        List<HeaderChecker> checkers = List.of(
            new CorsChecker(),
            new CookieChecker(),
            new SecurityHeaderChecker()
        );

        api.proxy().registerResponseHandler(new OdinProxyHandler(api, checkers));

        api.extension().registerUnloadingHandler(() ->
            api.logging().logToOutput("Odin: extension unloaded.")
        );

        api.logging().logToOutput("Odin - Security Header Linter loaded successfully.");
    }
}
