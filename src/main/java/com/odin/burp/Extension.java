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

        // Scanner integration (Professional only) — gracefully skipped in Community edition
        try {
            OdinScanCheck scanCheck = new OdinScanCheck(api, checkers);
            api.scanner().registerScanCheck(scanCheck);
            api.logging().logToOutput("Scanner integration active (Professional edition).");
        } catch (Exception e) {
            api.logging().logToOutput("Scanner not available (Community edition) — using Proxy handler instead.");
        }

        // Proxy handler works in both Community and Professional editions.
        // Findings appear as color-coded annotations in Proxy > HTTP history,
        // and are logged to Extensions > Output.
        api.proxy().registerResponseHandler(new OdinProxyHandler(api, checkers));

        api.extension().registerUnloadingHandler(() ->
            api.logging().logToOutput("Odin: extension unloaded.")
        );

        api.logging().logToOutput("Odin - Security Header Linter loaded successfully.");
    }
}
