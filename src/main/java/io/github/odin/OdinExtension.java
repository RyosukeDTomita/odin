package io.github.odin;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import io.github.odin.checker.CookieChecker;
import io.github.odin.checker.CorsChecker;
import io.github.odin.checker.HeaderChecker;
import io.github.odin.checker.SecurityHeaderChecker;

import java.util.List;

public class OdinExtension implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("Odin - Security Header Linter");

        List<HeaderChecker> checkers = List.of(
            new CorsChecker(),
            new CookieChecker(),
            new SecurityHeaderChecker()
        );

        OdinScanCheck scanCheck = new OdinScanCheck(api, checkers);
        api.scanner().registerScanCheck(scanCheck);

        api.extension().registerUnloadingHandler(() ->
            api.logging().logToOutput("Odin: extension unloaded.")
        );

        api.logging().logToOutput("Odin - Security Header Linter loaded successfully.");
        api.logging().logToOutput("Passive scan check registered. Monitoring HTTP history for security header issues.");
    }
}
