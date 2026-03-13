{
  description = "Odin - Burp Suite passive security header linter";

  inputs = {
    nixpkgs.url     = "github:NixOS/nixpkgs/nixos-24.11";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs   = import nixpkgs { inherit system; };
        jdk    = pkgs.jdk21;
        gradle = pkgs.gradle.override { java = jdk; };
      in {
        devShells.default = pkgs.mkShell {
          buildInputs = [ jdk gradle ];

          shellHook = ''
            export JAVA_HOME="${jdk}"
            echo "Java: $(java -version 2>&1 | head -1)"
            echo "Gradle: $(gradle --version 2>/dev/null | grep '^Gradle' | head -1)"
            echo ""
            echo "Build:  ./gradlew shadowJar"
            echo "Output: build/libs/odin-1.0.0.jar"
          '';
        };
      });
}
