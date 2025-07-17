{
  description = "dev environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    crane.url = "github:ipetkov/crane";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay.url = "github:oxalica/rust-overlay";
  };

  outputs = { self, nixpkgs, crane, flake-utils, rust-overlay, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        # 1. Overlays and Packages
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs { inherit system overlays; };

        # 2. Rust Toolchain and Crane Setup
        rustToolchain = pkgs.rust-bin.nightly.latest.default.override {
          extensions = [ "rust-src" ]; # For rust-analyzer
        };
        craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;

        # 3. Build Configuration
        src = craneLib.cleanCargoSource ./.;

        # Common arguments for all crane operations on the workspace
        commonArgs = {
          inherit src;
          nativeBuildInputs = with pkgs; [
            pkg-config # For the `unshare-unsafe` build script
            libselinux # Dependency for build script
            libcap_ng # For capability dropping
          ];
        };

        # Build dependencies for the entire workspace
        cargoArtifacts = craneLib.buildDepsOnly commonArgs;

        # Build the main binary package from the workspace
        unshare-cli-pkg = craneLib.buildPackage (commonArgs // {
          inherit cargoArtifacts;
          pname = "unshare-cli"; # Specify which package from the workspace to build
        });

        # 4. Patched Pasta (for dev shell)
        patched-pasta = pkgs.passt.overrideAttrs (old: {
          patches = (old.patches or []) ++ [
            (pkgs.writeText "passt-fix-user-namespace-detection.patch"
              (builtins.readFile ./patches/passt-fix-user-namespace-detection.patch))
          ];
        });

      in
      {
        # 5. Flake Outputs

        # Default package for `nix build`
        packages.default = unshare-cli-pkg;

        # Checks for `nix flake check`
        checks = {
          # Run `cargo clippy` on the entire workspace
          clippy = craneLib.cargoClippy (commonArgs // {
            inherit cargoArtifacts;
            cargoClippyExtraArgs = "--all-targets -- --deny warnings";
          });

          # Run `cargo test` on the entire workspace.
          # `craneLib.cargoTest` on a workspace source will test all packages by default.
          test = craneLib.cargoTest (commonArgs // {
            inherit cargoArtifacts;
            buildInputs = with pkgs; [ coreutils ]; # for `hostname` and `echo`
            # Pass arguments to the test runner, not to cargo.
            cargoTestExtraArgs = "-- --test-threads=1";
            __impure = true;
          });
        };

        # Development shell for `nix develop`
        devShells.default = with pkgs; mkShell {
          # Inherit build inputs from the checks to keep the environment consistent.
          inputsFrom = [ self.checks."${system}".test ];
          # Add additional tools for development.
          buildInputs = [
            rust-analyzer
            nixd
            # C toolchain & build system
            clang
            clang-tools
            meson
            ninja
            cmake

            nixd
            perf-tools
            pkgs.linuxPackages_latest.perf

            # runtime dependencies

            patched-pasta
            # Other development tools
            tokei
            findutils
            libxslt.bin
            bash-completion
          ];
          PKG_CONFIG_PATH = "${pkgs.lib.makeSearchPath "lib/pkgconfig" [ pkgs.libselinux ]}";
        };
      });
}
