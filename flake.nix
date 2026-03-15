{
  description = "sssd-oidc — NSS/PAM modules for OIDC via SCIM 2.0";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs { inherit system overlays; };

        # Latest stable Rust (MSRV in Cargo.toml is 1.85)
        rustToolchain = pkgs.rust-bin.stable."1.94.0".default.override {
          extensions = [ "rust-src" "rust-analyzer" "clippy" ];
        };
      in
      {
        devShells.default = pkgs.mkShell {
          name = "sssd-oidc";

          nativeBuildInputs = [
            rustToolchain
            pkgs.cargo-nextest
            pkgs.pkg-config
          ];

          buildInputs = [
            # SQLite (rusqlite bundled feature handles its own, but headers
            # are handy for debugging)
            pkgs.sqlite

            # PAM headers for pam_oidc crate
            pkgs.pam
          ] ++ pkgs.lib.optionals pkgs.stdenv.isLinux [
            # Container runtime for integration testing (Linux only)
            pkgs.podman
            pkgs.slirp4netns   # rootless networking for podman
            pkgs.fuse-overlayfs # rootless storage driver

            # Useful for NSS/PAM debugging on Linux
            pkgs.glibc
          ];

          shellHook = ''
            echo "sssd-oidc devshell — Rust $(rustc --version | cut -d' ' -f2)"
            ${pkgs.lib.optionalString pkgs.stdenv.isLinux ''
              echo "  podman $(podman --version | cut -d' ' -f3)"
            ''}
          '';
        };
      });
}
