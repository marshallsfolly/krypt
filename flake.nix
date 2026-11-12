{
  description = "krypt.chat — fast, secure, end-to-end encrypted messenger";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    crane.url = "github:ipetkov/crane";
  };

  outputs = { self, nixpkgs, flake-utils, fenix, crane }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};

        # Exact toolchain is pinned in rust-toolchain.toml; the hash pins the bits.
        toolchain = fenix.packages.${system}.fromToolchainFile {
          file = ./rust-toolchain.toml;
          sha256 = "sha256-+xUr6Al1wZSqX8aEsq7DpuFOK4Ve/i+qTl+K5uWQ9GM=";
        };

        inherit (pkgs) lib;
        # Fuzzing only (`nix develop .#fuzz`, `just fuzz`): libFuzzer's
        # sanitizer instrumentation needs nightly. A dated nightly, pinned by
        # hash like the stable toolchain.
        nightly =
          (fenix.packages.${system}.toolchainOf {
            channel = "nightly";
            date = "2026-10-23";
            sha256 = "sha256-es0EkfaBWC8CpCIdDcaaSwExwEFVknrz/iS+N5kqs7c=";
          }).minimalToolchain;

        craneLib = (crane.mkLib pkgs).overrideToolchain toolchain;
        rustArgs = {
          # Rust sources and manifests, and the fixtures tests read.
          src = lib.cleanSourceWith {
            src = ./.;
            name = "source";
            filter =
              path: type:
              craneLib.filterCargoSources path type || builtins.match ".*/tests/fixtures/.*" path != null;
          };
          strictDeps = true;
          pname = "krypt";
          version = "0.1.0";
        };
        # Dependencies build once and are shared by every Rust check.
        cargoArtifacts = craneLib.buildDepsOnly rustArgs;

        # The web client, built sealed: the core in WebAssembly
        # (`just web-core`), then the Vite build (`just web-build`).
        wasmArgs = rustArgs // {
          pname = "krypt-wasm";
          cargoExtraArgs = "-p krypt-wasm --target wasm32-unknown-unknown";
          CARGO_PROFILE = "wasm";
          doCheck = false;
        };
        webCore = craneLib.mkCargoDerivation (wasmArgs // {
          cargoArtifacts = craneLib.buildDepsOnly wasmArgs;
          nativeBuildInputs = [ pkgs.wasm-bindgen-cli pkgs.binaryen ];
          buildPhaseCargoCommand = "cargoWithProfile build $cargoExtraArgs";
          installPhaseCommand = ''
            wasm-bindgen --target web --out-dir $out target/wasm32-unknown-unknown/wasm/krypt_wasm.wasm
            wasm-opt -Oz --enable-bulk-memory --enable-nontrapping-float-to-int --enable-sign-ext --enable-mutable-globals --strip-debug -o $out/krypt_wasm_bg.wasm $out/krypt_wasm_bg.wasm
          '';
        });
        webDist = pkgs.stdenv.mkDerivation (finalAttrs: {
          pname = "krypt-web";
          version = "0.1.0";
          src = lib.fileset.toSource {
            root = ./.;
            fileset = lib.fileset.unions [ ./apps/web ./design/tokens ];
          };
          pnpmRoot = "apps/web";
          pnpmDeps = pkgs.fetchPnpmDeps {
            inherit (finalAttrs) pname version src;
            sourceRoot = "${finalAttrs.src.name}/apps/web";
            fetcherVersion = 5;
            hash = "sha256-9b+9tWRjBlw6tcbMXQRdbb1+eaRmFkUTz3p1NnsCrXM=";
          };
          nativeBuildInputs = [ pkgs.nodejs_22 pkgs.pnpm pkgs.pnpmConfigHook ];
          buildPhase = ''
            runHook preBuild
            cp -r ${webCore} apps/web/src/core
            chmod -R u+w apps/web/src/core
            (cd apps/web && pnpm build)
            runHook postBuild
          '';
          installPhase = "cp -r apps/web/dist $out";
        });

      in
      {
        packages = {
          inherit webDist;
        };
        devShells = {
          default = pkgs.mkShell {
            packages = [
              toolchain

              # Rust workflow
              pkgs.cargo-nextest
              pkgs.cargo-fuzz
              pkgs.cargo-deny
              pkgs.cargo-vet
              pkgs.wasm-bindgen-cli
              pkgs.binaryen
              pkgs.librsvg
              pkgs.zbar

              # Profiling and benchmarking
              pkgs.samply
              pkgs.hyperfine
              pkgs.cargo-flamegraph

              # Edge (Cloudflare) and web
              pkgs.wrangler
              pkgs.worker-build
              pkgs.nodejs_22
              pkgs.pnpm

              # Secrets and tooling
              pkgs.sops
              pkgs.age
              pkgs.ssh-to-age
              pkgs.just
              pkgs.jq
              pkgs.curl
              pkgs.dig
            ];

            RUST_BACKTRACE = "1";
          };

          # A separate workspace (fuzz/) built with the nightly toolchain.
          fuzz = pkgs.mkShell {
            packages = [
              nightly
              pkgs.cargo-fuzz
              pkgs.just
            ];

            RUST_BACKTRACE = "1";
          };
        };

        formatter = pkgs.nixfmt-rfc-style;

        checks = {
          fmt = craneLib.cargoFmt rustArgs;

          clippy = craneLib.cargoClippy (rustArgs // {
            inherit cargoArtifacts;
            cargoClippyExtraArgs = "--workspace --all-targets -- -D warnings";
          });

          tests = craneLib.cargoNextest (rustArgs // {
            inherit cargoArtifacts;
            cargoNextestExtraArgs = "--workspace";
            # The sandbox has no system trust store; HTTPS clients need one.
            SSL_CERT_FILE = "${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt";
          });

          # Licenses, bans and sources (deny.toml). Advisories need the
          # network: `just audit`.
          deny = craneLib.cargoDeny (rustArgs // {
            cargoDenyChecks = "licenses bans sources";
          });

          # A fixed slice of the simulator: the same 2,000 seeds every time,
          # each run twice to prove it replays exactly.
          sim = craneLib.mkCargoDerivation (rustArgs // {
            inherit cargoArtifacts;
            pnameSuffix = "-sim";
            buildPhaseCargoCommand = ''
              cargo build --release -p krypt-sim
              ./target/release/krypt-sim --seeds 2000 --determinism
            '';
            installPhaseCommand = "mkdir -p $out";
          });

          # Fails if any secret file is committed unencrypted.
          # Every theme defines the same tokens; references and haptics are well formed.
          design-tokens = pkgs.runCommand "design-tokens" { nativeBuildInputs = [ pkgs.jq ]; } ''
            bash ${./design/tokens/check.sh} ${./design/tokens}
            touch $out
          '';
        };
      });
}
