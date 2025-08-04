{
  description = "LilVault - A secure, encrypted secrets management system for homelabs";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    flake-parts.url = "github:hercules-ci/flake-parts";

    treefmt-nix = {
      url = "github:numtide/treefmt-nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    git-hooks-nix = {
      url = "github:cachix/git-hooks.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    # Fenix for Rust toolchain
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    # MCP servers for development tools
    mcp-servers = {
      url = "github:natsukium/mcp-servers-nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = inputs @ {flake-parts, ...}:
    flake-parts.lib.mkFlake {inherit inputs;} {
      systems = ["x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin"];

      imports = [
        inputs.treefmt-nix.flakeModule
        inputs.git-hooks-nix.flakeModule
      ];

      perSystem = {
        config,
        self',
        inputs',
        pkgs,
        system,
        ...
      }: let
        # Prepare SQLx database for compile-time verification
        sqlx-db =
          pkgs.runCommand "sqlx-db-prepare" {
            nativeBuildInputs = with pkgs; [sqlx-cli sqlite];
          } ''
            mkdir -p $out
            export DATABASE_URL=sqlite:$out/db.sqlite3

            # Create database and run migrations
            sqlx database create
            sqlx migrate run --source ${./migrations}
          '';

        # Fenix Rust toolchain
        rustToolchain = inputs.fenix.packages.${system}.stable.toolchain;

        # MCP configuration
        mcpConfig = inputs.mcp-servers.lib.mkConfig pkgs {
          format = "json";
          fileName = ".mcp.json";

          programs = {
            memory = {
              enable = true;
              env = {
                "MEMORY_FILE_PATH" = "\${MEMORY_FILE_PATH}";
              };
            };
            sequential-thinking.enable = true;
          };

          settings.servers = {
            language-server = {
              command = "mcp-language-server";
              args = ["--workspace" "." "--lsp" "rust-analyzer"];
            };
          };
        };

        # Manual Rust package using Fenix toolchain
        lilvault =
          (pkgs.makeRustPlatform {
            cargo = rustToolchain;
            rustc = rustToolchain;
          }).buildRustPackage {
            pname = "lilvault";
            version = "0.1.0";

            src = pkgs.lib.cleanSource ./.;

            cargoLock = {
              lockFile = ./Cargo.lock;
            };

            nativeBuildInputs = with pkgs; [
              pkg-config
              sqlx-cli
            ];

            buildInputs = with pkgs; [
              sqlite
              openssl
            ];

            # Set up database for SQLx compile-time verification
            preBuild = ''
              export DATABASE_URL=sqlite:${sqlx-db}/db.sqlite3
            '';

            # Skip tests in Nix build (tests require interactive terminal features)
            doCheck = false;

            meta = with pkgs.lib; {
              description = "A secure, encrypted secrets management system for homelabs";
              homepage = "https://github.com/yourusername/lilvault";
              license = with licenses; [mit asl20];
              maintainers = [];
              mainProgram = "lilvault";
            };
          };
      in {
        imports = [
          "${inputs.nixpkgs}/nixos/modules/misc/nixpkgs.nix"
        ];

        nixpkgs = {
          hostPlatform = system;
          config.allowUnfree = true;
        };

        # Flake checks (equivalent to .claude/ hook scripts)
        checks = {
          # Rust compilation check
          rust-check =
            pkgs.runCommand "rust-check" {
              nativeBuildInputs = with pkgs; [cargo rustc pkg-config sqlx-cli];
              buildInputs = with pkgs; [sqlite openssl];
              src = pkgs.lib.cleanSource ./.;
            } ''
              cd $src
              export DATABASE_URL=sqlite:${sqlx-db}/db.sqlite3
              cargo check
              touch $out
            '';

          # Rust linting with clippy
          rust-clippy =
            pkgs.runCommand "rust-clippy" {
              nativeBuildInputs = with pkgs; [cargo rustc clippy pkg-config sqlx-cli];
              buildInputs = with pkgs; [sqlite openssl];
              src = pkgs.lib.cleanSource ./.;
            } ''
              cd $src
              export DATABASE_URL=sqlite:${sqlx-db}/db.sqlite3
              cargo clippy -- -D warnings
              touch $out
            '';

          # Rust tests (when not running in interactive mode)
          rust-test =
            pkgs.runCommand "rust-test" {
              nativeBuildInputs = with pkgs; [cargo rustc pkg-config sqlx-cli];
              buildInputs = with pkgs; [sqlite openssl];
              src = pkgs.lib.cleanSource ./.;
            } ''
              cd $src
              export DATABASE_URL=sqlite:${sqlx-db}/db.sqlite3
              # Skip interactive tests in check environment
              CARGO_TARGET_DIR=/tmp/cargo-target cargo test --lib --bins
              touch $out
            '';

          # Code formatting check
          treefmt-check = config.treefmt.build.check (pkgs.lib.cleanSource ./.);

          # Pre-commit hooks check
          pre-commit-check = config.pre-commit.build.devShell;
        };

        packages = {
          inherit lilvault;
          default = lilvault;

          # Development utility scripts
          dump-schema = pkgs.writeShellApplication {
            name = "dump-schema";
            runtimeInputs = with pkgs; [sqlx-cli sqlite lilvault];
            text = builtins.readFile ./bin/dump-schema.sh;
          };
        };

        # Treefmt configuration
        treefmt.config = {
          projectRootFile = "flake.nix";
          programs = {
            alejandra.enable = true; # Nix formatter
            rustfmt.enable = true; # Rust formatter
            shfmt.enable = true; # Shell script formatter
          };
        };

        # Git hooks configuration
        pre-commit = {
          check.enable = true;
          settings = {
            hooks = {
              # Tree formatting (formats all files)
              treefmt = {
                enable = true;
                description = "Format code with treefmt";
              };

              # Rust linting
              clippy = {
                enable = true;
                description = "Lint Rust code with clippy";
                settings = {
                  denyWarnings = true;
                };
              };

              # Shell script linting
              shellcheck = {
                enable = true;
                description = "Lint shell scripts with shellcheck";
              };

              # General code quality
              check-merge-conflicts.enable = true;
              check-added-large-files.enable = true;
              check-toml.enable = true;
              check-yaml.enable = true;
              end-of-file-fixer.enable = true;
              trim-trailing-whitespace.enable = true;
            };
          };
        };

        # Simple development shell using Fenix toolchain
        devShells.default = pkgs.mkShell {
          packages = with pkgs;
            [
              # Fenix Rust toolchain with all components
              (inputs.fenix.packages.${system}.stable.withComponents [
                "cargo"
                "rustc"
                "clippy"
                "rustfmt"
                "rust-analyzer"
                "rust-src"
              ])

              # Core development tools
              sqlite
              sqlx-cli
              pkg-config

              # Utilities
              rage # age encryption tool

              # Development scripts
              config.packages.dump-schema

              # Treefmt tools
              config.treefmt.build.wrapper # Wrapped treefmt script

              # Nix Language Server
              nil

              # Claude Code
              claude-code
            ]
            ++
            # All the formatter programs
            (lib.attrValues config.treefmt.build.programs);

          shellHook = ''
            echo "🚀 Welcome to LilVault development environment!"
            echo "📦 Available commands:"
            echo "  - cargo build/test/run"
            echo "  - dump-schema (generate db/schema.sql)"
            echo "  - nix fmt (format all files)"
            echo ""

            # Set up MCP environment
            export MEMORY_FILE_PATH=$(pwd)/.claude/memory.json
            ln -sf ${mcpConfig}/.mcp.json .mcp.json

            # Generate initial schema.sql if it doesn't exist
            if [ ! -f db/schema.sql ]; then
              echo "📋 Generating initial schema.sql..."
              dump-schema
            fi
          '';
        };
      };
    };
}
