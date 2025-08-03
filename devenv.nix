{
  pkgs,
  lib,
  config,
  inputs,
  ...
}: let
  pkgs-unstable = import inputs.nixpkgs-unstable {
    inherit (pkgs) system;
    config = pkgs.config;
  };
  mcp-config = inputs.mcp-servers.lib.mkConfig pkgs-unstable {
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
in {
  languages.rust = {
    enable = true;
    channel = "stable";
    components = ["rustc" "cargo" "clippy" "rustfmt" "rust-analyzer" "llvm-tools-preview"];
  };

  packages = [
    pkgs-unstable.claude-code
    pkgs.rage
    pkgs.alejandra
    pkgs.treefmt
    pkgs.nil
    inputs.my-configs.packages.${pkgs.system}.mcp-language-server
  ];

  # Git hooks for code quality
  git-hooks = {
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

      # General code quality
      check-merge-conflicts.enable = true;
      check-added-large-files.enable = true;
      check-toml.enable = true;
      check-yaml.enable = true;
      end-of-file-fixer.enable = true;
      trim-trailing-whitespace.enable = true;
    };
  };

  # Setup MCP configs
  enterShell = ''
    export MEMORY_FILE_PATH=$(pwd)/.claude/memory.json
    ln -sf ${mcp-config} .mcp.json
  '';
}
