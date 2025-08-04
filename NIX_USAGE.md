# Using LilVault in Other Nix Flakes

This project exports the `lilvault` package as a devenv output, making it available for installation in other Nix flakes.

## Using in a Nix Flake

Add this project as an input to your `flake.nix`:

```nix
{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    lilvault = {
      url = "path:/path/to/lilvault"; # or git+https://... for remote
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, lilvault }: {
    # Install lilvault in your system packages
    nixosConfigurations.your-host = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        {
          environment.systemPackages = [
            lilvault.outputs.packages.x86_64-linux.lilvault
          ];
        }
      ];
    };

    # Or use in a dev shell
    devShells.x86_64-linux.default = nixpkgs.legacyPackages.x86_64-linux.mkShell {
      buildInputs = [
        lilvault.outputs.packages.x86_64-linux.lilvault
      ];
    };
  };
}
```

## Using with Home Manager

```nix
{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    home-manager.url = "github:nix-community/home-manager";
    lilvault = {
      url = "path:/path/to/lilvault";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { nixpkgs, home-manager, lilvault, ... }: {
    homeConfigurations.your-user = home-manager.lib.homeManagerConfiguration {
      pkgs = nixpkgs.legacyPackages.x86_64-linux;
      modules = [
        {
          home.packages = [
            lilvault.outputs.packages.x86_64-linux.lilvault
          ];
        }
      ];
    };
  };
}
```

## Package Details

The lilvault package includes:
- Pre-built SQLx queries for compile-time verification
- All necessary dependencies (SQLite, OpenSSL, etc.)
- Complete CLI functionality with ssh-keyscan integration
- Interactive terminal support with dialoguer

## Build Features

The Nix package automatically:
1. Sets up a temporary SQLite database with migrations
2. Runs SQLx compile-time query verification
3. Includes all runtime dependencies
4. Supports both terminal and non-terminal environments

## Requirements

- NixOS or Nix with flakes enabled
- SQLite available in the target environment (included automatically)
- ssh-keyscan available for host key scanning features

## Available Outputs

- `packages.${system}.lilvault` - The main lilvault binary
- `packages.${system}.default` - Alias to lilvault package

## Example Commands After Installation

```bash
# Initialize a new vault
lilvault init --name "primary"

# Add host keys via scanning
lilvault keys scan-host example.com

# Store secrets with interactive key selection
lilvault secret store my-secret --stdin
```
