#!/usr/bin/env nix-shell
#!nix-shell -i bash -p cargo

# Wrapper script that converts cargo test failures to blocking exit code 2

cargo test
exit_code=$?

if [ $exit_code -ne 0 ]; then
    exit 2
fi

exit 0
