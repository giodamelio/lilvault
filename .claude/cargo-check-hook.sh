#!/usr/bin/env nix-shell
#!nix-shell -i bash -p cargo

# Wrapper script that converts cargo check failures to blocking exit code 2

cargo check
exit_code=$?

if [ $exit_code -ne 0 ]; then
    exit 2
fi

exit 0
