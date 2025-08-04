#!/usr/bin/env nix-shell
#!nix-shell -i bash -p treefmt

# Wrapper script that converts treefmt failures to blocking exit code 2

treefmt
exit_code=$?

if [ $exit_code -ne 0 ]; then
    exit 2
fi

exit 0
