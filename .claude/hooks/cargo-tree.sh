#!/usr/bin/env bash
# Check for duplicate dependencies

echo "🌳 Checking dependency tree for duplicates..."
if ! cargo tree --duplicates; then
  exit 2
fi
