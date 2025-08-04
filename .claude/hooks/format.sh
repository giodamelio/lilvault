#!/usr/bin/env bash
# Format code with treefmt

echo "🔧 Formatting code..."
if ! treefmt; then
  exit 2
fi
