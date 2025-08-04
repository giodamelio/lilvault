#!/usr/bin/env bash
# Generate Rust documentation

echo "📚 Generating documentation..."
if ! cargo doc --no-deps; then
  exit 2
fi
