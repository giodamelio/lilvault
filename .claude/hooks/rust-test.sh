#!/usr/bin/env bash
# Run Rust tests

echo "🧪 Running Rust tests..."

# Set up database for SQLx
export DATABASE_URL="sqlite:vault.db"

# Ensure database exists and run migrations if needed
if [ ! -f "vault.db" ]; then
  echo "📋 Creating database and running migrations..."
  if ! sqlx database create; then
    exit 2
  fi
  if ! sqlx migrate run; then
    exit 2
  fi
fi

# Run tests (skip interactive tests in CI-like environment)
if ! cargo test --lib --bins; then
  exit 2
fi
