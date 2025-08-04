#!/usr/bin/env bash
# Run Rust clippy linting

echo "📎 Running Clippy linting..."

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

if ! cargo clippy -- -D warnings; then
  exit 2
fi
