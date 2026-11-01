#!/usr/bin/env bash
# Required verification entry for Fairlead.
set -euo pipefail
cd "$(dirname "$0")/.."

cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace

# The generated release-rewriter must pass the same helper tests CI runs.
PYTHONDONTWRITEBYTECODE=1 python3 .github/test_release.py
