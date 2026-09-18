#!/usr/bin/env bash
set -euo pipefail

# Wrapper for harvesting Firehose loaders from bulk community sources
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_SCRIPT="${SCRIPT_DIR}/harvest_loaders.py"

if ! command -v gh &>/dev/null && ! command -v git &>/dev/null; then
    echo "Error: neither 'gh' nor 'git' is installed or in your PATH." >&2
    echo "Install gh via Homebrew: brew install gh" >&2
    exit 1
fi

if ! command -v python3 &>/dev/null; then
    echo "Error: 'python3' is not installed or not in your PATH." >&2
    exit 1
fi

exec python3 "${PYTHON_SCRIPT}" "$@"
