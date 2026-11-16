#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

if ! command -v php >/dev/null 2>&1; then
    echo "PHP CLI is required to run the tests." >&2
    exit 127
fi

php "$SCRIPT_DIR/run-tests.php"
