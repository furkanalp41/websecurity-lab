#!/bin/sh
# SPDX-License-Identifier: MIT
set -eu
TARGET="${1:-${TARGET:-http://127.0.0.1:8080}}"
here="$(cd "$(dirname "$0")" && pwd)"
python3 "$here/exploit.py" --target "$TARGET" --timeout 60 | tail -n1 | grep -Eq '^FLAG\{[0-9a-f]{64}\}$'
echo "checker: solved"
