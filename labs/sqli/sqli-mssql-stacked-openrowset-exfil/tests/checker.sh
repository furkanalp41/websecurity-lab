#!/bin/sh
# SPDX-License-Identifier: MIT
set -eu
TARGET="${1:-${TARGET:-http://127.0.0.1:8080}}"
exec timeout 180 python3 "$(dirname "$0")/exploit.py" --target "$TARGET" --timeout 170
