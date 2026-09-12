#!/usr/bin/env bash
# Thin convenience wrapper - identical to `python3 main.py "$@"`.
# Works with either `python3` or `python` on the PATH.
set -e
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if command -v python3 >/dev/null 2>&1; then
    exec python3 "$DIR/main.py" "$@"
elif command -v python >/dev/null 2>&1; then
    exec python "$DIR/main.py" "$@"
else
    echo "Python 3 is required but was not found on PATH." >&2
    exit 1
fi
