#!/usr/bin/env bash
# Run the lint and type checks, then report copied code.
#   tools/check.sh
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
python="${PYTHON:-.venv/bin/python}"
[[ -x "$python" ]] || python=python3

"$python" -m ruff check src tests tools
"$python" -m mypy src tests

# Report copied code in the changed files. This report does not fail the check.
if command -v jscpd >/dev/null; then
  jscpd --changed --baseline "$(git rev-parse --git-dir)/jscpd-baseline.json" \
    --reporters ai --no-colors src tools || true
else
  echo "jscpd is not installed: no duplicate report."
fi
