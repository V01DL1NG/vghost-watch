#!/usr/bin/env bash
# Optional weekly runner for cron (Linux/macOS). Not installed automatically --
# this repo has no CI/remote scheduler. To use it:
#
#   crontab -e
#   0 6 * * 1 SHODAN_API_KEY=... /path/to/vghost-watch/scripts/weekly_cron.sh >> /path/to/vghost-watch/weekly.log 2>&1
#
# Adjust REPO_DIR below if this script is copied elsewhere, and set
# SHODAN_API_KEY in the crontab line (or export it in a file this script
# sources) if you want the Shodan step to run.
set -euo pipefail
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_DIR"

if [ -d .venv ]; then
  # shellcheck disable=SC1091
  source .venv/bin/activate
fi

ARGS=(--sender-name "${SENDER_NAME:-[your name]}")
if [ -n "${SHODAN_QUERY:-}" ]; then
  ARGS+=(--shodan-query "$SHODAN_QUERY")
fi

python3 src/run_pipeline.py "${ARGS[@]}"
