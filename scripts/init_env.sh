#!/usr/bin/env bash
# Interactively create/update .env at the repo root with the API keys and
# settings the scripts read from the environment. .env is gitignored --
# nothing here gets committed. Leave a prompt blank to keep the existing
# value (or leave it unset).
#
# Usage:
#   scripts/init_env.sh
#
# To load the values into your current shell afterward:
#   set -a; source .env; set +a
set -euo pipefail
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$REPO_DIR/.env"

declare -a KEYS=(SHODAN_API_KEY CENSYS_API_ID CENSYS_API_SECRET SENDER_NAME SHODAN_QUERY)
declare -A CURRENT

if [ -f "$ENV_FILE" ]; then
  while IFS='=' read -r k v; do
    [[ -z "$k" || "$k" == \#* ]] && continue
    CURRENT["$k"]="$v"
  done < "$ENV_FILE"
fi

echo "Creating/updating $ENV_FILE -- leave blank to keep current value, 'y' prompt only in TTY."
for key in "${KEYS[@]}"; do
  existing="${CURRENT[$key]:-}"
  if [ -n "$existing" ]; then
    masked="${existing:0:4}...(${#existing} chars)"
    read -r -p "$key [$masked]: " input
  else
    read -r -p "$key []: " input
  fi
  if [ -n "$input" ]; then
    CURRENT["$key"]="$input"
  fi
done

{
  echo "# Created by scripts/init_env.sh -- do not commit (see .gitignore)"
  for key in "${KEYS[@]}"; do
    val="${CURRENT[$key]:-}"
    [ -n "$val" ] && echo "$key=$val"
  done
} > "$ENV_FILE"
chmod 600 "$ENV_FILE"

echo "[+] wrote $ENV_FILE (permissions 600)"
echo "[*] load it into your shell with:  set -a; source .env; set +a"
echo "[*] run_pipeline.py also loads it automatically when run from the repo root"
