#!/usr/bin/env bash
# Pushes sekisho's application boot config (provider API keys, caller bearer
# keys, policy JSON) to a running enclave over its dedicated one-shot VSOCK
# channel (port 7778 -- see enclave/eif/run.sh; distinct from argonaut's own
# bootstrap handshake on 7777, which `make expose` / scripts/expose_enclave.sh
# handles). The gateway process does not start until this has been received,
# so GET /attestation etc. are unreachable until you run this.
#
# Usage:
#   scripts/send_boot_config.sh path/to/boot-config.json
#
# boot-config.json shape is owned by enclave/src (see docs/SPEC.md sec 4):
# roughly { "providers": {...api keys...}, "callers": {...bearer keys...},
# "policy": {...} }. This script does not validate its contents -- the
# enclave does, and its SHA-256 becomes config_hash in every Receipt.
set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "Usage: $0 <boot-config.json>" >&2
  exit 1
fi

CONFIG_FILE="$1"
ENCLAVE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../enclave" && pwd)"
ARGONAUT_BIN="${ARGONAUT_BIN:-$ENCLAVE_DIR/out/argonaut-host}"

if [ ! -f "$CONFIG_FILE" ]; then
  echo "Config file not found: $CONFIG_FILE" >&2
  exit 1
fi
if ! command -v nitro-cli >/dev/null 2>&1; then
  echo "nitro-cli is required on the Nitro host" >&2
  exit 1
fi
if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required" >&2
  exit 1
fi
if [ ! -x "$ARGONAUT_BIN" ]; then
  echo "argonaut host binary not found at $ARGONAUT_BIN -- run 'make -C enclave eif' first." >&2
  exit 1
fi

SIZE=$(wc -c < "$CONFIG_FILE")
if [ "$SIZE" -gt 1048576 ]; then
  echo "Config file is ${SIZE} bytes; argonaut's one-shot config channel caps payloads at 1 MiB." >&2
  exit 1
fi

ENCLAVE_CID=$(nitro-cli describe-enclaves | jq -r ".[0].EnclaveCID")
if [ "$ENCLAVE_CID" = "null" ] || [ -z "$ENCLAVE_CID" ]; then
  echo "No running enclave found. Run 'make -C enclave run-eif' first." >&2
  exit 1
fi

echo "Sending $CONFIG_FILE ($SIZE bytes) to CID $ENCLAVE_CID over VSOCK:7778..."
"$ARGONAUT_BIN" config send "$ENCLAVE_CID" 7778 < "$CONFIG_FILE"
echo "Sent. The gateway should now be starting -- check with:"
echo "  curl \"http://<host>:\${HTTP_PORT:-3000}/health_check\""
