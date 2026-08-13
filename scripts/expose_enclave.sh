#!/usr/bin/env bash
# Starts the host-side argonaut bridges against a running sekisho enclave:
# inbound HTTP (host TCP:$HTTP_PORT -> enclave VSOCK:3000 -> enclave app) and
# outbound HTTPS for each domain in the provider allowlist (enclave loopback
# -> VSOCK -> this host -> the real provider). Replaces the plain-socat
# expose_enclave.sh used by an internal sibling project / the Nautilus template --
# sekisho bakes argonaut into the image instead (see enclave/eif/run.sh),
# and `argonaut host` does both directions of bridging in one process.
#
# Run this after `make -C enclave run-eif`. It runs in the foreground
# (matching the old socat-based script's shape); background it yourself
# (`... &`) if you want to keep using the same shell.
#
# Note: `argonaut host` unconditionally pushes enclave/eif/bridge-config.json
# to the enclave over VSOCK:7777 before it starts bridging. The enclave
# discards that push (see enclave/eif/run.sh) -- the real bridge topology
# comes from the identical copy of this file baked into the image at build
# time. This push still has to succeed for `argonaut host` to proceed, so run
# this only once the enclave has booted far enough to be listening on 7777.
set -euo pipefail

HTTP_PORT="${HTTP_PORT:-3000}"
ENCLAVE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../enclave" && pwd)"
BRIDGE_CONFIG="${BRIDGE_CONFIG:-$ENCLAVE_DIR/eif/bridge-config.json}"
ARGONAUT_BIN="${ARGONAUT_BIN:-$ENCLAVE_DIR/out/argonaut-host}"

if ! command -v nitro-cli >/dev/null 2>&1; then
  echo "nitro-cli is required on the Nitro host" >&2
  exit 1
fi
if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required" >&2
  exit 1
fi
if [ ! -x "$ARGONAUT_BIN" ]; then
  echo "argonaut host binary not found at $ARGONAUT_BIN." >&2
  echo "Run 'make -C enclave eif' first -- it exports argonaut-host alongside nitro.eif," >&2
  echo "guaranteeing it's byte-identical to the argonaut baked into the enclave image." >&2
  exit 1
fi
if [ ! -f "$BRIDGE_CONFIG" ]; then
  echo "bridge config not found at $BRIDGE_CONFIG" >&2
  exit 1
fi

ENCLAVE_CID=$(nitro-cli describe-enclaves | jq -r ".[0].EnclaveCID")
if [ "$ENCLAVE_CID" = "null" ] || [ -z "$ENCLAVE_CID" ]; then
  echo "No running enclave found. Run 'make -C enclave run-eif' first." >&2
  exit 1
fi

# argonaut's host mode takes its httpPort strictly from the config file (no
# CLI flag), so honor $HTTP_PORT by patching a temp copy when it differs from
# the file's baked-in default.
CONFIG_HTTP_PORT=$(jq -r '.httpPort' "$BRIDGE_CONFIG")
if [ "$CONFIG_HTTP_PORT" != "$HTTP_PORT" ]; then
  PATCHED_CONFIG=$(mktemp)
  trap 'rm -f "$PATCHED_CONFIG"' EXIT
  jq --argjson port "$HTTP_PORT" '.httpPort = $port' "$BRIDGE_CONFIG" > "$PATCHED_CONFIG"
  BRIDGE_CONFIG="$PATCHED_CONFIG"
fi

echo "Enclave CID: $ENCLAVE_CID"
echo "argonaut host: TCP:${HTTP_PORT} <-> VSOCK:${ENCLAVE_CID} <-> enclave bridges"
echo "bridge config: $BRIDGE_CONFIG"
exec "$ARGONAUT_BIN" host "$ENCLAVE_CID" "$BRIDGE_CONFIG"
