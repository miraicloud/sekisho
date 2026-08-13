#!/bin/sh
# Nitro Enclave init script (PID 1's target via `nit.target=/run.sh`).
#
# Sequencing matters here:
#
#   1. Loopback up.
#   2. Drain argonaut's own host->enclave handshake on VSOCK:7777. `argonaut host`
#      (run by the operator via `make expose`) unconditionally pushes its bridge
#      config to VSOCK:7777 before it will start bridging -- that push target is
#      hardcoded in argonaut (see unconfirmedlabs/argonaut main.go, configVsockPort)
#      and is NOT ours to configure. We must have something listening there or
#      `make expose` fails outright. We deliberately DISCARD what's received: the
#      real bridge topology (which domains this enclave may reach) comes from the
#      config baked into the image at /etc/argonaut/bridge-config.json, not from
#      whatever the (untrusted) EC2 host chooses to send -- see step 4.
#   3. Receive sekisho's OWN one-shot boot config (provider API keys, caller
#      bearer keys, policy JSON) on a *different* VSOCK port (7778), via
#      argonaut's low-level one-shot `config recv` primitive. Never baked into
#      the image (would break reproducibility across operators and put secrets
#      in the PCR-measured image); config_hash of this blob ends up in every
#      Receipt instead (docs/SPEC.md sec 3/4).
#   4. Start the argonaut enclave-side bridges (inbound HTTP :3000, outbound
#      HTTPS to the provider allowlist) from the image-baked, PCR-visible
#      config -- so a rebuild is required to change which domains the gateway
#      can reach, and that rebuild changes PCR2.
#   5. exec the gateway. It only starts once boot config has arrived.
set -eu

export PATH=/bin:/sbin:/usr/bin:/usr/sbin
export SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt

busybox ip addr add 127.0.0.1/32 dev lo 2>/dev/null || true
busybox ip link set dev lo up
echo "127.0.0.1 localhost" > /etc/hosts

# --- 2. Drain argonaut's own bootstrap push (discarded; see header) ---
/bin/argonaut config recv 7777 > /dev/null

# --- 3. Sekisho application boot config (secrets), one-shot on VSOCK:7778 ---
/bin/argonaut config recv 7778 > /tmp/sekisho-config.json
chmod 600 /tmp/sekisho-config.json
export SEKISHO_CONFIG=/tmp/sekisho-config.json

# --- 4. Bridges: inbound HTTP :3000, outbound HTTPS to the baked-in allowlist ---
/bin/argonaut enclave < /etc/argonaut/bridge-config.json &

# --- 5. Hand off to the gateway ---
exec /sekisho-enclave
