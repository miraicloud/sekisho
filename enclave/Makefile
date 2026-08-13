REGISTRY ?= local
OUT_DIR ?= out
ENCLAVE_MEMORY ?= 4096M
ENCLAVE_PACKAGE ?= sekisho-enclave
ENCLAVE_BIN ?= $(ENCLAVE_PACKAGE)
HTTP_PORT ?= 3000

# argonaut is built from source inside Containerfile.eif, pinned to a fixed
# commit for reproducibility. Override to test against a newer argonaut
# revision; the default is the pinned, audited value.
ARGONAUT_REV ?= 8f5d1ba937fb2020b6572cc834faa4ceaf939d1c

EIF_INPUTS := Cargo.toml Cargo.lock rust-toolchain.toml Containerfile.eif .dockerignore $(shell find src eif -type f 2>/dev/null)

.DEFAULT_GOAL := eif

.PHONY: eif
eif: $(OUT_DIR)/nitro.eif

$(OUT_DIR):
	mkdir -p $(OUT_DIR)

# Produces nitro.eif, nitro.pcrs, rootfs.cpio, and argonaut-host (the exact
# argonaut binary baked into the enclave, for host-side use -- see
# scripts/expose_enclave.sh) in a single build.
$(OUT_DIR)/nitro.eif: $(EIF_INPUTS) | $(OUT_DIR)
	docker build \
		--pull \
		--tag $(REGISTRY)/sekisho-rust-enclave \
		--progress=plain \
		--platform linux/amd64 \
		--provenance=false \
		--output type=local,rewrite-timestamp=true,dest=$(OUT_DIR) \
		-f Containerfile.eif \
		--build-arg ENCLAVE_PACKAGE=$(ENCLAVE_PACKAGE) \
		--build-arg ENCLAVE_BIN=$(ENCLAVE_BIN) \
		--build-arg ARGONAUT_REV=$(ARGONAUT_REV) \
		.

.PHONY: run-eif
run-eif: $(OUT_DIR)/nitro.eif
	nitro-cli run-enclave \
		--cpu-count 2 \
		--memory $(ENCLAVE_MEMORY) \
		--eif-path $(PWD)/$(OUT_DIR)/nitro.eif

.PHONY: run-eif-debug
run-eif-debug: $(OUT_DIR)/nitro.eif
	nitro-cli run-enclave \
		--cpu-count 2 \
		--memory $(ENCLAVE_MEMORY) \
		--eif-path $(PWD)/$(OUT_DIR)/nitro.eif \
		--debug-mode \
		--attach-console

.PHONY: run run-debug
run: run-eif
run-debug: run-eif-debug

# Starts the host-side argonaut bridges (inbound HTTP :3000, outbound HTTPS
# to the provider allowlist) against the running enclave. Requires
# `make run-eif` first (the enclave must be listening for this call's
# mandatory VSOCK:7777 handshake -- see enclave/eif/run.sh). The gateway
# itself won't start until you *also* run scripts/send_boot_config.sh --
# see .claude/skills/register-enclave.md for the full sequence.
.PHONY: expose
expose:
	HTTP_PORT=$(HTTP_PORT) ../scripts/expose_enclave.sh

.PHONY: stop
stop:
	nitro-cli terminate-enclave --all

.PHONY: dev
dev:
	cargo run

.PHONY: check
check:
	cargo fmt --check
	cargo clippy --all-targets --locked -- -D warnings
	cargo test --all-targets --locked

.PHONY: clean
clean:
	rm -rf $(OUT_DIR)/
