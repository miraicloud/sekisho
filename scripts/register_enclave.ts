#!/usr/bin/env bun
/**
 * Register a sekisho enclave on-chain by fetching a nonce-bound Nitro
 * attestation document and calling sekisho::checkpoint::register via a Sui
 * PTB. Adapted from an internal sibling project's registration script.
 *
 * Registration is bound to the registering Sui address (docs/SPEC.md sec 3):
 * `checkpoint::register` asserts the attestation document's `nonce` field
 * equals the BCS bytes of `ctx.sender()`. This closes a hijack path -- since
 * GET /attestation is public and unbound, anyone could otherwise grab a live
 * enclave's attestation document and register it under their own address
 * first. So this script does NOT use GET /attestation; it POSTs a nonce
 * (BCS(sender address), hex-encoded) and only that nonce-bound document is
 * submitted on-chain.
 *
 * PTB:
 *   0x2::nitro_attestation::load_nitro_attestation(attestation_bytes, @0x6)
 *   -> sekisho::checkpoint::register(checkpoint, doc)
 * (register shares the resulting Gateway object itself -- no separate
 * `share` call needed, per docs/SPEC.md sec 3 / docs/research/nautilus.md sec 3.)
 *
 * Usage:
 *   bun scripts/register_enclave.ts [--dry-run]
 *
 * Env:
 *   GATEWAY_URL        http(s) URL of the running gateway (default http://localhost:3000)
 *   SEKISHO_PACKAGE    sekisho Move package id (required)
 *   CHECKPOINT_OBJECT  shared Checkpoint object id (required)
 */

import { execSync } from "node:child_process";
import { bcs } from "@mysten/sui/bcs";
import { parseAttestationDocument, pcrHex } from "./lib/attestation";

const GATEWAY_URL = process.env.GATEWAY_URL ?? "http://localhost:3000";
const SEKISHO_PACKAGE = process.env.SEKISHO_PACKAGE;
const CHECKPOINT_OBJECT = process.env.CHECKPOINT_OBJECT;
const DRY_RUN = process.argv.includes("--dry-run");

/** Hex string -> Sui PTB `vector[N u8, ...]` literal. */
function hexToVectorLiteral(hex: string): string {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  const bytes: string[] = [];
  for (let i = 0; i < clean.length; i += 2) {
    bytes.push(`${parseInt(clean.slice(i, i + 2), 16)}u8`);
  }
  return `vector[${bytes.join(", ")}]`;
}

function activeAddress(): string {
  return execSync("sui client active-address", { encoding: "utf-8" }).trim();
}

async function main() {
  if (!SEKISHO_PACKAGE || !CHECKPOINT_OBJECT) {
    console.error("Set SEKISHO_PACKAGE and CHECKPOINT_OBJECT env vars before running this script.");
    process.exit(1);
  }

  const sender = activeAddress();
  console.log(`Sender: ${sender}`);

  // nonce = BCS(address) -- a fixed-size 32-byte encoding, no length prefix.
  const nonceBytes = bcs.Address.serialize(sender).toBytes();
  const nonceHex = Buffer.from(nonceBytes).toString("hex");
  console.log(`Requesting nonce-bound attestation (nonce=${nonceHex})...`);

  const res = await fetch(`${GATEWAY_URL}/attestation`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ nonce: nonceHex }),
  });
  if (!res.ok) {
    throw new Error(`Gateway returned ${res.status}: ${await res.text()}`);
  }
  const { attestation } = (await res.json()) as { attestation: string };
  console.log(
    `Attestation hex length: ${attestation.length} chars (${attestation.length / 2} bytes)`,
  );

  // Sanity-check locally before spending gas: public_key present, nonce
  // actually matches what we asked for. Full COSE/cert-chain verification
  // happens on-chain in load_nitro_attestation; this is just a fast local
  // fail-fast for obviously-wrong responses.
  try {
    const doc = parseAttestationDocument(attestation);
    if (!doc.publicKey) {
      console.error("WARNING: 'public_key' missing from attestation document.");
    } else {
      console.log(`Public key present: ${doc.publicKey.length} bytes`);
    }
    const gotNonce = doc.nonce ? Buffer.from(doc.nonce).toString("hex") : undefined;
    if (gotNonce !== nonceHex) {
      console.error(
        `WARNING: attestation nonce (${gotNonce ?? "<none>"}) does not match the requested ` +
          `nonce (${nonceHex}). On-chain registration will fail with ENonceNotSender.`,
      );
    }
    console.log(`PCR0: ${pcrHex(doc, 0) ?? "<missing>"}`);
    console.log(`PCR1: ${pcrHex(doc, 1) ?? "<missing>"}`);
    console.log(`PCR2: ${pcrHex(doc, 2) ?? "<missing>"}`);
  } catch (err) {
    console.error(`WARNING: could not locally parse attestation document: ${(err as Error).message}`);
  }

  const vectorLiteral = hexToVectorLiteral(attestation);

  const ptbArgs = [
    `--assign v "${vectorLiteral}"`,
    `--move-call "0x2::nitro_attestation::load_nitro_attestation" v @0x6`,
    `--assign attestation_doc`,
    `--move-call "${SEKISHO_PACKAGE}::checkpoint::register" @${CHECKPOINT_OBJECT} attestation_doc`,
    `--gas-budget 100000000`,
  ];
  if (DRY_RUN) ptbArgs.push("--dry-run");

  const cmd = `sui client ptb ${ptbArgs.join(" \\\n    ")}`;

  console.log(`\nExecuting PTB as ${sender}...`);
  if (DRY_RUN) console.log("(dry-run mode)");

  try {
    const result = execSync(cmd, { encoding: "utf-8", maxBuffer: 50 * 1024 * 1024 });
    console.log(result);
  } catch (err: any) {
    console.error("Transaction failed:");
    console.error(err.stderr || err.stdout || err.message);
    console.error(
      "\nIf this is ENonceNotSender: the attestation's nonce didn't match ctx.sender() at " +
        "execution time. Re-run this script (it always binds the nonce to the current " +
        "`sui client active-address`) rather than reusing a previously-fetched attestation, " +
        "and make sure you haven't switched active addresses in between.",
    );
    process.exit(1);
  }
}

main();
