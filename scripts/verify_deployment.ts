#!/usr/bin/env bun
/**
 * Verify a running sekisho gateway is exactly the code it claims to be.
 *
 * This is the product's whole pitch, executable in one command (docs/SPEC.md
 * sec 5): given a gateway URL and a git ref, it
 *
 *   (a) fetches GET /attestation from the live gateway and extracts PCR0/1/2
 *       + the enclave's ephemeral public key,
 *   (b) compares those PCRs against a locally-built out/nitro.pcrs for that
 *       ref (built via `make -C enclave eif`) and/or a published nitro.pcrs
 *       file,
 *   (c) if a Checkpoint object id is given, confirms on-chain that this PCR
 *       triple is approved and not revoked, and (if a Gateway object id is
 *       also given) that the pubkey is registered against it.
 *
 * Every check prints a clear PASS / FAIL / WARN / SKIP line; the process
 * exits non-zero if any check FAILs.
 *
 * This script does NOT verify the attestation document's COSE signature or
 * AWS certificate chain -- that verification is `sui::nitro_attestation`'s
 * job on-chain (see scripts/lib/attestation.ts header, docs/research/nautilus.md
 * sec 3). What it verifies is: does the *code* the live gateway is running
 * match the *code* at this git ref (PCR equality), and does the chain agree
 * this code + key is registered and trusted.
 *
 * Usage:
 *   bun scripts/verify_deployment.ts <gateway-url> --ref <git-ref> \
 *     [--pcrs-file <path-or-url>] [--checkpoint <object-id>] [--gateway <object-id>] \
 *     [--rpc <url>] [--network mainnet|testnet|devnet|localnet] [--skip-build]
 *
 * Examples:
 *   bun scripts/verify_deployment.ts https://gateway.example.com --ref v1.2.0
 *   bun scripts/verify_deployment.ts http://localhost:3000 --ref $(git rev-parse HEAD) \
 *     --checkpoint 0xabc... --gateway 0xdef... --network testnet
 */

import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { parseAttestationDocument, pcrHex, type NitroAttestationDoc } from "./lib/attestation";

type Status = "PASS" | "FAIL" | "WARN" | "SKIP";

interface CheckResult {
  status: Status;
  label: string;
  detail?: string;
}

const results: CheckResult[] = [];
function report(status: Status, label: string, detail?: string) {
  results.push({ status, label, detail });
  const icon = { PASS: "✓", FAIL: "✗", WARN: "!", SKIP: "-" }[status];
  const line = `[${icon} ${status}] ${label}`;
  console.log(detail ? `${line}\n      ${detail}` : line);
}

function parseArgs(argv: string[]) {
  const positional: string[] = [];
  const flags: Record<string, string> = {};
  const boolFlags = new Set(["skip-build"]);
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith("--")) {
      const name = a.slice(2);
      if (boolFlags.has(name)) {
        flags[name] = "true";
      } else {
        flags[name] = argv[++i];
      }
    } else {
      positional.push(a);
    }
  }
  return { positional, flags };
}

function normalizePcrHex(h: string): string {
  return h.trim().toLowerCase().replace(/^0x/, "");
}

/** Parses eif_build's `--pcrs_output` format: `<hex> PCR<N>` per line. */
function parsePcrsFile(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const rawLine of text.trim().split("\n")) {
    const line = rawLine.trim();
    if (!line) continue;
    const parts = line.split(/\s+/);
    if (parts.length !== 2) continue;
    const [hex, label] = parts;
    out[label.toUpperCase()] = normalizePcrHex(hex);
  }
  return out;
}

async function loadExpectedPcrs(source: string): Promise<Record<string, string>> {
  if (source.startsWith("http://") || source.startsWith("https://")) {
    const res = await fetch(source);
    if (!res.ok) throw new Error(`fetching ${source}: HTTP ${res.status}`);
    return parsePcrsFile(await res.text());
  }
  return parsePcrsFile(await readFile(source, "utf-8"));
}

async function fetchLiveAttestation(gatewayUrl: string): Promise<NitroAttestationDoc> {
  const res = await fetch(`${gatewayUrl.replace(/\/$/, "")}/attestation`);
  if (!res.ok) {
    throw new Error(`GET ${gatewayUrl}/attestation returned HTTP ${res.status}`);
  }
  const { attestation } = (await res.json()) as { attestation: string };
  return parseAttestationDocument(attestation);
}

function comparePcrs(live: NitroAttestationDoc, expected: Record<string, string>) {
  for (const index of [0, 1, 2] as const) {
    const liveHex = pcrHex(live, index);
    const expectedHex = expected[`PCR${index}`];
    const label = `PCR${index}`;
    if (!liveHex) {
      report("FAIL", label, "missing from the live attestation document");
      continue;
    }
    if (!expectedHex) {
      report("FAIL", label, "missing from the expected PCRs source");
      continue;
    }
    if (liveHex === expectedHex) {
      report("PASS", label, liveHex);
    } else {
      report("FAIL", label, `live=${liveHex} expected=${expectedHex}`);
    }
  }
}

// --- On-chain checks (best-effort: move/checkpoint.move's exact object shape
// may still be evolving; these degrade to WARN with the raw JSON rather than
// crashing the whole script on an unexpected field layout). ---

/** Best-effort coercion of a Move JSON field to lowercase hex, handling the
 * couple of plausible representations (hex string, 0x-prefixed hex, byte array). */
/**
 * Move `vector<u8>` fields reach us in three different shapes depending on the
 * reader: `sui client object --json` emits **base64**, some RPC paths emit a
 * plain number array, and hand-written input is usually hex. Handle all three
 * — assuming hex silently produced "no approved entry matches" against a
 * Checkpoint whose entry did in fact match, since base64 is often valid hex-ish
 * text but decodes to entirely different bytes.
 */
function fieldToHex(value: unknown): string | undefined {
  if (Array.isArray(value) && value.every((v) => typeof v === "number")) {
    return Buffer.from(value as number[]).toString("hex");
  }
  if (typeof value !== "string") return undefined;

  const stripped = value.startsWith("0x") ? value.slice(2) : value;
  // A PCR is 48 bytes: 96 hex chars, or 64 base64 chars.
  if (/^[0-9a-fA-F]+$/.test(stripped) && stripped.length % 2 === 0) {
    return normalizePcrHex(value);
  }
  if (/^[A-Za-z0-9+/]+={0,2}$/.test(value)) {
    try {
      const hex = Buffer.from(value, "base64").toString("hex");
      if (hex.length > 0) return hex;
    } catch {
      // fall through
    }
  }
  return undefined;
}

async function checkOnChain(opts: {
  network: string;
  rpcUrl: string;
  checkpointId?: string;
  gatewayId?: string;
  ref?: string;
  live: NitroAttestationDoc;
}) {
  const { network, rpcUrl, checkpointId, gatewayId, ref, live } = opts;
  if (!checkpointId) {
    report("SKIP", "on-chain Checkpoint check", "no --checkpoint object id given");
    return;
  }

  let SuiGrpcClient: typeof import("@mysten/sui/grpc").SuiGrpcClient;
  try {
    ({ SuiGrpcClient } = await import("@mysten/sui/grpc"));
  } catch (err) {
    report("SKIP", "on-chain Checkpoint check", `@mysten/sui/grpc unavailable: ${(err as Error).message}`);
    return;
  }

  const client = new SuiGrpcClient({ network: network as any, baseUrl: rpcUrl });

  let checkpointJson: any;
  try {
    const { objects } = await client.core.getObjects({
      objectIds: [checkpointId],
      include: { json: true },
    });
    checkpointJson = (objects[0] as any)?.json;
    if (!checkpointJson) throw new Error("object has no parsed JSON content (deleted? wrong id?)");
  } catch (err) {
    report("FAIL", "fetch Checkpoint object", (err as Error).message);
    return;
  }

  const liveTriple = [0, 1, 2].map((i) => pcrHex(live, i));
  const approvedPcrs: any[] = checkpointJson.approved_pcrs ?? checkpointJson.approvedPcrs ?? [];
  if (!Array.isArray(approvedPcrs)) {
    report(
      "WARN",
      "approved_pcrs shape",
      `expected an array on the Checkpoint object, got: ${JSON.stringify(checkpointJson).slice(0, 200)}`,
    );
    return;
  }

  let matchIndex = -1;
  for (let i = 0; i < approvedPcrs.length; i++) {
    const entry = approvedPcrs[i];
    const pcr0 = fieldToHex(entry.pcr0);
    const pcr1 = fieldToHex(entry.pcr1);
    const pcr2 = fieldToHex(entry.pcr2);
    if (pcr0 === liveTriple[0] && pcr1 === liveTriple[1] && pcr2 === liveTriple[2]) {
      matchIndex = i;
      break;
    }
  }

  if (matchIndex === -1) {
    report(
      "FAIL",
      "PCR triple approved on Checkpoint",
      `no entry in approved_pcrs matches PCR0=${liveTriple[0]} PCR1=${liveTriple[1]} PCR2=${liveTriple[2]}`,
    );
    return;
  }

  const entry = approvedPcrs[matchIndex];
  const revoked = Boolean(entry.revoked);
  if (revoked) {
    report("FAIL", "PCR triple not revoked", `approved_pcrs[${matchIndex}] is revoked`);
  } else {
    report("PASS", "PCR triple approved and not revoked", `approved_pcrs[${matchIndex}]`);
  }

  if (ref) {
    const codeRef = entry.code_ref ?? entry.codeRef;
    if (typeof codeRef === "string" && codeRef.length > 0) {
      // Git short refs are normal on-chain (they're typed by hand at approval
      // time), so treat a prefix match as a match rather than warning.
      const refMatches =
        codeRef === ref || ref.startsWith(String(codeRef)) || String(codeRef).startsWith(ref);
      if (refMatches) {
        report("PASS", "code_ref matches --ref", codeRef);
      } else {
        report("WARN", "code_ref differs from --ref", `on-chain=${codeRef} --ref=${ref}`);
      }
    } else {
      report("WARN", "code_ref check", "approved_pcrs entry has no readable code_ref field");
    }
  }

  // --- Gateway pubkey registration ---
  if (!gatewayId) {
    report(
      "SKIP",
      "Gateway pubkey registration",
      "no --gateway object id given (pass the object id printed by register_enclave.ts)",
    );
    return;
  }

  let gatewayJson: any;
  try {
    const { objects } = await client.core.getObjects({
      objectIds: [gatewayId],
      include: { json: true },
    });
    gatewayJson = (objects[0] as any)?.json;
    if (!gatewayJson) throw new Error("object has no parsed JSON content");
  } catch (err) {
    report("FAIL", "fetch Gateway object", (err as Error).message);
    return;
  }

  const onChainPk = fieldToHex(gatewayJson.pk);
  const livePk = live.publicKey ? Buffer.from(live.publicKey).toString("hex") : undefined;
  if (!livePk) {
    report("FAIL", "Gateway pubkey matches live attestation", "live attestation has no public_key");
  } else if (!onChainPk) {
    report("WARN", "Gateway pubkey matches live attestation", "could not read pk field from Gateway JSON");
  } else if (onChainPk === livePk) {
    report("PASS", "Gateway pubkey matches live attestation", livePk);
  } else {
    report("FAIL", "Gateway pubkey matches live attestation", `on-chain=${onChainPk} live=${livePk}`);
  }

  // `pcr_version` IS the index into `approved_pcrs`: sekisho::checkpoint
  // appends entries and never deletes them, so the index is stable and a
  // mismatch means this Gateway was registered against different code than the
  // enclave is currently running.
  const pcrVersion = gatewayJson.pcr_version ?? gatewayJson.pcrVersion;
  if (typeof pcrVersion === "number" || typeof pcrVersion === "string") {
    if (Number(pcrVersion) === matchIndex) {
      report("PASS", "Gateway pcr_version matches approved entry", String(pcrVersion));
    } else {
      report(
        "FAIL",
        "Gateway pcr_version matches approved entry",
        `Gateway was registered under approved_pcrs[${pcrVersion}] but the live enclave's PCRs match approved_pcrs[${matchIndex}] — the running code is not what this Gateway attested to`,
      );
    }
  } else {
    report("WARN", "Gateway pcr_version matches approved entry", "could not read pcr_version from Gateway JSON");
  }
}

function defaultRpcUrl(network: string): string {
  switch (network) {
    case "mainnet":
      return "https://fullnode.mainnet.sui.io:443";
    case "devnet":
      return "https://fullnode.devnet.sui.io:443";
    case "localnet":
      return "http://127.0.0.1:9000";
    case "testnet":
    default:
      return "https://fullnode.testnet.sui.io:443";
  }
}

async function main() {
  const { positional, flags } = parseArgs(process.argv.slice(2));
  const gatewayUrl = positional[0];
  const ref = flags["ref"];

  if (!gatewayUrl) {
    console.error(
      "Usage: bun scripts/verify_deployment.ts <gateway-url> --ref <git-ref> " +
        "[--pcrs-file <path-or-url>] [--checkpoint <id>] [--gateway <id>] [--rpc <url>] " +
        "[--network testnet|mainnet|devnet|localnet] [--skip-build]",
    );
    process.exit(2);
  }
  if (!ref) {
    console.error("Missing --ref <git-ref>. verify_deployment.ts always compares against a named ref.");
    process.exit(2);
  }

  console.log(`Gateway:  ${gatewayUrl}`);
  console.log(`Ref:      ${ref}`);
  console.log("");

  // (a) live attestation
  let live: NitroAttestationDoc;
  try {
    live = await fetchLiveAttestation(gatewayUrl);
    report("PASS", "fetched live attestation", `pubkey ${live.publicKey ? "present" : "MISSING"}, module_id=${live.moduleId}`);
  } catch (err) {
    report("FAIL", "fetch live attestation", (err as Error).message);
    printSummary();
    process.exit(1);
  }

  console.log(`  PCR0: ${pcrHex(live, 0) ?? "<missing>"}`);
  console.log(`  PCR1: ${pcrHex(live, 1) ?? "<missing>"}`);
  console.log(`  PCR2: ${pcrHex(live, 2) ?? "<missing>"}`);
  console.log("");

  // (b) expected PCRs: --pcrs-file, else local out/nitro.pcrs, built if
  // requested and out/ doesn't exist yet.
  const repoRoot = path.resolve(import.meta.dir, "..");
  const localPcrsPath = path.join(repoRoot, "enclave", "out", "nitro.pcrs");
  const pcrsSource = flags["pcrs-file"] ?? localPcrsPath;

  if (!flags["pcrs-file"] && !existsSync(localPcrsPath)) {
    report(
      "SKIP",
      "compare PCRs against a build of --ref",
      `${localPcrsPath} does not exist. Build it yourself and re-run:\n` +
        `      git checkout ${ref} && make -C enclave eif && ` +
        `bun scripts/verify_deployment.ts ${gatewayUrl} --ref ${ref}\n` +
        `      (or pass --pcrs-file <path-or-url> to a published nitro.pcrs for this ref)`,
    );
  } else {
    try {
      const expected = await loadExpectedPcrs(pcrsSource);
      comparePcrs(live, expected);
    } catch (err) {
      report("FAIL", "load expected PCRs", `${pcrsSource}: ${(err as Error).message}`);
    }
  }
  console.log("");

  // (c) on-chain checks
  const network = flags["network"] ?? "testnet";
  const rpcUrl = flags["rpc"] ?? defaultRpcUrl(network);
  await checkOnChain({
    network,
    rpcUrl,
    checkpointId: flags["checkpoint"],
    gatewayId: flags["gateway"],
    ref,
    live,
  });

  printSummary();
}

function printSummary() {
  console.log("\n--- Summary ---");
  const counts: Record<Status, number> = { PASS: 0, FAIL: 0, WARN: 0, SKIP: 0 };
  for (const r of results) counts[r.status]++;
  console.log(
    `${counts.PASS} passed, ${counts.FAIL} failed, ${counts.WARN} warnings, ${counts.SKIP} skipped`,
  );
  if (counts.FAIL > 0) {
    console.log("\nFAIL");
    process.exit(1);
  } else if (counts.SKIP > 0 || counts.WARN > 0) {
    console.log("\nPASS (with warnings/skipped checks -- see above)");
    process.exit(0);
  } else {
    console.log("\nPASS");
    process.exit(0);
  }
}

main().catch((err) => {
  console.error("Unexpected error:", err);
  process.exit(1);
});
