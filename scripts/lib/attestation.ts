/**
 * Minimal CBOR decoder + AWS Nitro attestation document parser.
 *
 * Deliberately self-contained (no external CBOR dependency): this parses
 * bytes returned by a gateway we're trying to *verify*, i.e. untrusted input,
 * for a security-sensitive comparison. Keeping the decode surface small and
 * auditable in one file matters more here than generality or spec coverage.
 *
 * This does NOT verify the COSE_Sign1 signature or the AWS Nitro certificate
 * chain -- that trust decision belongs to `sui::nitro_attestation::load_nitro_attestation`
 * on-chain at registration time (see docs/research/nautilus.md sec 3). This
 * module only decodes the CBOR structure to read out PCR values and the
 * embedded public key for local, offline comparison
 * (scripts/verify_deployment.ts) or a sanity check before submitting a PTB
 * (scripts/register_enclave.ts).
 *
 * Wire shape (AWS Nitro attestation document):
 *   COSE_Sign1 = [protected: bstr, unprotected: map, payload: bstr, signature: bstr]
 *   payload (CBOR-decoded) = {
 *     module_id, timestamp, digest, pcrs: {uint => bstr(48)},
 *     certificate, cabundle, public_key, user_data, nonce
 *   }
 * The top-level array may or may not carry a CBOR tag(18) wrapper depending
 * on producer; both are accepted.
 */

export type CborValue =
  | number
  | Uint8Array
  | string
  | boolean
  | null
  | CborValue[]
  | Map<CborValue, CborValue>
  | { tag: number; value: CborValue };

class CborReader {
  pos = 0;
  constructor(private buf: Uint8Array) {}

  private byte(): number {
    if (this.pos >= this.buf.length) throw new Error("cbor: unexpected end of input");
    return this.buf[this.pos++];
  }

  private bytes(n: number): Uint8Array {
    if (this.pos + n > this.buf.length) throw new Error("cbor: unexpected end of input");
    const out = this.buf.subarray(this.pos, this.pos + n);
    this.pos += n;
    return out;
  }

  private readLength(additional: number): number {
    if (additional < 24) return additional;
    if (additional === 24) return this.byte();
    if (additional === 25) {
      const b = this.bytes(2);
      return (b[0] << 8) | b[1];
    }
    if (additional === 26) {
      const b = this.bytes(4);
      return ((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]) >>> 0;
    }
    if (additional === 27) {
      const b = this.bytes(8);
      let n = 0n;
      for (const byte of b) n = (n << 8n) | BigInt(byte);
      if (n > BigInt(Number.MAX_SAFE_INTEGER)) {
        throw new Error("cbor: length exceeds Number.MAX_SAFE_INTEGER");
      }
      return Number(n);
    }
    throw new Error(`cbor: unsupported length encoding (additional=${additional})`);
  }

  decode(): CborValue {
    const first = this.byte();
    const major = first >> 5;
    const additional = first & 0x1f;

    switch (major) {
      case 0: // unsigned int
        return this.readLength(additional);
      case 1: // negative int
        return -1 - this.readLength(additional);
      case 2: // byte string
        if (additional === 31) throw new Error("cbor: indefinite byte strings unsupported");
        return this.bytes(this.readLength(additional));
      case 3: // text string
        if (additional === 31) throw new Error("cbor: indefinite text strings unsupported");
        return new TextDecoder().decode(this.bytes(this.readLength(additional)));
      case 4: {
        // array
        if (additional === 31) throw new Error("cbor: indefinite arrays unsupported");
        const len = this.readLength(additional);
        const arr: CborValue[] = [];
        for (let i = 0; i < len; i++) arr.push(this.decode());
        return arr;
      }
      case 5: {
        // map
        if (additional === 31) throw new Error("cbor: indefinite maps unsupported");
        const len = this.readLength(additional);
        const map = new Map<CborValue, CborValue>();
        for (let i = 0; i < len; i++) {
          const k = this.decode();
          const v = this.decode();
          map.set(k, v);
        }
        return map;
      }
      case 6: {
        // tag
        const tag = this.readLength(additional);
        return { tag, value: this.decode() };
      }
      case 7: {
        // simple / float
        if (additional === 20) return false;
        if (additional === 21) return true;
        if (additional === 22) return null; // null
        if (additional === 23) return null; // undefined
        if (additional === 25) {
          this.bytes(2);
          return null; // half float, unused in attestation docs
        }
        if (additional === 26) {
          this.bytes(4);
          return null; // float
        }
        if (additional === 27) {
          this.bytes(8);
          return null; // double
        }
        throw new Error(`cbor: unsupported simple value (additional=${additional})`);
      }
      default:
        throw new Error(`cbor: unsupported major type ${major}`);
    }
  }
}

export function decodeCbor(bytes: Uint8Array): CborValue {
  return new CborReader(bytes).decode();
}

export interface NitroAttestationDoc {
  moduleId: string;
  timestampMs: number;
  digest: string;
  /** PCR index -> raw bytes (48 bytes for SHA384-measured PCRs). */
  pcrs: Map<number, Uint8Array>;
  publicKey: Uint8Array | null;
  userData: Uint8Array | null;
  nonce: Uint8Array | null;
}

function bytesToHex(b: Uint8Array): string {
  return Buffer.from(b).toString("hex");
}

/** Parses a hex-encoded attestation document (as returned by GET/POST /attestation). */
export function parseAttestationDocument(hex: string): NitroAttestationDoc {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  const raw = new Uint8Array(Buffer.from(clean, "hex"));

  let top = decodeCbor(raw);
  if (typeof top === "object" && top !== null && "tag" in top) {
    top = (top as { tag: number; value: CborValue }).value;
  }
  if (!Array.isArray(top) || top.length !== 4) {
    throw new Error("attestation: expected a 4-element COSE_Sign1 array");
  }

  const payloadBytes = top[2];
  if (!(payloadBytes instanceof Uint8Array)) {
    throw new Error("attestation: COSE_Sign1 payload is not a byte string");
  }

  const doc = decodeCbor(payloadBytes);
  if (!(doc instanceof Map)) throw new Error("attestation: payload is not a CBOR map");

  const pcrsRaw = doc.get("pcrs");
  if (!(pcrsRaw instanceof Map)) throw new Error("attestation: missing/invalid 'pcrs' map");
  const pcrs = new Map<number, Uint8Array>();
  for (const [k, v] of pcrsRaw) {
    if (typeof k === "number" && v instanceof Uint8Array) pcrs.set(k, v);
  }

  const moduleIdRaw = doc.get("module_id");
  const digestRaw = doc.get("digest");
  const publicKeyRaw = doc.get("public_key");
  const userDataRaw = doc.get("user_data");
  const nonceRaw = doc.get("nonce");
  const timestampRaw = doc.get("timestamp");

  return {
    moduleId:
      moduleIdRaw instanceof Uint8Array
        ? Buffer.from(moduleIdRaw).toString("utf-8")
        : String(moduleIdRaw ?? ""),
    timestampMs: typeof timestampRaw === "number" ? timestampRaw : 0,
    digest: digestRaw instanceof Uint8Array ? bytesToHex(digestRaw) : String(digestRaw ?? ""),
    pcrs,
    publicKey: publicKeyRaw instanceof Uint8Array ? publicKeyRaw : null,
    userData: userDataRaw instanceof Uint8Array ? userDataRaw : null,
    nonce: nonceRaw instanceof Uint8Array ? nonceRaw : null,
  };
}

/** Convenience: hex string for PCR N, or undefined if absent from the document. */
export function pcrHex(doc: NitroAttestationDoc, index: number): string | undefined {
  const v = doc.pcrs.get(index);
  return v ? bytesToHex(v) : undefined;
}
