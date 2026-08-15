import type { ClientWithCoreApi, SuiClientRegistration } from '@mysten/sui/client'
import { Transaction } from '@mysten/sui/transactions'
import { fromHex } from '@mysten/sui/utils'
import { SekishoClient } from './client'
import type { Receipt } from './receipt'

export interface SekishoExtensionOptions<Name extends string = 'sekisho'> {
  url: string
  apiKey: string
  /** Property name the client is registered under. Defaults to `'sekisho'`. */
  name?: Name
  /** Custom `fetch` implementation (e.g. for testing or a service binding). */
  fetch?: typeof fetch
}

/**
 * Register Sekisho as an extension on a Sui client, following the Mysten SDK
 * extension pattern:
 *
 * ```ts
 * const client = new SuiClient({ network: 'testnet' })
 *   .$extend(sekisho({ url: 'https://gateway.example.com', apiKey }))
 *
 * const { data, receiptId } = await client.sekisho.chat({ model, messages })
 * ```
 */
export function sekisho<const Name extends string = 'sekisho'>({
  name = 'sekisho' as Name,
  ...options
}: SekishoExtensionOptions<Name>): SuiClientRegistration<ClientWithCoreApi, Name, SekishoClient> {
  return {
    name,
    register: () => new SekishoClient(options),
  }
}

export interface BuildVerifyTransactionOptions {
  /** Existing transaction to append the call to. Defaults to a new `Transaction`. */
  transaction?: Transaction
  /** `sekisho` Move package id (configurable — differs per network/deployment). */
  packageId: string
  /** Shared `Gateway` object id the receipt was signed by. */
  gatewayId: string
  /** Shared `Checkpoint` object id (the PCR trust root) to verify the gateway's PCR version against. */
  checkpointId: string
  /** `IntentMessage.timestamp_ms` — must match what the enclave signed. */
  timestampMs: bigint | number
  receipt: Receipt
  /** Ed25519 signature over the BCS `IntentMessage<Receipt>`, hex-encoded. */
  signatureHex: string
}

/**
 * Build (or append to) a PTB that verifies a receipt onchain.
 *
 * `sekisho::receipt::verify` takes a `Receipt` **by value**, and a PTB cannot
 * construct a Move struct from pure arguments — so this chains two calls:
 * `new_receipt(...)` builds the struct (17 args, spec order — SPEC.md section 3),
 * and its result is passed to `verify(gateway, checkpoint, clock, timestamp_ms,
 * receipt, sig)`.
 *
 * `verify` returns a `VerifiedReceipt` (which has `drop`), so leaving the
 * result unused is valid. To act on the verified data, append further calls
 * consuming the returned value — this helper returns the transaction so a
 * caller can keep building.
 *
 * `packageId` is caller-supplied rather than hardcoded so the same helper
 * works against testnet/mainnet/local deployments.
 */
export function buildVerifyTransaction(options: BuildVerifyTransactionOptions): Transaction {
  const {
    transaction = new Transaction(),
    packageId,
    gatewayId,
    checkpointId,
    timestampMs,
    receipt,
    signatureHex,
  } = options

  // Passed on as the whole command result (a single `Receipt` return value),
  // not `result[0]` — indexing would produce a NestedResult referring to a
  // field of a multi-value return, which this function does not have.
  const receiptArg = transaction.moveCall({
    target: `${packageId}::receipt::new_receipt`,
    arguments: [
      transaction.pure.vector('u8', fromHex(receipt.receiptId)),
      transaction.pure.vector('u8', fromHex(receipt.configHash)),
      transaction.pure.u8(receipt.provider),
      transaction.pure.string(receipt.endpointHost),
      transaction.pure.vector('u8', fromHex(receipt.tlsCertSha256)),
      transaction.pure.u256(receipt.requestBlob),
      transaction.pure.u256(receipt.upstreamRequestBlob),
      transaction.pure.vector('u8', fromHex(receipt.upstreamHeadersHash)),
      transaction.pure.string(receipt.modelId),
      transaction.pure.string(receipt.providerRequestId),
      transaction.pure.u256(receipt.responseBlob),
      transaction.pure.vector('u8', fromHex(receipt.providerMetaHash)),
      transaction.pure.u64(receipt.inputTokens),
      transaction.pure.u64(receipt.cacheCreationTokens),
      transaction.pure.u64(receipt.cacheReadTokens),
      transaction.pure.u64(receipt.outputTokens),
      transaction.pure.u8(receipt.outcome),
    ],
  })

  transaction.moveCall({
    target: `${packageId}::receipt::verify`,
    arguments: [
      transaction.object(gatewayId),
      transaction.object(checkpointId),
      // Consensus time for the ReceiptVerified event, so the skew against the
      // enclave's self-reported timestamp is visible in the event itself.
      transaction.object.clock(),
      transaction.pure.u64(timestampMs),
      receiptArg,
      transaction.pure.vector('u8', fromHex(signatureHex)),
    ],
  })

  return transaction
}
