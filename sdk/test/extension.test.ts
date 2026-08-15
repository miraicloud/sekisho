import { describe, expect, test } from 'bun:test'
import { Transaction } from '@mysten/sui/transactions'
import { buildVerifyTransaction, sekisho } from '../src/extension'
import type { ReceiptV1 } from '../src/receipt'
import { ReceiptOutcome } from '../src/receipt'

// Offline: inspects `Transaction.getData()` directly rather than calling
// `build()`, which would require a client to resolve object references over
// the network. Mirrors the "hand-construct minimal valid inputs, zero
// network calls" pattern used by @unconfirmed/onara's own test suite.

const PACKAGE_ID = `0x${'1'.repeat(64)}`
const GATEWAY_ID = `0x${'2'.repeat(64)}`
const CHECKPOINT_ID = `0x${'3'.repeat(64)}`

const receipt: ReceiptV1 = {
  receiptId: '00'.repeat(16),
  configHash: 'aa'.repeat(32),
  requestHash: 'bb'.repeat(32),
  upstreamRequestHash: 'cc'.repeat(32),
  modelId: 'claude-sonnet-5',
  responseHash: 'dd'.repeat(32),
  inputTokens: 1000n,
  outputTokens: 250n,
  outcome: ReceiptOutcome.Ok,
}

describe('buildVerifyTransaction', () => {
  // `receipt::verify` takes a ReceiptV1 by value and a PTB cannot build a Move
  // struct from pure args, so the helper must chain new_receipt_v1 -> verify
  // and pass the constructor's Result. Asserting the shape here is what keeps
  // this helper honest against move/sources/receipt.move.
  test('chains new_receipt_v1 into verify, passing the struct as a Result', () => {
    const tx = buildVerifyTransaction({
      packageId: PACKAGE_ID,
      gatewayId: GATEWAY_ID,
      checkpointId: CHECKPOINT_ID,
      timestampMs: 1234567890123n,
      receipt,
      signatureHex: 'ff'.repeat(64),
    })

    const data = tx.getData() as {
      commands: Array<{
        $kind: string
        MoveCall?: {
          package: string
          module: string
          function: string
          arguments: Array<{ $kind: string }>
        }
      }>
    }

    const moveCalls = data.commands.filter((c) => c.$kind === 'MoveCall')
    expect(moveCalls).toHaveLength(2)

    const ctor = moveCalls[0]!.MoveCall!
    expect(ctor.package).toBe(PACKAGE_ID)
    expect(ctor.module).toBe('receipt')
    expect(ctor.function).toBe('new_receipt_v1')
    expect(ctor.arguments).toHaveLength(9)

    const call = moveCalls[1]!.MoveCall!
    expect(call.package).toBe(PACKAGE_ID)
    expect(call.module).toBe('receipt')
    expect(call.function).toBe('verify')
    // gateway, checkpoint, clock, timestamp_ms, receipt (Result), sig
    expect(call.arguments).toHaveLength(6)
    expect(call.arguments[4]!.$kind).toBe('Result')
  })

  test('appends to an existing transaction when provided', () => {
    const existing = new Transaction()
    const tx = buildVerifyTransaction({
      transaction: existing,
      packageId: PACKAGE_ID,
      gatewayId: GATEWAY_ID,
      checkpointId: CHECKPOINT_ID,
      timestampMs: 1n,
      receipt,
      signatureHex: 'ff'.repeat(64),
    })

    expect(tx).toBe(existing)
  })
})

describe('sekisho() extension', () => {
  test('returns a SuiClientRegistration with the default name', () => {
    const registration = sekisho({ url: 'https://gateway.example.com', apiKey: 'k' })
    expect(registration.name).toBe('sekisho')
    expect(typeof registration.register).toBe('function')
  })

  test('honors a custom registration name', () => {
    const registration = sekisho({ url: 'https://gateway.example.com', apiKey: 'k', name: 'myGateway' })
    expect(registration.name).toBe('myGateway')
  })

  test('register() produces a SekishoClient', () => {
    const registration = sekisho({ url: 'https://gateway.example.com', apiKey: 'k' })
    const client = registration.register({} as never)
    expect(client.constructor.name).toBe('SekishoClient')
  })
})
