import { afterAll, beforeAll, describe, expect, test } from 'bun:test'
import { SekishoClient } from '../src/client'
import { SekishoError } from '../src/errors'
import type { ChatCompletionChunk, MessagesStreamEvent } from '../src/types'

// ─── Local Bun.serve mock gateway ───────────────────────────────────────────
//
// Exercises the SDK against a real HTTP server (real headers, real SSE
// framing over the wire) rather than a stubbed `fetch`, per the offline test
// requirement — no external network access, everything is loopback.

let server: ReturnType<typeof Bun.serve>
let baseUrl: string

const API_KEY = 'test-key'
const RECEIPT_ID = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'

function sseChunk(data: unknown): string {
  return `data: ${JSON.stringify(data)}\n\n`
}

beforeAll(() => {
  server = Bun.serve({
    port: 0,
    async fetch(req) {
      const url = new URL(req.url)
      const auth = req.headers.get('authorization')

      if (url.pathname === '/v1/chat/completions' && req.method === 'POST') {
        if (auth !== `Bearer ${API_KEY}`) {
          return Response.json({ error: 'Unauthorized' }, { status: 401 })
        }
        const body = (await req.json()) as { stream?: boolean; model: string }

        if (body.stream) {
          const stream = new ReadableStream<Uint8Array>({
            start(controller) {
              const encoder = new TextEncoder()
              const chunks: ChatCompletionChunk[] = [
                {
                  id: 'chatcmpl-1',
                  object: 'chat.completion.chunk',
                  created: 1,
                  model: body.model,
                  choices: [{ index: 0, delta: { role: 'assistant', content: 'Hel' } }],
                },
                {
                  id: 'chatcmpl-1',
                  object: 'chat.completion.chunk',
                  created: 1,
                  model: body.model,
                  choices: [{ index: 0, delta: { content: 'lo' }, finish_reason: 'stop' }],
                },
              ]
              for (const chunk of chunks) controller.enqueue(encoder.encode(sseChunk(chunk)))
              controller.enqueue(encoder.encode('data: [DONE]\n\n'))
              controller.close()
            },
          })
          return new Response(stream, {
            headers: {
              'content-type': 'text/event-stream',
              'x-receipt-id': RECEIPT_ID,
            },
          })
        }

        return Response.json(
          {
            id: 'chatcmpl-1',
            object: 'chat.completion',
            created: 1,
            model: body.model,
            choices: [
              { index: 0, message: { role: 'assistant', content: 'Hello' }, finish_reason: 'stop' },
            ],
            usage: { prompt_tokens: 5, completion_tokens: 1, total_tokens: 6 },
          },
          { headers: { 'x-receipt-id': RECEIPT_ID } },
        )
      }

      if (url.pathname === '/v1/messages' && req.method === 'POST') {
        if (auth !== `Bearer ${API_KEY}`) {
          return Response.json({ error: 'Unauthorized' }, { status: 401 })
        }
        const body = (await req.json()) as { stream?: boolean; model: string }

        if (body.stream) {
          const stream = new ReadableStream<Uint8Array>({
            start(controller) {
              const encoder = new TextEncoder()
              const events: MessagesStreamEvent[] = [
                { type: 'message_start', message: { id: 'msg-1', model: body.model } },
                { type: 'content_block_delta', delta: { type: 'text_delta', text: 'Hi' } },
                { type: 'message_stop' },
              ]
              for (const event of events) controller.enqueue(encoder.encode(sseChunk(event)))
              controller.close()
            },
          })
          return new Response(stream, {
            headers: {
              'content-type': 'text/event-stream',
              'x-receipt-id': RECEIPT_ID,
            },
          })
        }

        return Response.json(
          {
            id: 'msg-1',
            type: 'message',
            role: 'assistant',
            model: body.model,
            content: [{ type: 'text', text: 'Hi' }],
            stop_reason: 'end_turn',
            usage: { input_tokens: 3, output_tokens: 1 },
          },
          { headers: { 'x-receipt-id': RECEIPT_ID } },
        )
      }

      if (url.pathname.startsWith('/receipts/') && req.method === 'GET') {
        if (auth !== `Bearer ${API_KEY}`) {
          return Response.json({ error: 'Unauthorized' }, { status: 401 })
        }
        const id = url.pathname.split('/').pop()
        if (id !== RECEIPT_ID) {
          return Response.json({ error: 'Not found' }, { status: 404 })
        }
        return Response.json({
          receipt_id: RECEIPT_ID,
          timestamp_ms: '1234567890123',
          config_hash: 'aa'.repeat(32),
          provider: 0,
          endpoint_host: 'api.anthropic.com',
          tls_cert_sha256: 'bb'.repeat(32),
          request_blob: '12345',
          upstream_request_blob: '67890',
          upstream_headers_hash: 'cc'.repeat(32),
          model_id: 'claude-sonnet-5',
          provider_request_id: 'msg_011Ce3rq3tLXgrQNPLAYKda8',
          response_blob: '24680',
          provider_meta_hash: 'dd'.repeat(32),
          input_tokens: '1000',
          cache_creation_tokens: '0',
          cache_read_tokens: '0',
          output_tokens: '250',
          outcome: 0,
          signature: 'ff'.repeat(64),
        })
      }

      if (url.pathname === '/attestation' && req.method === 'GET') {
        return Response.json({ document: 'base64-cbor-document', public_key: 'ee'.repeat(32) })
      }

      return new Response('not found', { status: 404 })
    },
  })
  baseUrl = `http://localhost:${server.port}`
})

afterAll(() => {
  server.stop(true)
})

function client(): SekishoClient {
  return new SekishoClient({ url: baseUrl, apiKey: API_KEY })
}

// ─── chat() ──────────────────────────────────────────────────────────────────

describe('chat()', () => {
  test('non-streaming: returns data + receiptId from x-receipt-id header', async () => {
    const { data, receiptId } = await client().chat({
      model: 'claude-sonnet-5',
      messages: [{ role: 'user', content: 'hi' }],
    })

    expect(receiptId).toBe(RECEIPT_ID)
    expect(data.choices[0]?.message?.content).toBe('Hello')
  })

  test('streaming: async-iterates SSE chunks and exposes receiptId immediately', async () => {
    const { data, receiptId } = await client().chat({
      model: 'claude-sonnet-5',
      messages: [{ role: 'user', content: 'hi' }],
      stream: true,
    })

    // receiptId is available from the response headers before the stream is drained.
    expect(receiptId).toBe(RECEIPT_ID)

    const collected: ChatCompletionChunk[] = []
    for await (const chunk of data) collected.push(chunk)

    expect(collected).toHaveLength(2)
    expect(collected[0]?.choices[0]?.delta?.content).toBe('Hel')
    expect(collected[1]?.choices[0]?.delta?.content).toBe('lo')
    expect(collected[1]?.choices[0]?.finish_reason).toBe('stop')
  })

  test('throws SekishoError on non-2xx response', async () => {
    const badClient = new SekishoClient({ url: baseUrl, apiKey: 'wrong-key' })
    await expect(
      badClient.chat({ model: 'x', messages: [{ role: 'user', content: 'hi' }] }),
    ).rejects.toBeInstanceOf(SekishoError)
  })
})

// ─── messages() ──────────────────────────────────────────────────────────────

describe('messages()', () => {
  test('non-streaming: returns data + receiptId', async () => {
    const { data, receiptId } = await client().messages({
      model: 'claude-sonnet-5',
      max_tokens: 100,
      messages: [{ role: 'user', content: 'hi' }],
    })

    expect(receiptId).toBe(RECEIPT_ID)
    expect(data.content[0]).toEqual({ type: 'text', text: 'Hi' })
  })

  test('streaming: async-iterates SSE events', async () => {
    const { data, receiptId } = await client().messages({
      model: 'claude-sonnet-5',
      max_tokens: 100,
      messages: [{ role: 'user', content: 'hi' }],
      stream: true,
    })

    expect(receiptId).toBe(RECEIPT_ID)

    const collected: MessagesStreamEvent[] = []
    for await (const event of data) collected.push(event)

    expect(collected.map((e) => e.type)).toEqual([
      'message_start',
      'content_block_delta',
      'message_stop',
    ])
  })
})

// ─── getReceipt() ────────────────────────────────────────────────────────────

describe('getReceipt()', () => {
  test('fetches a receipt by id', async () => {
    const receipt = await client().getReceipt(RECEIPT_ID)
    expect(receipt.receipt_id).toBe(RECEIPT_ID)
    expect(receipt.input_tokens).toBe('1000')
  })

  test('throws SekishoError for an unknown id', async () => {
    await expect(client().getReceipt('does-not-exist')).rejects.toBeInstanceOf(SekishoError)
  })
})

// ─── getAttestation() ────────────────────────────────────────────────────────

describe('getAttestation()', () => {
  test('fetches the attestation document', async () => {
    const attestation = await client().getAttestation()
    expect(attestation.document).toBe('base64-cbor-document')
    expect(attestation.public_key).toBe('ee'.repeat(32))
  })
})

// ─── constructor ─────────────────────────────────────────────────────────────

describe('constructor', () => {
  test('strips trailing slashes from url', async () => {
    const c = new SekishoClient({ url: `${baseUrl}///`, apiKey: API_KEY })
    const attestation = await c.getAttestation()
    expect(attestation.document).toBe('base64-cbor-document')
  })
})
