import { SekishoError } from './errors'
import type {
  AttestationResponse,
  ChatCompletionChunk,
  ChatCompletionRequest,
  ChatCompletionResponse,
  MessagesRequest,
  MessagesResponse,
  MessagesStreamEvent,
  ReceiptRecord,
  SekishoErrorResponse,
  SekishoResponse,
} from './types'

export interface SekishoClientOptions {
  url: string
  apiKey: string
  /** Custom `fetch` implementation (e.g. for testing or a service binding). */
  fetch?: typeof fetch
}

const RECEIPT_ID_HEADER = 'x-receipt-id'

/**
 * Parse a `text/event-stream` response body into an async iterator of the
 * JSON payload carried by each `data:` field. Both sekisho streaming surfaces
 * (OpenAI-compatible chat-completions deltas and Anthropic-native message
 * events) use standard SSE framing, so a single parser covers both.
 *
 * Stops on a literal `data: [DONE]` event (OpenAI convention) or when the
 * stream closes, whichever comes first.
 */
async function* parseSSE<T>(response: Response): AsyncGenerator<T, void, unknown> {
  if (!response.body) return
  const reader = response.body.getReader()
  const decoder = new TextDecoder()
  let buffer = ''
  try {
    while (true) {
      const { done, value } = await reader.read()
      if (value) buffer += decoder.decode(value, { stream: true })
      if (done) {
        buffer += decoder.decode()
      }

      let separatorIndex: number
      // SSE events are separated by a blank line (`\n\n`, or `\r\n\r\n`).
      while ((separatorIndex = buffer.indexOf('\n\n')) !== -1) {
        const rawEvent = buffer.slice(0, separatorIndex)
        buffer = buffer.slice(separatorIndex + 2)

        const dataLines = rawEvent
          .split('\n')
          .map((line) => line.replace(/\r$/, ''))
          .filter((line) => line.startsWith('data:'))
          .map((line) => line.slice(5).replace(/^ /, ''))

        if (dataLines.length === 0) continue
        const data = dataLines.join('\n')
        if (data === '[DONE]') return
        yield JSON.parse(data) as T
      }

      if (done) return
    }
  } finally {
    reader.releaseLock()
  }
}

export class SekishoClient {
  private readonly baseUrl: string
  private readonly apiKey: string
  private readonly fetch: typeof fetch

  constructor(options: SekishoClientOptions) {
    this.baseUrl = options.url.replace(/\/+$/, '')
    this.apiKey = options.apiKey
    this.fetch = options.fetch ?? globalThis.fetch
  }

  private headers(): Record<string, string> {
    return {
      Authorization: `Bearer ${this.apiKey}`,
      'Content-Type': 'application/json',
    }
  }

  private async errorFrom(res: Response): Promise<SekishoError> {
    let message = `Request failed with status ${res.status}`
    try {
      const body = (await res.json()) as SekishoErrorResponse
      if (body?.error) message = body.error
    } catch {
      // Non-JSON error body — fall back to the generic message above.
    }
    return new SekishoError(message, res.status)
  }

  /** OpenAI-compatible `POST /v1/chat/completions` (non-streaming). */
  async chat(
    request: ChatCompletionRequest & { stream?: false },
  ): Promise<SekishoResponse<ChatCompletionResponse>>
  /** OpenAI-compatible `POST /v1/chat/completions` (streaming). */
  async chat(
    request: ChatCompletionRequest & { stream: true },
  ): Promise<SekishoResponse<AsyncIterable<ChatCompletionChunk>>>
  async chat(
    request: ChatCompletionRequest,
  ): Promise<SekishoResponse<ChatCompletionResponse | AsyncIterable<ChatCompletionChunk>>> {
    const res = await this.fetch(`${this.baseUrl}/v1/chat/completions`, {
      method: 'POST',
      headers: this.headers(),
      body: JSON.stringify(request),
    })
    const receiptId = res.headers.get(RECEIPT_ID_HEADER)

    if (!res.ok) {
      throw await this.errorFrom(res)
    }

    if (request.stream) {
      return { data: parseSSE<ChatCompletionChunk>(res), receiptId }
    }

    const data = (await res.json()) as ChatCompletionResponse
    return { data, receiptId }
  }

  /** Anthropic-native `POST /v1/messages` passthrough (non-streaming). */
  async messages(
    request: MessagesRequest & { stream?: false },
  ): Promise<SekishoResponse<MessagesResponse>>
  /** Anthropic-native `POST /v1/messages` passthrough (streaming). */
  async messages(
    request: MessagesRequest & { stream: true },
  ): Promise<SekishoResponse<AsyncIterable<MessagesStreamEvent>>>
  async messages(
    request: MessagesRequest,
  ): Promise<SekishoResponse<MessagesResponse | AsyncIterable<MessagesStreamEvent>>> {
    const res = await this.fetch(`${this.baseUrl}/v1/messages`, {
      method: 'POST',
      headers: this.headers(),
      body: JSON.stringify(request),
    })
    const receiptId = res.headers.get(RECEIPT_ID_HEADER)

    if (!res.ok) {
      throw await this.errorFrom(res)
    }

    if (request.stream) {
      return { data: parseSSE<MessagesStreamEvent>(res), receiptId }
    }

    const data = (await res.json()) as MessagesResponse
    return { data, receiptId }
  }

  /** `GET /receipts/:id` — look up a previously issued receipt by id. */
  async getReceipt(id: string): Promise<ReceiptRecord> {
    const res = await this.fetch(`${this.baseUrl}/receipts/${encodeURIComponent(id)}`, {
      headers: { Authorization: `Bearer ${this.apiKey}` },
    })
    if (!res.ok) {
      throw await this.errorFrom(res)
    }
    return res.json() as Promise<ReceiptRecord>
  }

  /** `GET /attestation` — the enclave's current Nitro attestation document. */
  async getAttestation(): Promise<AttestationResponse> {
    const res = await this.fetch(`${this.baseUrl}/attestation`)
    if (!res.ok) {
      throw await this.errorFrom(res)
    }
    return res.json() as Promise<AttestationResponse>
  }
}
