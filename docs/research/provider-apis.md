# Provider API Surfaces for a Model-Routing Relay (August 2026)

Research brief for building a gateway/relay that sits in front of Anthropic, OpenAI-compatible, and OpenRouter-style backends and must (a) relay requests/streams faithfully and (b) produce a signed receipt of `(prompt hash, model id, response hash)`.

---

## 1. Anthropic Messages API

**Endpoint:** `POST https://api.anthropic.com/v1/messages`
Also: `POST /v1/messages/count_tokens` (token counting, no generation), `POST /v1/messages/batches` (async batch), `GET /v1/models`, `GET /v1/models/{id}`.

**Auth headers (mutually exclusive — sending both 401s):**
- API key: `x-api-key: <key>` + `anthropic-version: 2023-06-01`
- OAuth bearer (CLI / Claude Code style): `Authorization: Bearer <token>` + `anthropic-beta: oauth-2025-04-20` (OAuth tokens must **not** go on `x-api-key`)
- Beta features additionally require `anthropic-beta: <flag>` (comma-joinable, e.g. `fast-mode-2026-02-01,mid-conversation-tool-changes-2026-07-01`)

**Request shape (non-streaming):**
```json
{
  "model": "claude-opus-5",
  "max_tokens": 16000,
  "system": [{"type": "text", "text": "...", "cache_control": {"type": "ephemeral"}}],
  "messages": [
    {"role": "user", "content": [{"type": "text", "text": "..."}]},
    {"role": "assistant", "content": [{"type": "text", "text": "..."}]}
  ],
  "tools": [{"name": "...", "description": "...", "input_schema": {...}}],
  "tool_choice": {"type": "auto"},
  "thinking": {"type": "adaptive", "display": "summarized"},
  "output_config": {"effort": "high", "format": {...}},
  "stream": false
}
```
Content is block-based, not a flat string: `text`, `image`, `document`, `tool_use`, `tool_result`, `thinking`, `redacted_thinking`. Roles strictly alternate `user`/`assistant` (system is a top-level field, not a message role) — except on models that support **mid-conversation `role: "system"` messages** (Claude Opus 5, Opus 4.8, Fable 5, Mythos 5 — not Sonnet 5), which let an operator inject trusted instructions mid-conversation without touching the cached top-level `system` prefix.

**Response shape (non-streaming):**
```json
{
  "id": "msg_01...",
  "type": "message",
  "role": "assistant",
  "model": "claude-opus-5",
  "content": [{"type": "text", "text": "..."}],
  "stop_reason": "end_turn",
  "stop_details": null,
  "usage": {
    "input_tokens": 123,
    "output_tokens": 45,
    "cache_creation_input_tokens": 0,
    "cache_read_input_tokens": 0
  }
}
```
`stop_reason` ∈ `end_turn | max_tokens | stop_sequence | tool_use | pause_turn | refusal | model_context_window_exceeded`. `stop_details` is populated only when `stop_reason == "refusal"` (a policy decline — HTTP 200, not an error; content may be empty if declined pre-output, or partial if declined mid-stream, and partial output *is* billed).

**Streaming (SSE, `stream: true`):** fixed event sequence per turn —
1. `message_start` — full `Message` shell with empty `content`
2. Per content block: `content_block_start` → one or more `content_block_delta` → `content_block_stop`, each carrying an `index` matching the final `content[]` position
3. One or more `message_delta` — top-level changes (`stop_reason`, and **cumulative** `usage`)
4. `message_stop`

Delta types inside `content_block_delta`: `text_delta` (`{text}`), `input_json_delta` (`{partial_json}` — a **partial JSON string**, only safely parseable after `content_block_stop`, not per-delta), `thinking_delta` (`{thinking}`), `signature_delta` (thinking-block integrity signature, sent just before that block's `content_block_stop`; suppressed entirely — block still opens/closes but carries only the signature — when `display: "omitted"`). `ping` events may appear anywhere and carry no data. `error` events can appear mid-stream (e.g. `overloaded_error`, mapping to what would be HTTP 529 outside streaming). One SSE-specific wrinkle for a relay: during **server-side model fallback** (Claude Fable 5's `fallbacks` param), a `fallback` content block appears as a `content_block_start`/`content_block_stop` pair with no deltas, marking a model switch mid-response — a relay computing per-model billing must watch for this.

**No documented idempotency-key header** on `/v1/messages` — repeated identical requests are simply repeated generations (non-deterministic by default; there is no `temperature=0` guarantee of byte-identical output on 4.6+ models, since `temperature`/`top_p`/`top_k` are removed entirely on current models).

**Zero data retention / no-training:**
- Anthropic does **not** train on API data by default; ZDR is a separate, stronger guarantee (no retention at all beyond abuse-screening need).
- ZDR is an **organization-level commercial agreement**, obtained by contacting Anthropic sales — there is no per-request header or parameter to opt in.
- Once granted, it applies automatically to **all** traffic under that org's Commercial API key (including Claude Code via API); no request-time signal from the relay is needed or possible.
- One interaction to know: **Claude Fable 5 / Mythos 5 require a minimum 30-day retention window and are unavailable under ZDR** — a ZDR org routing to Fable 5 gets a hard `400 invalid_request_error` on every request, which a relay should detect and message clearly rather than retry.
- HIPAA-readiness is a separate, adjacent agreement (BAA), not implied by ZDR.

Sources: [Streaming messages](https://platform.claude.com/docs/en/build-with-claude/streaming), [API and data retention](https://platform.claude.com/docs/en/manage-claude/api-and-data-retention), [ZDR product coverage — Anthropic Privacy Center](https://privacy.claude.com/en/articles/8956058-i-have-a-zero-data-retention-agreement-with-anthropic-what-products-does-it-apply-to), [HTTP error codes](https://platform.claude.com/docs/en/api/errors).

---

## 2. OpenAI-compatible Chat Completions API

This shape is the de facto lingua franca — used natively by OpenAI, and re-implemented (with varying fidelity) by OpenRouter, DeepSeek, Groq, Together, vLLM, Ollama, and effectively every open-model host.

**Endpoint:** `POST https://api.openai.com/v1/chat/completions` (OpenAI); other hosts mirror the path, often at `/v1/chat/completions` on their own base URL.

**Auth:** `Authorization: Bearer <api-key>` (no separate version header, unlike Anthropic).

**Request shape:**
```json
{
  "model": "gpt-5.2",
  "messages": [
    {"role": "system", "content": "..."},
    {"role": "user", "content": "..."},
    {"role": "assistant", "content": "...", "tool_calls": [...]},
    {"role": "tool", "tool_call_id": "...", "content": "..."}
  ],
  "tools": [{"type": "function", "function": {"name": "...", "parameters": {...}}}],
  "stream": false,
  "stream_options": {"include_usage": true}
}
```
Flatter than Anthropic's: `role` is a real message field including `system`/`developer`/`tool`; content is usually a plain string but can be a content-part array for multimodal input; tool calls live on the `assistant` message as `tool_calls[]`, and tool results are separate `role: "tool"` messages keyed by `tool_call_id` (vs. Anthropic's `tool_result` content block inside a `user` message).

**Response shape (non-streaming):**
```json
{
  "id": "chatcmpl-...",
  "object": "chat.completion",
  "created": 1234567890,
  "model": "gpt-5.2",
  "choices": [
    {"index": 0, "message": {"role": "assistant", "content": "..."}, "finish_reason": "stop"}
  ],
  "usage": {"prompt_tokens": 123, "completion_tokens": 45, "total_tokens": 168}
}
```
`finish_reason` ∈ `stop | length | tool_calls | content_filter | function_call (deprecated)` — note there is no direct analog to Anthropic's `refusal` stop reason; a policy decline surfaces as `content_filter` or as ordinary refusal *text* in `content`, which is a meaningfully different signal shape a relay's receipt logic needs to branch on separately per provider.

**Streaming (SSE):** each chunk is `object: "chat.completion.chunk"`, sharing one `id` across the whole stream, with a `choices[].delta` object (`content`, `role`, `refusal`, `tool_calls[]`, `function_call` deprecated) instead of a full message. Tool calls stream incrementally per-`index` inside `delta.tool_calls[]`, each element carrying partial `function.name`/`function.arguments` strings that must be concatenated per-index and JSON-parsed only once complete — structurally analogous to Anthropic's `input_json_delta`, but embedded directly in the delta rather than as a separate block type. **Usage is only present when the client explicitly opts in** via `stream_options: {"include_usage": true}`; it then arrives in a final chunk whose `choices` array is empty. The stream is terminated by a literal SSE line `data: [DONE]` (not a typed event, unlike Anthropic's `message_stop`) — a relay's parser must special-case this sentinel since it isn't valid JSON.

**Zero data retention / no-training:**
- No training on API data by default since March 2023 (opt-in only).
- ZDR (or the lighter "Modified Abuse Monitoring") is an **approved, negotiated enterprise control**, configured org-wide or per-project in the dashboard (Settings → Organization → Data controls) — again no per-request header.
- Enabling ZDR at the org/project level **forces the `store` parameter to `false` server-side even if a request sets `store: true`** — a relay that lets clients pass `store` through must be aware this can silently no-op under ZDR.
- Coverage is uneven across surfaces: **stateful features (Assistants, Threads, Vector Stores) are ZDR-ineligible** and retain state until manually deleted regardless of the org setting — a relay only proxying Chat Completions is unaffected, but a relay that also proxies stateful endpoints needs to flag this gap explicitly.

Sources: [Chat Completions streaming events reference](https://developers.openai.com/api/reference/resources/chat/subresources/completions/streaming-events), [Streaming API responses guide](https://developers.openai.com/api/docs/guides/streaming-responses), [Data controls in the OpenAI platform](https://developers.openai.com/api/docs/guides/your-data).

---

## 3. OpenRouter specifics

OpenRouter is a superset of the OpenAI Chat Completions shape (`POST https://openrouter.ai/api/v1/chat/completions`, `Authorization: Bearer <key>`), extended with routing/provider controls and its own usage/cost metadata.

**Model routing:**
- `model` is a vendor-prefixed slug, e.g. `anthropic/claude-sonnet-4.6`, `openai/gpt-5.2` — the vendor prefix disambiguates identically-named open models across hosts.
- `models: [...]` (plural) accepts an **ordered fallback list of model slugs** — if the primary errs or is unavailable, OpenRouter retries the next model in the list, which is a materially different failure mode than a single-model gateway (the *model actually served* can differ from the one requested, so a relay must always read the served `model` back off the response, never assume it equals the request).
- Shortcut suffixes on the slug: `:nitro` sorts by throughput, `:floor` sorts by price.

**Provider preferences** (`provider: {...}` object on the request):

| Field | Purpose |
|---|---|
| `order` | Explicit provider-slug attempt order (e.g. `["anthropic", "openai"]`) |
| `allow_fallbacks` (default `true`) | Whether to fall back off the preferred provider list at all |
| `ignore` | Provider slugs to exclude entirely |
| `require_parameters` (default `false`) | Only route to providers supporting every parameter in the request |
| `quantizations` | Filter open-model backends by quant level (`int4`, `fp8`, `bf16`, …) |
| `sort` | `price` \| `throughput` \| `latency` — overrides default load-balancing |
| `preferred_min_throughput` / `preferred_max_latency` / `max_price` | Soft/hard performance and cost constraints |
| `data_collection` | `"allow"` (default) \| `"deny"` — deny excludes any provider that stores request data at all |
| `zdr` | Per-request Zero Data Retention flag — routes **only** to endpoints with a ZDR policy |

**Pass-through auth (BYOK):** OpenRouter supports Bring-Your-Own-Key, where the relay's own upstream provider credentials are used instead of OpenRouter's pooled capacity; the response includes an `is_byok` field so the caller can confirm which credential path served the request — directly relevant if a gateway needs to attribute cost/billing correctly per tenant.

**Privacy/logging semantics, layered:**
- OpenRouter itself does not train on traffic and does not log prompts/completions by default (opt-in prompt logging only).
- `data_collection: "deny"` restricts routing to upstream providers that themselves don't retain/train on data.
- `zdr: true` is the strictest: only routes to endpoints with a documented zero-retention policy. **It composes with an account-wide ZDR default via OR** — either the per-request flag or the account setting being true is sufficient to enforce it; `zdr: false`/omitted defers entirely to the account default rather than disabling it.

**Usage/cost reporting:** every response's `usage` object carries the standard OpenAI-shape `prompt_tokens`/`completion_tokens`/`total_tokens`, plus OpenRouter-specific `prompt_tokens_details.cached_tokens` and `.cache_write_tokens`, and a `cache_discount` figure — notably **negative** for some providers' cache writes (a real added cost) and positive for cache reads (a real discount), which a relay computing a receipt's cost/usage fields needs to sum correctly rather than assume is always a discount. Full generation metadata (including final routed provider) is also queryable after the fact via `GET /api/v1/generation`.

**Reliability/session semantics relevant to a relay:** "sticky" provider sessions (for cache continuity) expire after 10 minutes of inactivity, reset by each successful request; if the sticky provider errors, OpenRouter reroutes automatically **and the cache is not updated**, so a client relying on prompt-cache economics across a conversation can silently lose the cache mid-session on provider failover. No documented idempotency-key mechanism.

Sources: [Provider Routing](https://openrouter.ai/docs/docs/routing/provider-selection), [Prompt Caching](https://openrouter.ai/docs/features/prompt-caching), [OpenRouter Privacy Policy](https://openrouter.ai/privacy).

---

## 4. Design implications for a relay producing signed receipts

**Target receipt: `sign(prompt_hash, model_id, response_hash, [usage, timestamp, provider_request_id])`.**

### Canonical request hashing
- **Hash a normalized intermediate representation, not raw request bytes.** Wire bytes vary by client SDK (key ordering, whitespace, which optional fields are explicitly `null` vs. omitted) even for semantically identical requests, and the same logical prompt can arrive in Anthropic-block-shape or OpenAI-flat-shape depending on which client-facing surface the caller used (see §5). Canonicalize to one internal schema first (sorted keys, stable content-block ordering, deterministic JSON serialization — e.g. RFC 8785 JCS or an equivalent fixed canonicalizer), *then* hash that.
- **Decide, and document, exactly what's in-scope for the hash.** At minimum: `model` (post-alias-resolution — resolve `"claude-opus-5"` and any dated/aliased equivalent to the same canonical ID before hashing, or routing metadata pollutes the prompt hash), the full message/content-block sequence, `system`/developer instructions, `tools` definitions (schema changes are prompt changes), and generation-affecting params (`temperature`, `effort`, `thinking` mode) if determinism claims depend on them. **Exclude** provider-assigned or per-request-random fields that don't affect output: request IDs, `stream` (transport choice, not content), auth headers, retry counters.
- **Tool definitions and system prompts are part of the prompt for hashing purposes** — a relay that mid-conversation swaps tools (Anthropic's beta `mid-conversation-tool-changes-2026-07-01`, or a naive re-send with a different `tools[]`) is issuing a materially different request each time; the receipt must reflect the tool set actually in effect for that turn, not just the user-visible text.

### Canonical response hashing — streamed vs. final
- **Hash the final assembled message, never the raw SSE byte stream.** Chunk boundaries are explicitly not a content guarantee on either provider: Anthropic's docs state input-JSON deltas may arrive in arbitrarily granular pieces "so that the format can automatically support finer granularity in future models," and OpenAI's `delta.content` chunking is unspecified and host-dependent (a self-hosted vLLM backend will chunk differently from OpenAI's own servers for byte-identical output). Two semantically identical responses can produce different SSE framings, which would break a hash keyed to the wire stream.
- **Concrete algorithm:** accumulate content blocks/deltas in order (Anthropic: concatenate `text_delta`s within a block by index, parse `input_json_delta` only after `content_block_stop`; OpenAI: concatenate `delta.content` and `delta.tool_calls[].function.arguments` per index) into the same canonical structure used for the non-streaming response shape, **then** hash that assembled object — including `stop_reason`/`finish_reason` and tool-call structure, not just visible text, since two responses with identical text but different tool calls are not the same response.
- **Thinking/reasoning content is a hashing decision point.** Anthropic's `thinking` blocks are billed and real, but the visible text is often empty (`display: "omitted"`) with only a `signature_delta` for integrity — decide up front whether the receipt's response hash covers thinking content (available when `display: "summarized"`) or only the model's final answer; be consistent, and document the choice, since it changes what the signature actually attests to.
- **Server-side fallback (Anthropic) and multi-model routing (OpenRouter `models[]`) both mean the model that produced the response may differ mid-stream from the one requested.** The receipt's `model_id` must be read from the response (Anthropic: track `fallback` content-block boundaries and the final `message.model`; OpenRouter: the response's `model` field, and optionally `is_byok`/provider from `/v1/generation`), never assumed from the request.

### Usage/token reporting
- **Anthropic:** `usage` in `message_delta` events is **cumulative**, not incremental — summing per-event usage double-counts; take the value from the terminal `message_delta`/final `message_stop`-adjacent state only.
- **OpenAI-compatible:** usage is opt-in per streaming request (`stream_options.include_usage`) and arrives once, in a final chunk with an empty `choices[]` — a relay must request it explicitly on every streamed call if the receipt needs token counts, and must not assume it's present by default.
- **OpenRouter:** usage additionally carries `cached_tokens`/`cache_write_tokens` and a `cache_discount` that can be *negative* (added cost on cache writes) — a receipt that reports "cost" needs to net this correctly rather than assume caching always saves money.

### Idempotency
- **Neither Anthropic's Messages API nor the OpenAI Chat Completions shape document a provider-side idempotency-key mechanism** (unlike, e.g., Stripe-style payment APIs). Retrying an identical request is just a new generation — with no sampling determinism guaranteed (Anthropic has removed `temperature`/`top_p`/`top_k` entirely on current models; even where present elsewhere, `temperature=0` has never been a byte-identical-output guarantee).
- **Implication for the relay:** idempotency has to be the relay's own responsibility, keyed off (canonical prompt hash + model + a client-supplied nonce/idempotency token), with an explicit policy for what "duplicate" means (identical canonical request within a time window → return the cached receipt and prior response, vs. always re-execute). Don't conflate this with the *provider's* request ID, which only identifies one execution attempt, not a semantic prompt.

### Error semantics worth relaying (normalize, don't just pass through)
| Category | Anthropic | OpenAI-shape | Relay handling |
|---|---|---|---|
| Malformed request | `400 invalid_request_error` | `400` | Non-retryable; surface validation detail |
| Auth | `401 authentication_error` | `401` | Non-retryable; never retry with same key |
| Permission/plan | `403 permission_error` | `403` | Non-retryable |
| Not found (bad model ID) | `404 not_found_error` | `404` | Non-retryable; likely a routing config bug |
| Payload too large | `413 request_too_large` | `413` | Non-retryable; needs client-side chunking |
| Rate limited | `429 rate_limit_error` (retryable, honor `retry-after`) | `429` | Retryable with backoff; distinct rate pools per model/tier |
| Server error | `500 api_error` (retryable) | `500` | Retryable with backoff |
| Overloaded | `529 overloaded_error` (retryable) | usually `503` | Retryable, treat as a distinct "capacity" signal from `500` |
| Content-policy decline | `stop_reason: "refusal"` — **HTTP 200**, not an error | `finish_reason: "content_filter"` or refusal text in content — also HTTP 200 | **Not an error at all** — must still be receipted (tokens may be billed on a mid-stream decline) but flagged distinctly from a successful completion; the two providers signal this so differently (typed field vs. content-filter finish reason vs. plain refusal text) that a relay needs a per-provider adapter just for this one case |

A relay's normalized error taxonomy should have at least: `invalid_request` (client bug, never retry), `auth`/`permission` (config bug, never retry), `rate_limited`/`overloaded` (retry with backoff, provider-attributable), `server_error` (retry, provider-attributable), and `declined` (not an error — a successful call the model chose not to fully answer, still receipted). Collapsing "declined" into "error" is the most common design mistake here, since it's the one case both providers return with a `200`.

---

## 5. Recommended unified request abstraction

**What comparable gateways expose:**

| Gateway | Primary client-facing surface | Native passthrough? |
|---|---|---|
| **OpenRouter** | OpenAI-compatible only (`/api/v1/chat/completions`), extended with a `provider{}` object and `models[]` fallback array as additive fields | No — everything (including Anthropic-backed models) is translated to/from the OpenAI shape; no `/v1/messages`-equivalent |
| **LiteLLM** (proxy) | OpenAI-compatible (`/v1/chat/completions`) as the default/universal surface | **Yes** — also exposes a native `/v1/messages` endpoint that passes Anthropic-shape requests through with minimal translation, so the official Anthropic SDK can point its `base_url` straight at the LiteLLM proxy and keep using Anthropic-native features (content blocks, `cache_control`, thinking blocks) losslessly |

**Recommendation: expose both, but with an explicit primary/secondary relationship — not two independent schemas.**

1. **Primary surface: OpenAI-compatible `/v1/chat/completions`.** This is the correct default because it's the path of least resistance for the overwhelming majority of clients — every agent framework (LangChain, LlamaIndex, the AI SDK), every eval harness, and most internal tooling already speaks it, and it's what OpenRouter, DeepSeek, and most open-model hosts use natively, so requests destined for those backends need zero translation on the way in. Making this the default also means the gateway's own routing/provider-preference extensions (à la OpenRouter's `provider{}` object) can be added as additive fields without breaking strict OpenAI clients that ignore unknown keys.

2. **Secondary surface: native Anthropic passthrough at `/v1/messages`.** Justification: translating Anthropic-shape requests into OpenAI shape and back is lossy in both directions — thinking blocks, `cache_control` breakpoints, `stop_details.category` on refusals, and multi-block tool-result structures don't have clean OpenAI equivalents, and round-tripping them loses information a downstream Anthropic-native client (including Claude Code / the Anthropic SDK itself, per LiteLLM's own design choice) would need back intact. Offering this as a thin, mostly-passthrough endpoint (not a second reimplementation of the whole feature set) keeps the maintenance burden bounded to "proxy + receipt-signing," not "maintain two full translation layers."

3. **Do not invent a third bespoke request schema.** Neither OpenRouter nor LiteLLM does this, and for good reason: a novel schema forces every client to write a gateway-specific adapter with zero ecosystem reuse, for no benefit over reusing one of the two formats the entire industry already standardized on.

4. **Internally, canonicalize to one intermediate representation regardless of which surface the request arrived on** — this is also what makes §4's hashing scheme work cleanly: the prompt/response hash is computed against the canonical internal form, not against either wire shape, so a receipt is identical whether the caller used the OpenAI-shape endpoint or the Anthropic-native one for the same logical request. This is the architectural reason to prefer "OpenAI-compatible primary + Anthropic-native passthrough, both translated to one internal canonical form" over "OpenAI-only" (loses Anthropic-native fidelity for receipt purposes) or "Anthropic-only" (fails the compatibility goal with the rest of the ecosystem).

Sources: [OpenRouter Provider Routing](https://openrouter.ai/docs/docs/routing/provider-selection), [LiteLLM /v1/messages (Anthropic-format passthrough)](https://docs.litellm.ai/docs/anthropic_unified/), [LiteLLM Getting Started](https://docs.litellm.ai/docs/), [BerriAI/litellm on GitHub](https://github.com/BerriAI/litellm).
