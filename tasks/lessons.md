# Lessons

- **Naming (2026-08-13)**: One themed name per project (the repo name) is the budget. Internal
  concepts, types, modules, and docs use plain English (`Receipt`, `Checkpoint`, `Gateway`), not
  additional Japanese terms, and no kanji/etymology flourishes in docs. Correction from BL after
  `Tegata` was introduced for the receipt type.

- **Cross-language contracts need one pinned artifact, generated not hand-written.**
  `docs/receipt-v1-vectors.json` let Move, Rust, and TypeScript agree byte-for-byte without ever
  testing against each other. Verify the artifact itself with a *different* implementation than
  the one that produced it — cross-checking with Mysten's BCS caught that `u64::MAX` stored as a
  JSON number silently rounds up in any IEEE-754 parser.

- **Unit tests don't catch contract mismatches; run the real thing.** Every workstream was green
  and the first end-to-end run still failed twice: `receipt_id` was served as a dashed UUID while
  every sibling field was hex, and `/attestation` omitted the signing key. Both were invisible to
  tests written on one side of the boundary.

- **Check the claims in docstrings, not just the code.** The SDK documented that its hash helpers
  reproduce a receipt's `request_hash`. Testing it against a live gateway showed they don't — the
  enclave hashes a normalized internal form. A false docstring is worse than a missing one.

- **Optional request fields are policy bypasses.** A `max_tokens` cap that only checks requests
  which *specify* `max_tokens` is escapable by omitting the field, since absent means "model
  default" (unbounded). Treat absent-but-capped as a violation.

- **Verify what a measurement actually measures.** The spec claimed baked-in config was "covered
  by PCR2". The first real build showed PCR2 byte-identical across three unrelated projects —
  Nautilus passes a single `--ramdisk`, so `eif_build` records no application layer and PCR2 is a
  constant (and PCR0 collapses to equal PCR1). The binding is real but comes from PCR0. A security
  property attributed to the wrong mechanism reads as verified when it isn't.
