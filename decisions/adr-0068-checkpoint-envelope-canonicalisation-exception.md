# ADR-0068: The checkpoint envelope keeps length-first canonical key order

**Status:** PROPOSED — records the key order every checkpoint already has,
which [ADR-0066](./adr-0066-sec-signed-checkpoint-size.md) D9 has since made
normative for the protected header, and names it as the one exception to
core deterministic encoding rather than leaving two normative statements in
conflict.
**Date:** 2026-09-19, revised 2026-09-20
**Related:** [rules/platform.md](../rules/platform.md) P16,
[spec/checkpoints-and-receipts.md](../spec/checkpoints-and-receipts.md) §1.3,
[ADR-0066](./adr-0066-sec-signed-checkpoint-size.md) D9,
[spec/delegation-and-webauthn-envelopes.md](../spec/delegation-and-webauthn-envelopes.md)
§5.1.

## Context

Rule P16 requires RFC 8949 §4.2 core deterministic encoding for every wire
format, on encode and on decode. The checkpoint envelope — the COSE Sign1 the
Go log library emits for every sealed massif — is encoded with the older
length-first canonical map key order (RFC 7049 §3.9: shorter key encodings
first, then bytewise). The certificate builders and the receipt exporters use
core deterministic order (bytewise only).

The two orders produce identical bytes while every map label is a single
byte. The checkpoint protected header carries multi-byte labels (`395` and
`-65933`), so the orders differ for it: length-first puts `1`, `395`, `-65933`
in that order, and the canonical header for ES256 at size 8 is
`a3012619018b033a0001018c08`. [ADR-0066](./adr-0066-sec-signed-checkpoint-size.md)
D9 specifies that header as deterministic CBOR with keys in canonical order,
and every verifier — the contract, the Go library and the TypeScript library
— enforces the length-first order for it, so it is no longer only an
observed property. The certificate maps have only single-byte labels, so
their order is the same under both rules.

Migrating the envelope to bytewise order would change the bytes of every
checkpoint the sealer emits and every checkpoint vector, for no observed
benefit.

## Decision

1. The **checkpoint envelope** is the one format for which length-first
   canonical key order is the specified encoding, as ADR-0066 D9 states for
   its protected header. Every other format uses core deterministic encoding.
2. A verifier of checkpoints MUST require the length-first order for the
   protected header (D9) and MUST NOT re-encode a checkpoint and expect byte
   identity with a bytewise-order encoder. Signature verification is over the
   bytes as received.
3. Any new checkpoint format version that changes the order will carry a new
   format identifier and new vectors; the current format keeps its bytes.
4. Rule P16 states the rule and the exception; the checkpoint document and
   ADR-0066 state the encoding.

## Consequences

- No wire change.
- The fact that two orders coexist stays recorded in
  [spec/implementation-status.md](../spec/implementation-status.md), because
  an encoder that re-encodes a checkpoint header in bytewise order produces a
  header every verifier rejects.
- Implementers of a new checkpoint encoder in another language must use
  length-first order for the protected header and core deterministic
  encoding for everything inside the envelope that is separately encoded
  (the consistency proof byte string, the peak receipts).
