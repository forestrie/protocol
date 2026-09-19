# ADR-0067: The checkpoint envelope keeps length-first canonical ordering

**Status:** PROPOSED — records the encoding every checkpoint on every deployed
log already has, and names it as the one exception to core deterministic
encoding rather than leaving two normative statements in conflict.
**Date:** 2026-09-19
**Related:** [rules/platform.md](../rules/platform.md) P16,
[spec/checkpoints-and-receipts.md](../spec/checkpoints-and-receipts.md) §1,
[spec/delegation-and-webauthn-envelopes.md](../spec/delegation-and-webauthn-envelopes.md)
§5.1.

## Context

Rule P16 requires RFC 8949 §4.2 core deterministic encoding for every wire
format, on encode and on decode. The checkpoint envelope — the COSE Sign1 the
Go log library emits for every sealed massif — is encoded with the older
length-first canonical map ordering (RFC 7049 §3.9). The certificate builders
and the receipt exporters use core deterministic ordering.

The two orderings produce identical bytes while every map label is a single
byte. The checkpoint envelope carries multi-byte labels (`395`, `396`, and the
private-use labels), so the orderings can differ for it; no divergence has
been observed, because the contract rebuilds the signed bytes from pre-decoded
parts rather than re-encoding the envelope, and off-chain verifiers verify the
bytes they are given.

Migrating the envelope to core deterministic ordering would change the bytes
of every checkpoint the sealer emits and break the frozen burial vectors, for a
divergence that has never been observed.

## Decision

1. The **checkpoint envelope** is the one format for which length-first
   canonical ordering is the specified encoding. Every other format uses core
   deterministic encoding.
2. A verifier of checkpoints MUST accept the length-first order and MUST NOT
   re-encode a checkpoint and expect byte identity with a core deterministic
   encoder. Signature verification is over the bytes as received.
3. Any new checkpoint format version that changes the ordering will carry a
   new format identifier and new vectors; the current format keeps its bytes.
4. Rule P16 states the rule and the exception; the checkpoint document states
   the encoding.

## Consequences

- No wire change.
- The fact that two orderings coexist stays recorded in
  [spec/implementation-status.md](../spec/implementation-status.md) as an
  implementation matter, because an encoder that re-encodes a checkpoint with
  the wrong ordering would produce a checkpoint the contract rejects.
- Implementers of a new checkpoint encoder in another language must use
  length-first ordering for the envelope and core deterministic ordering for
  everything inside it that is separately encoded (the consistency proof
  byte string, the peak receipts).
