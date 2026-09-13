# Checkpoints and receipts

**Status:** LIVE
**Date:** 2026-08-30
**Audience:** implementers of a Forestrie verifier, and anyone assessing what
can be checked without contacting the operator.
**Related:** [receipt-trust-model.md](./receipt-trust-model.md)
(questions 1 and 2),
[label-registry.md](./label-registry.md),
[log-authority-and-grants.md](./log-authority-and-grants.md),
[glossary.md](../glossary.md).

## Summary

A **checkpoint** is the log's signed commitment to its own state. A **receipt**
is a proof that one entry sits inside a checkpointed state. In Forestrie these
are the same kind of object: the sealed checkpoint *is* a standards-shaped
consistency receipt, publishable directly as contract calldata, with no bespoke
sibling format.

The property that matters most here is not the format — it is that a
checkpoint carries enough pre-signed material for **anyone holding public data
to mint a valid inclusion receipt without the signing key**. The operator's
receipt endpoint is a convenience, not an authority.

## 1. The checkpoint

A COSE Sign1 with a **detached payload**, carrying one consistency proof from
the previous checkpoint to this one.

| Part | Contents |
|---|---|
| Protected header | `1` algorithm, `395` verifiable data structure (value `3` = the MMR consistency profile) |
| Unprotected header | `396` proofs map, plus the private-use labels below |
| Payload | **Detached** — the raw concatenation of the accumulator peaks |
| Signature | By the delegated sealing key |

Unprotected labels a checkpoint may carry:

| Label | Value | Contents |
|---|---|---|
| Proofs map | `396` | Key `-2` inside it holds the consistency proof |
| Peak receipts | `-65931` | One detached-payload Sign1 per accumulator peak, signed at seal time |
| On-chain delegation proof | `-66535` | The proof the contract verifies at publish |
| Delegation certificate | `1000` | The certificate bytes, as a CBOR byte string |

Labels `1000` and `-66535` coexist and mean different things — the certificate
and the on-chain proof respectively. Both are carried opaquely by the sealer,
which does not branch on their contents.

### 1.1 The detached payload

The payload is the accumulator peaks concatenated raw — no CBOR framing, no
length prefixes. Verifiers reconstruct it independently and supply it to the
signature check, which is what makes the checkpoint publishable as calldata:
the contract can rebuild the exact signed bytes from the pre-decoded parts it
already receives, without parsing COSE on-chain.

### 1.2 One seal, one proof

Each checkpoint carries exactly one consistency proof, from the previous
checkpoint to this one. Catching up over several seals means **chaining** those
proofs at publish time rather than producing a single wide proof. Checkpoint
bases snap to massif entry boundaries, so a chain verifies boundary to
boundary.

## 2. Why anyone can mint a receipt

At seal time the sealer signs **one detached-payload Sign1 per accumulator
peak** and attaches them at `-65931`.

That is the whole trick. A peak receipt says "this peak was sealed" — signed
once, by the key that had authority at that moment. Anyone who later holds the
checkpoint and the replicated log data can:

1. compute an entry's inclusion path up to whichever peak covers it,
2. attach that path to the peak's pre-signed receipt at header `396`,
3. emit a standards-compliant inclusion receipt.

No signing key is involved, so no permission is involved. The emitted receipt
is privacy-preserving too: it reveals the path to a peak, not the rest of the
log.

This is what makes the operator structurally optional for receipt production.
It is also why a **replica** of the log is a complete verification substrate
rather than a cache — and why absence is provable against a replicated log
today, even though a *succinct* absence proof is not yet available.

## 3. What the contract receives

The contract verifies checkpoints but never parses COSE. It takes
**pre-decoded** structures:

| Structure | Purpose |
|---|---|
| `ConsistencyReceipt` | Protected header, signature, the chained consistency proofs, and the delegation proof |
| `ConsistencyProof` | One previous-to-current step |
| `InclusionProof` | Pre-decoded path and index |

The publisher's job is to decode the sealer's COSE into these and assemble the
chain. The contract then rebuilds the signed bytes, checks the signature under
the log's root key or a valid delegation of it, and re-checks the presented
grant's inclusion in its parent — the authority walk it performs on every
publish.

Checkpoint signing accepts **ES256 and KS256 only**. The WebAuthn algorithm is
never a checkpoint-signing algorithm; a passkey authorises a sealer, it never
seals. A KS256 checkpoint additionally rejects delegation outright.

## 4. The inclusion receipt

A receipt is a COSE Sign1 whose unprotected header carries the proofs map:

```
396 → -1 → { 1: mmrIndex, 2: inclusionPath }
```

The payload is either nil — the detached form, where the verifier supplies the
peak — or the 32-byte peak itself.

Verification decomposes into three layers, which should be named separately
because they fail for different reasons and carry different trust:

| Layer | Checks | Trust source |
|---|---|---|
| **A** | Receipt signature over the peak | The genesis COSE trust root, on the offline path |
| **B** | Inclusion, via the `396` proof, against the signed peak | Pure computation over the receipt bytes |
| **C** | Leaf binding — the entry hashes to what the receipt claims | Caller-supplied entry or grant context |

**Layer D — on-chain canonicality** — is deliberately separate and not part of
offline verification. Offline verification may legitimately succeed while a tip
is not yet anchored on-chain; treating that as a failure would conflate "this
is proven included" with "this is proven final".

For an entry, layer C is the content hash plus the idtimestamp. For a grant, it
is the grant commitment.

### 4.1 The offline boundary is explicit

Verification is **pure over bytes**. During verify there is no call to the
registration API, the coordinator, an RPC endpoint, a wallet, or any secret
store. A single trust bootstrap is allowed *before* verification — fetching or
loading the genesis document — and is not part of the verify step.

This boundary is the headline product claim in mechanical form. A hidden fetch
inside verify would falsify it silently, which is why it is stated as a
prohibition rather than a preference.

## 5. Identifiers and time

Entries carry a monotone `idtimestamp` assigned by the sequencer. Its time
component is what the endorsement window is checked against, so it is load-
bearing beyond ordering:

```
unixMs = (idtimestamp >> TimeShift) + epochBaseMs(epoch)
```

The identifier packs a time component, a sequence number and a device or shard
id into 8 bytes, big-endian.

Two properties are worth stating plainly, because they are frequently assumed
in the wrong direction:

- **A signature never establishes ordering.** Only the sequencer's monotone
  idtimestamp does, and only checkpoint anchoring bounds it. Anything deriving
  order from a signature time is deriving it from a claim, not a fact.
- **The exclusion trie is keyed on the idtimestamp**, not on content. No
  content-derived key can be a trie key, which is precisely why succinct
  absence needs a new authenticated index rather than a query against the
  existing one.

## 6. Caching

Published artifacts declare their own cache policy, and completeness decides
immutability:

| Artifact | Policy |
|---|---|
| Complete massif | `immutable` |
| Head massif | `no-store` |
| **All checkpoints** | `no-store` |
| Negative (404) responses | `no-store` |

Checkpoints are never cached because a re-seal overwrites one. A cached
checkpoint is a stale proof; a cached 404 can block a later legitimate write.
Heuristic caching of mutable objects fails silently, which is the failure mode
this policy exists to prevent.

## Open questions

- **Two CBOR canonicalisations coexist.** The certificate builder uses
  core-deterministic ordering while the checkpoint envelope uses the older
  length-first canonical ordering. They agree byte-for-byte only while every
  map label is single-byte, and the checkpoint envelope carries multi-byte
  labels. This has not caused a failure; it is the kind of thing that fails
  once, obscurely.
- **The epoch base calculation is off by one millisecond** relative to the
  obvious reading of the constant. It is self-consistent across producer and
  verifier, so nothing breaks; it would matter to a third-party implementer
  working from first principles.
- **A length guard in the idtimestamp byte splitter is written against the
  wrong bound**, accepting inputs it should reject. Callers currently supply
  well-formed input, so it is latent.
- **Layer D has no offline story by design.** Anchoring is checked by reading
  the chain. That is correct, but it means "verified offline" and "final" are
  genuinely different claims that a UI must not merge.

## References

- [receipt-trust-model.md](./receipt-trust-model.md) — what a receipt proves,
  and the trust roots that answer each question.
- [ADR-0045](../decisions/adr-0045-receipt-verify-offline-contract.md) — the
  accepted contract for layers A–C and the offline boundary.
- [log-authority-and-grants.md](./log-authority-and-grants.md) — the grant
  commitment that layer C checks for a grant receipt.
- [delegation-and-webauthn-envelopes.md](./delegation-and-webauthn-envelopes.md)
  — the delegation material a checkpoint carries.
- [label-registry.md](./label-registry.md) — every label above, with values.
