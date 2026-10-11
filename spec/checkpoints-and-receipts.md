# Checkpoints and receipts

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
are the same kind of object: the sealed checkpoint *is* a consistency receipt
in the shape of the COSE receipts MMR profile, publishable directly as contract
calldata, with no bespoke sibling format. §4.2 states where the shape departs
from the published RFC.

The property that matters most here is not the format — it is that a
checkpoint carries enough pre-signed material for **anyone holding public data
to mint a valid inclusion receipt without the signing key**. The operator's
receipt endpoint is a convenience, not an authority.

## 1. The checkpoint

A COSE Sign1 with a **detached payload**, carrying one consistency proof from
the massif's entry boundary to this seal. The sealer emits it tagged (CBOR tag
18); verifiers accept the untagged form as well, and the retained checkpoints
under `vectors/golden/burial/` are untagged.

| Part | Contents |
|---|---|
| Protected header | `1` algorithm, `395` verifiable data structure (value `3` = the MMR consistency profile), `-65933` `tree-size-2` — the signed size, required. Deterministic CBOR, canonical key order (§1.3) |
| Unprotected header | `396` proofs map, plus the private-use labels below |
| Payload | **Detached** — the raw concatenation of the accumulator peaks for `tree-size-2`, in descending height order |
| Signature | By the delegated sealing key, or by the root key when the owner seals directly |

The unprotected header carries the proofs map at `396` and, as the sealer
attaches them, the peak receipts at `-65931`, the on-chain delegation proof
at `-66535` and the delegation certificate at `1000`. The values and their
meanings are in [label-registry.md](./label-registry.md) §2; their encodings
are in §1.4 below. Labels `1000` and `-66535` coexist and mean different
things — the certificate and the on-chain proof respectively. Both are
carried opaquely by the sealer, which does not branch on their contents.

### 1.1 The detached payload

The payload is the accumulator peaks concatenated raw, 32 bytes each, in
descending height order — no CBOR framing, no length prefixes. Verifiers
reconstruct it independently and supply it to the signature check, which is
what makes the checkpoint publishable as calldata: the contract can rebuild
the exact signed bytes from the pre-decoded parts it already receives, without
parsing COSE on-chain.

### 1.2 One seal, one proof, from the massif boundary

Each checkpoint carries exactly one consistency proof. Its base is **the
massif's entry boundary** — the log size at which the massif being sealed
begins — never the previous checkpoint. A massif is sealed repeatedly as it
grows, and each re-seal **replaces** the checkpoint object with one whose proof
still runs from the same boundary to the new size; the head checkpoint decides
only where sealing resumes. A completed massif's final checkpoint is therefore
a boundary-to-boundary link, and a retained chain of those verifies boundary
to boundary, each link's base equal to the previous link's sealed size.

Catching up over several sealed massifs at publish means **chaining** those
proofs in one contract call rather than producing a single wide proof; §1.3
states what the contract requires of a chain.

### 1.3 What the signature covers

The checkpoint signature asserts **the accumulator and the tree size it is
the accumulator of**: the protected header's `tree-size-2` and the detached
payload. Nothing else is signed. The consistency proof in the `396` map is
prover context; it is how a verifier reconstructs the payload, and its
`tree-size-2` MUST equal the signed one. Its `tree-size-1` is not signed:
a verifier already holds the size and accumulator it verifies from, and the
proof need only be consistent with them.

The size is signed because the proof alone does not pin it. When no
origin peak is folded — every first checkpoint, and any extension whose
origin peaks all sit above the split — the same accumulator and signature
verify at several declared sizes, and whoever submits the receipt chooses
which one is stored. Values are never forged; the height they are read at
is. Reasoning and the finding: [ADR-0066](../decisions/adr-0066-sec-signed-checkpoint-size.md).

When a chain of proofs is published together (§1.2), the signed
`tree-size-2` MUST equal the last proof's `tree-size-2`, and each proof's
base MUST equal the previous proof's target, the first the verifier's
trusted size. The publisher may relay several sealed steps, and re-base a
step, under the head checkpoint's signature, because no signed value names
the base. Every verifier of a consistency proof, on-chain or off, MUST:

1. take `tree-size-1` from state it already trusts — its own accumulator, or
   on-chain the anchored size — never from the proof;
2. require the signed `tree-size-2` to equal the declared one, carried as a
   CBOR unsigned integer;
3. require `tree-size-2` to be a complete MMR size;
4. require each origin peak's path to have exactly the length the two sizes
   imply, and every origin peak below the split to prove the same root; the
   number of proven roots and of right peaks is then fixed by the sizes.

The reference fold is univocity's `consistentRootsForSizes`; the Go and
TypeScript verifiers port it line for line against one set of vectors.

The protected header is deterministic CBOR as the profile draft requires
(RFC 8949 §4.2.1: shortest-form arguments, definite lengths, keys in
canonical order, no duplicate keys, no tags, the map consuming the whole
header, integer keys only), and univocity rejects anything else. A label a
verifier does not read may carry an integer, a byte string, a valid-UTF-8
text string, `false`, `true`, `null` or a shortest-form float, and the
verifier skips it; any other value type under an unread label (a container,
a tag, `undefined`, a wider-than-needed float) is rejected everywhere
(ADR-0066 D9). The sealer emits `{1: alg, 395: 3, -65933: tree-size-2}`.

### 1.4 The encodings

**The consistency proof.** Key `-2` of the `396` map holds a **byte string**
wrapping a CBOR array `[tree-size-1, tree-size-2, paths, right-peaks]`:
`tree-size-1` is the base, `tree-size-2` the sealed size, `paths` one
inclusion path per base peak proven at the sealed size, and `right-peaks` the
new peaks the proven roots do not cover.

**The peak receipts.** Label `-65931` holds an **array of byte strings**, one
per accumulator peak in the same descending-height order. Each is a tagged
COSE Sign1 (tag 18) with protected header `{1: alg, 395: 3, 4: kid}` (the
`kid` present when the signer has one), an empty unprotected map, a nil
payload, and a signature over the 32-byte peak as detached payload.

**The delegation material.** Label `1000` holds the delegation certificate as
a byte string wrapping its COSE Sign1; label `-66535` holds the on-chain
delegation proof. Both are carried opaquely by the sealer.

## 2. Why anyone can mint a receipt

At seal time the sealer signs **one detached-payload Sign1 per accumulator
peak** and attaches them at `-65931`.

That is the mechanism. A peak receipt says "this peak was sealed" — signed
once, by the key that had authority at that moment. Anyone who later holds the
checkpoint and the replicated log data can:

1. compute an entry's inclusion path up to whichever peak covers it,
2. attach that path to the peak's pre-signed receipt at header `396`, and
   copy the checkpoint's label-`1000` certificate alongside it when the
   checkpoint carries one,
3. emit an inclusion receipt in the MMR profile shape (§4).

No signing key is involved, so no permission is involved. The emitted receipt
is privacy-preserving too: it reveals the path to a peak, not the rest of the
log.

This is what makes the operator structurally optional for receipt production.
It is also why a **replica** of the log is a complete verification substrate
rather than a cache — and why absence is provable against a replicated log.
The *succinct* form is a different matter, stated in
[trust-boundaries-and-operator-powers.md](./trust-boundaries-and-operator-powers.md)
§6.

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
publish. It parses `tree-size-2` from the protected header in the same walk
as `alg`, requires it to equal the size it is about to store, and rejects a
receipt that omits it or whose header is not deterministic CBOR (§1.3).

Checkpoint signing accepts **ES256 and KS256 only**. The WebAuthn algorithm is
never a checkpoint-signing algorithm; a passkey authorises a sealer, it never
seals. A KS256 checkpoint additionally rejects delegation outright.

## 4. The inclusion receipt

A receipt is a COSE Sign1 whose unprotected header carries the proofs map.
Key `-1` holds an **array** of inclusion proofs; a Forestrie receipt carries
one, and verifiers read the first element:

```
396 → { -1: [ { 1: mmrIndex, 2: [ + bstr .size 32 ] } ] }
```

The payload is either nil — the detached form, where the verifier supplies the
peak — or the 32-byte peak itself. When the checkpoint the receipt was minted
from carries a delegation certificate at label `1000`, the receipt carries a
copy at the same label.

Verification decomposes into three layers, which should be named separately
because they fail for different reasons and carry different trust:

| Layer | Checks | Trust source |
|---|---|---|
| **A** | Receipt signature over the peak. Under a signature root the key is resolved from the root: directly, or through the label-`1000` certificate when the receipt carries one (root → certificate → delegated sealing key) | The trust root the caller holds |
| **B** | Inclusion, via the `396` proof, against the signed peak | Pure computation over the receipt bytes |
| **C** | Leaf binding — the entry hashes to what the receipt claims | Caller-supplied entry or grant context, and the idtimestamp |

**Layer D — on-chain canonicality** — is deliberately separate and not part of
offline verification. Offline verification may legitimately succeed before a
tip is anchored on-chain; treating that as a failure would conflate "this is
proven included" with "this is proven final".

For an entry, layer C is the content hash plus the idtimestamp:

```
leaf = SHA-256( idtimestamp(8, big-endian) ‖ SHA-256( statement bytes ) )
```

where the statement bytes are the exact registered COSE Sign1, endorsement
included. For a grant, the inner hash is the grant commitment's inner hash
instead ([log-authority-and-grants.md](./log-authority-and-grants.md) §4), and
the outer hash is the same. The idtimestamp is not carried in the receipt;
the caller supplies it, from the entry id or from a sealed grant's `-65537`
header, and the leaf hash binds it.

### 4.1 The offline boundary is explicit

Verification is **pure over bytes**. During verify there is no call to the
registration API, the coordinator, an RPC endpoint, a wallet, or any secret
store. A single trust bootstrap is allowed *before* verification — fetching or
loading the genesis document — and is not part of the verify step.

This boundary is what "verifiable offline" means mechanically. A hidden fetch
inside verify would falsify it silently, which is why it is stated as a
prohibition rather than a preference.

### 4.2 Where the shape departs from RFC 9942

RFC 9942 (COSE receipts) defines headers `395` and `396`. Forestrie's receipts
and checkpoints are shaped on the MMR profile draft for that registry and
differ from a strict reading of the RFC in three ways a verifier must
tolerate:

1. the inclusion proof under `396 → -1` is a plain `{1, 2}` map inside the
   array, not a byte-string-wrapped array;
2. a receipt may carry the 32-byte peak as an attached payload rather than
   always detaching it;
3. the verifiable data structure value `3` is requested by the MMR profile
   draft and not registered. Checkpoints carry it (§1.3); inclusion receipts
   minted from a peak receipt carry only the algorithm, and no receipt
   vector in this repository carries `395`. A verifier must not treat its
   presence as registry fact.

## 5. Identifiers and time

Entries carry a monotone `idtimestamp` assigned by the sequencer. Its time
component is what the endorsement window is checked against, so it is load-
bearing beyond ordering:

```
TimeShift        = 24
epochBaseMs(e)   = e × (2^40 − 1)
unixMs           = (idtimestamp >> TimeShift) + epochBaseMs(epoch)
```

The time component occupies the top 40 bits, so an epoch spans about 34 years;
the reference time is unix time and the current epoch is 1. The identifier
packs that time component, a sequence number and a device or shard id into
8 bytes, big-endian.

Two properties are stated here because they are commonly assumed in the wrong
direction:

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
| Forest genesis document | `immutable` |
| Complete massif | `immutable` |
| Head massif | `no-store` |
| **All checkpoints** | `no-store` |
| Receipts | `no-store` |
| Negative (404) responses | `no-store` |

Checkpoints are never cached because a re-seal overwrites one, and receipts
are not cached even for a complete massif because they are minted from the
checkpoint. A cached checkpoint is a stale proof; a cached 404 can block a
later legitimate write. Heuristic caching of mutable objects fails silently,
which is the failure mode this policy exists to prevent.

## Wire encoding conformance

Every CBOR object on the wire — signed structures (COSE Sign1 envelopes,
checkpoints, protected headers) and unsigned request bodies alike — MUST be
deterministically encoded per RFC 8949 §4.2 core deterministic encoding:
shortest-form arguments, definite lengths only, canonical key order, no
duplicate keys, no tags. This is the wire's baseline, not a property scoped
to the checkpoint's protected header alone (§1.3).

Verifiers and decoders reject non-canonical encodings on receipt. This is an
enforced boundary, not an implementation preference a client is free to
relax.

An encoder that does not guarantee deterministic, canonical output is
unsupported, even where its output is valid CBOR by some other reading.
`cbor-x` is the standing example: it is a JSON-as-CBOR encoder and does not
produce COSE/CTAP2-compatible canonical CBOR, so its output is rejected on
the same terms as any other non-canonical encoding.

The protected header's canonical-key-order requirement, including the
grammar for values carried under labels a verifier does not read, is stated
in full in
[ADR-0066 D9](../decisions/adr-0066-sec-signed-checkpoint-size.md#d9--receipt-encoding-conformance).
One divergence from core-deterministic order is carved out there and
nowhere else — the checkpoint envelope's protected header uses length-first
canonical key order instead — noted under [Open questions](#open-questions).

## Open questions

- **Layer D has no offline story by design.** Anchoring is checked by reading
  the chain. That is correct, but it means "verified offline" and "final" are
  genuinely different claims that a UI must not merge.

The two CBOR canonicalisations in use, and the idtimestamp splitter's length
guard, are implementation matters recorded in
[implementation-status.md](./implementation-status.md).

## References

- [receipt-trust-model.md](./receipt-trust-model.md) — what a receipt proves,
  and the trust roots that answer each question.
- [ADR-0045](../decisions/adr-0045-receipt-verify-offline-contract.md) — the
  accepted contract for layers A–C and the offline boundary.
- [ADR-0066](../decisions/adr-0066-sec-signed-checkpoint-size.md) — the
  signed tree sizes and the verification MUSTs of §1.3.
- [log-authority-and-grants.md](./log-authority-and-grants.md) — the grant
  commitment that layer C checks for a grant receipt.
- [delegation-and-webauthn-envelopes.md](./delegation-and-webauthn-envelopes.md)
  — the delegation material a checkpoint carries.
- [label-registry.md](./label-registry.md) — every label above, with values.
