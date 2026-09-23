# ADR-0066: Signed checkpoint tree size

**Status:** ACCEPTED — one of the accepted decisions the specification under
[`spec/`](../spec/) rests on. Decided by the owner on 2026-09-19 as decisions
D1–D8 of Forestrie plan-2609-10 (an internal planning document); revised on
2026-09-20 after the implementation reviews (D1–D5 and D8
narrowed to one signed size, D9 added). This record integrates the
revisions; each affected section carries an "Alternatives considered" note
recording what the first cut chose and what the review found. The
2026-09-19 text is in the internal devdocs history at `c69b1c1`.
**Date:** 2026-09-19, revised 2026-09-20
**Categories:** [SECURITY, WIRE-FORMAT, CHECKPOINTS, VERIFICATION,
UNIVOCITY, ARBOR, CANOPY, PROTOCOL]
**Tracking:** Forestrie issue FOR-568 (internal tracker). Plan:
plan-2609-10-signed-checkpoint-size (internal).
**Related:**
[spec/checkpoints-and-receipts.md](../spec/checkpoints-and-receipts.md)
(the checkpoint envelope this ADR changes),
[spec/label-registry.md](../spec/label-registry.md)
(where the label is registered),
[rules/platform.md](../rules/platform.md)
P14 (whose wording this ADR corrects),
[draft-bryce-cose-receipts-mmr-profile](https://github.com/robinbryce/draft-bryce-cose-receipts-mmr-profile)
(the profile the checkpoint receipt follows). Implementation: univocity
[PR #42](https://github.com/forestrie/univocity/pull/42) (FOR-567, the
shape-checked fold this ADR completes) and
[PR #43](https://github.com/forestrie/univocity/pull/43) (the signed size
and header parsing); go-merklelog
[PR #11](https://github.com/forestrie/go-merklelog/pull/11) (the Go
verifier); arbor [PR #102](https://github.com/forestrie/arbor/pull/102)
(sealer and publisher); canopy
[PR #255](https://github.com/forestrie/canopy/pull/255) (the TypeScript
packages).

## Context

A Forestrie checkpoint is a COSE Receipt of Consistency under the MMR
profile of RFC 9942. The sealer signs the protected header `{alg, vds}` and
a detached payload, the raw concatenation of the accumulator peaks for the
new tree size. The consistency proof, including `tree-size-1` and
`tree-size-2`, travels in the **unprotected** header, exactly as the profile
draft specifies. No signed byte carries either size: not in the draft, not
in the arbor sealer, not in any off-chain verifier, and not in the
univocity contract, which nevertheless stores `tree-size-2` as the log's
anchored size.

The 2026-09-19 adversarial review of univocity (FOR-567, FOR-568) showed
what an unsigned size permits. The attacker never alters a signed value:
the peaks in the payload are the sealer's own. What the attacker chooses
is the tree size the contract records those peaks *as*, because the size
comes from the unprotected proof and nothing signed contradicts it.

The contract checks a consistency proof by folding it: it takes the peaks
of the previously anchored tree (the origin peaks), applies each one's
proof path to reach a peak of the new tree, and compares the result with
the signed payload. univocity PR #42 made that fold size-driven
(`consistentRootsForSizes`). The new size must be a complete MMR size, and
each origin peak's path must have exactly the length the two sizes imply:
an origin peak that the new tree merges into a larger peak needs a path of
one sibling per level climbed, while an origin peak that is still a peak of
the new tree needs an empty path. Where a path is non-empty, its length is
fixed by the two sizes and its hashes are checked against the signed
payload, so the declared new size is bound by the signature after all.

Where every path is empty, nothing ties the size to the signature: the
signed payload is simply the origin peaks followed by the new tree's extra
peaks, and any larger size that adds peaks of the same heights produces
the same payload. Two such cases are reachable without any key, using the
victim's own published calldata, by anyone who can front-run the
transaction:

1. **The first checkpoint of any non-root log.** With `tree-size-1 = 0`
   there are no origin peaks and nothing is proven; the payload is entirely
   new peaks. A first
   checkpoint signed for size 1 is accepted at any one-peak size, including
   `2^64 − 1`, after which `SizeMustIncrease` rejects every later
   checkpoint. The root authority log is not exposed, because its
   self-inclusion check binds the claimed size.
2. **Extensions in which every origin peak stays a peak.** When one leaf
   is appended without a carry (7 → 8, 15 → 16), every path is empty and
   the fold requires only the right number of new peaks. Every complete
   size with the same prefix and the same number of new peaks is accepted
   with byte-identical calldata and signature: 7 → 8 or 10; 15 → 16, 18 or
   22. Inflation is bounded below 2×, but the stored `(size, accumulator)`
   is a pair the log never had. The next inclusion proof stops verifying
   and the signer's own next checkpoint reverts.

The same gap is in the draft's own verification procedure: the signed
statement is the accumulator, and the sizes are prover-supplied context
that the verifier reads but nothing attests.

A previous resolution of FOR-568 marked the size-inflation half fixed by
PR #42. That was wrong for the two cases above, and this ADR exists so that
"path-length pinning alone defeats keyless replay" is not claimed again.

Two further facts, established by the implementation reviews, shape the
decisions below and are recorded once here:

- **Proofs are relayed and re-based under the head signature.** The
  arbor publisher relays several sealed steps' single proofs under the
  head checkpoint's signature, so the head's declared base is the last
  link's, not the first's; and after a partial-size publish it re-bases a
  link inside a massif under the original signature. The sealer may
  re-base in the same way. Both operations are legitimate, whichever
  component performs them, and both mean that no signed value may name
  the origin size (reviewed on
  [arbor #102](https://github.com/forestrie/arbor/pull/102) and
  [go-merklelog #11](https://github.com/forestrie/go-merklelog/pull/11);
  summarised on FOR-568).
- **Verifiers must agree on which headers are valid.** Under univocity
  rule U7 the contract is the arbiter of what the canonical wire bytes are.
  The review of [univocity #43](https://github.com/forestrie/univocity/pull/43)
  found five header encodings on which the first-cut contract and the Go
  decoder disagreed; each one is a checkpoint the chain would anchor that
  no replica could re-verify, or the reverse.

## Decision

### D1 — The target tree size is signed

The checkpoint receipt's protected header carries `tree-size-2`: the size
whose accumulator is the detached payload, and the size the contract
stores. `tree-size-1` is **not** signed. It stays where the profile always
had it, in the unprotected `consistency-proof`, as prover context. It
cannot be signed, because proofs are re-based and relayed after signing,
by the publisher and possibly the sealer (Context), so a signature over
the origin would break on every legitimate re-base. It need not be signed,
because a verifier already holds
the size and accumulator it verifies from and the fold pins every proof's
base to that state (D5.4).

*Alternatives considered.* The first cut signed both sizes, on the grounds
that a signed `tree-size-1` makes the receipt's claim explicit for a
relying party holding no state ("consistent from A to B, signed by the
log") and gives the contract a free cross-check against the anchored size.
Implemented in slice 02, the contract-side check reverted every multi-link
catch-up and every re-based publish, and the alternative of removing
re-basing broke publishing after any partial-size publish (Context, first
fact). The owner ruled that `tree-size-1` is not compared
on-chain by definition: the proof need only be consistent with the
previously published accumulator and size, which the verifier already
holds. The cross-check therefore compared a value the verifier must
already hold, and the stateless from-to claim is what D5.4 asks every
verifier to supply for itself. Label `−65932`, allocated for
`tree-size-1`, was withdrawn before any deployment used it (D3).

### D2 — Chain semantics

A receipt may carry several consistency proofs, one per sealed step,
relayed under the head checkpoint's signature. The signed `tree-size-2`
MUST equal the last proof's `tree-size-2`. Each proof's `tree-size-1` MUST
equal the previous proof's `tree-size-2`, and the first proof's
`tree-size-1` MUST equal the verifier's trusted size; the fold enforces
both against trusted state (D5.4), so intermediate sizes need no signature
of their own. A publisher may re-base a step under the original signature,
because nothing signed names the base.

*Alternatives considered.* The first cut also required the signed
`tree-size-1` to equal the *first* proof's base. That is the rule the
relay model contradicts (D1), and it was withdrawn with the signed origin.

### D3 — Label

An interim private-use value following the registry's derived convention
(`COSEPrivateStart − <related label>`, `COSEPrivateStart = −65535`),
treating 398 as the next conceptual protected-header slot after `vds`
(395), `vdp` (396) and the slot 397 that was briefly allocated:

| Parameter | Label | Type | Header |
|---|---|---|---|
| `tree-size-2` | `−65933` (= −65535 − 398) | uint (CBOR major type 0) | protected |
| ~~`tree-size-1`~~ | ~~`−65932`~~ (= −65535 − 397) | — | withdrawn 2026-09-20 before use; not to be reassigned |

The value does not collide with an existing allocation (`−65931` peak
receipts, `−66535` delegation proof, `−65799..−65801` algorithms and
envelopes). The profile draft mints `TBD_2` for `tree-size-2`, with the
private-use value as the interim assignment, mirroring how `TBD_1` (`vds`)
is handled. The registry's own `TBD1`/`TBD2` names (WebAuthn envelope,
session-key endorsement) are unrelated; the draft's names are scoped to the
draft.

*Alternatives considered.* Continuing the `−658xx` sequential band was
rejected because an algorithm id and an unprotected label already share
`−65800` there. `−65932` is kept in the table as withdrawn rather than
deleted so that the number is never reused for something else while any
fixture or branch from the first cut still carries it.

### D4 — Placement: a dedicated protected label, not a CWT claim

RFC 9942 §4.4 invites profiles to add mandatory protected header
parameters. SCITT (RFC 9943) mandates CWT Claims (label 15) on receipts,
and the size could live there as a private claim key, but a nested map
costs more to parse on-chain and would tie checkpoint receipts to CWT
claims that Forestrie does not otherwise put on checkpoints. The size is
a dedicated label, and it MUST be present on a receipt of consistency
under this profile.

Protected header after this change:

```cddl
protected-header-map = {
  &(alg: 1) => int
  &(vds: 395) => TBD_1
  &(tree-size-2: TBD_2) => uint
  * cose-label => cose-value
}
```

The unprotected `consistency-proof` structure is unchanged, so RFC 9942
verifiers that ignore unknown protected labels still read the proof; they
simply do not get the binding. The sealer emits exactly
`{1: alg, 395: 3, −65933: tree-size-2}`; for ES256 at size 8 the encoded
header is `a3012619018b033a0001018c08`.

### D5 — Verification MUSTs (spec and every verifier)

1. `tree-size-2` MUST be a complete MMR size:
   `mmr_size_for_leaf_count(leaf_count(size − 1)) == size`.
2. For each origin peak, the path length MUST equal the value implied by
   the two sizes. Let `split` be the height of the one new peak that
   absorbs origin peaks (the highest bit on which the two leaf counts
   differ). An origin peak of height `h` below `split` has a path of
   length `split − h`; an origin peak above `split` is still a peak and
   has an empty path. This is the length `inclusion_proof_path` produces,
   and it raises the draft's SHOULD to a MUST, stated for consistency
   proofs.
3. Every origin peak below `split` MUST prove the same root. The number of
   proven roots, and the number of right peaks (the new tree's peaks below
   every origin peak, which no path reaches and the prover supplies), are
   then fixed by the sizes.
4. A verifier MUST take `tree-size-1` from state it already trusts (its own
   accumulator, or on-chain the anchored size), never from the proof. The
   `tree-size-1` carried in each consistency proof is unsigned prover
   context: it is compared with that state (D2), never substituted for it.
5. The signed `tree-size-2` MUST equal the declared `tree-size-2` of the
   last consistency proof. It MUST be carried as a CBOR unsigned integer
   (major type 0); a negative integer or any other type under the label is
   rejected, not reinterpreted, and a receipt without the label is
   rejected.

Reference implementations: univocity `consistentRootsForSizes` (Solidity,
PR #42) and `consistent_roots_for_sizes` (Python,
[merkle-mountain-range-proofs PR #1](https://github.com/robinbryce/merkle-mountain-range-proofs/pull/1)).
The Go and TypeScript ports follow them line for line and are pinned to
the same KAT-39 vectors. `consistent_roots_for_sizes` does not call the
draft's earlier `consistent_roots`; an implementation that keeps
`consistent_roots` reaches the same accept set only with the five checks
above applied around it, including a root-count check in place of the
direct same-root comparison (plan-2609-10 slice 01, "Fold formulations").

These MUSTs apply to **every** verifier of a receipt of consistency, not
only to split-view detection: a consistency proof relates two states, so
every verifier carries `(size, accumulator)` forward as trusted state. The
wrongly recorded size shows up when the ledger's next genuine receipt fails
against it, which reads as equivocation by a correct ledger.

The inclusion receipt's SHOULD ("check the lengths of the proof paths are
appropriate for the provided tree sizes") stays a SHOULD. An inclusion
receipt under this profile carries no declared size; a path of the wrong
length changes the computed root and the signature fails. The MUST is
needed only where a size is declared, stored and acted on.

*Alternatives considered.* The first cut's rule 5 required both signed
sizes to equal the declared ones under the first-cut chain semantics; it
narrowed with D1 and D2. The type constraint in rule 5 was added in the
2026-09-20 revision alongside D9: a parser that reinterprets a negative
integer or a byte string as a size gives a different answer from one that
rejects it, and only rejection keeps the verifiers in agreement (D9).

### D6 — Rollout order and compatibility

No compatibility mode. Per environment:

1. Land the spec, the label and this ADR. Nothing deploys.
2. Land the Go, Solidity and TypeScript changes in parallel behind their own
   tests; publish canopy package versions; land the client bumps.
3. Deploy new univocity instances (immutable redeploy; UUPS implementation
   upgrade) that **require** the label, then the arbor sealer release that
   emits it, then the canopy and CLI verifiers that require it. Because the
   contract rejects old-format receipts, the sealer is released together
   with, or after, the contract in each environment; the window between
   them is a publish outage, not a safety gap.
4. Logs anchored before the change are retired or re-anchored. No legacy
   state is supported (owner decision, plan-2609-09).

### D7 — Interim mitigation

Until deployed, issue grants with a non-zero `maxHeight`, which caps how far
a relayer can inflate a declared size. It does not prevent mislabelling
within the cap. Operational note in plan-2609-10 slice 06, not a code
change.

### D8 — What each verifier compares

| Verifier | Trusted `tree-size-1` source | Checks added |
|---|---|---|
| univocity contract | `log.size` | signed size-2 == `claimedSize` (the last proof's `treeSize2`); label absent → reject; protected-header encoding per D9 |
| go-merklelog `VerifyCheckpointReceipt` (store-backed) | local store | signed size-2 == the store size used for the accumulator; size-driven fold for third-party receipts; receipt encoding per D9 |
| canopy `verifyCheckpointChain` | previous checkpoint in the chain, or a caller-supplied anchor | signed size-2 == declared; size-driven fold (D5); receipt encoding per D9 |
| forestrie-cli, thinker | via the canopy packages | none of their own; display the label |

*Alternatives considered.* The first cut's contract row also required the
signed `tree-size-1` to equal the first proof's base and the anchored size;
it was removed with the signed origin (D1).

### D9 — Receipt encoding conformance

A checkpoint receipt's protected header, its unprotected header map, the
`vdp` (label 396) map carried in the unprotected header, the
`consistency-proofs` array carried under `vdp` key `-2`, and every
`consistency-proof` tuple (`bstr .cbor [tree-size-1, tree-size-2, paths,
right-peaks]`) it contains MUST each be deterministically encoded CBOR (RFC
8949 §4.2.1): arguments in shortest form; definite lengths only; map keys
in canonical order (shorter encoding first, then bytewise), which makes any
duplicate keys adjacent; no duplicate keys. A string, array or map length
that exceeds the remaining bytes is rejected, and each of these structures
MUST consume exactly the bytes it declares: no trailing bytes, and none may
declare fewer elements or pairs than it carries. Integer keys whose
magnitude exceeds int64 are rejected.

Within a `consistency-proof` tuple, the CDDL requires an array at `paths`,
at each per-peak path inside it, and at `right-peaks`. A CBOR `null` (`f6`)
is not an alternative encoding of an empty array at any of these positions
and is rejected, not tolerated. An origin peak that the new size leaves
unchanged has an empty path: that per-peak path MUST be encoded as the
empty array `80`, and a decoder that reads a `null` there as though it
meant the same thing accepts bytes another verifier rejects.

A verifier MUST reject any of these five structures that is not so encoded,
and MUST NOT read any value out of one until it has confirmed that
structure consumes exactly its bytes. The protected header is signed whole
and read by label lookup, and the consistency-proofs chain is what the fold
— and, transitively, the signature — acts on: two conformant decoders
either read the same `alg`, `tree-size-2` and folded accumulator from a
receipt or both reject it, and under univocity rule U7 the contract's
acceptance is what every replica must be able to reproduce. Where
implementations cannot cheaply agree on a value type, the type is excluded
rather than tolerated.

**Keys** in the protected header and in the `vdp` map MUST be integers
(major type 0 or 1) within int64. Text-string labels, which COSE permits in
general, are not used by this profile and are rejected, so that key order
and duplicate detection are a comparison of integers in every
implementation.

**Values under protected-header labels the verifier does not read** MUST be
one of the following, and the verifier MUST skip, not reject, any of them:
an integer; a byte string; a text string that is valid UTF-8; the simple
values `false`, `true` and `null`; or a float in the shortest form that
preserves its value (half, then single, then double, as RFC 8949 §4.2.1
requires). A sealer adding a label of these types MUST NOT make its
checkpoints unverifiable. Everything else under an unread protected-header
label is rejected: arrays and maps (so no nesting, no nested-order
question, no nesting limit), tags, `undefined` and every other simple
value, a float that has a shorter form preserving its value, invalid UTF-8,
additional information 28–30, the break code 31, a two-byte simple value
below 32, and any item cut off by the end of the header. Tags are rejected
there because the profile assigns them no meaning under an unread label and
skipping one silently would hide a semantic the signer intended; containers
are rejected there because no protected-header label carries one and each
verifier would otherwise have to agree on nested order, duplicates and
depth. The value under `vdp` key `-2` is held to the same no-tag rule, for
the same reason: it MUST be a bare `consistency-proof` byte string or a
`consistency-proofs` array of them, and a CBOR tag wrapping either form is
rejected, because the fold reads the value positionally, not by tag. This
allowlist governs only those two positions; an unprotected-header label
this profile does not otherwise constrain (pre-signed peak receipts,
delegation material) legitimately carries a tagged COSE object, and D9 does
not narrow its value type beyond the deterministic encoding required above.

*Revised 2026-09-20 (D9 amendment).* The first wording admitted any
well-formed definite-length item under an unread protected-header label,
including `undefined`, every simple value, floats in any width, and
containers. The adversarial review of canopy #255 showed that this cannot
be met identically: go-merklelog's canonical re-encode check rejects a
single-precision float that fits a half, a double with a shorter form, and
`undefined`, while canopy and the contract accepted them, so the chain
would anchor a checkpoint no Go replica re-verifies, which is the case D9
exists to prevent. Shortest-form floats were already required by RFC 8949
§4.2.1; the wording above makes that explicit and removes the value types
on which implementations disagree. The review also found that the three
verifiers already agree on length-first key order (shorter encoding first,
then bytewise); the outliers are canopy's own encoder and arbor's
delegation-certificate code, which are moved to it, not the rule. The same
review, continuing into the go-merklelog and canopy implementation slices,
found that determinism was being checked for the protected header alone
while the unprotected header, the `vdp` map, the `consistency-proofs` array
and each proof tuple decoded leniently: an indefinite-length
`consistency-proofs` array, a tag wrapping it, duplicate `-2` keys in the
`vdp` map, non-canonical `vdp` key order, a non-shortest-form integer
inside a proof tuple, and a `null` in place of an empty per-peak path each
decoded, and in the header-only tests verified, on one side and not the
other. D9 is widened to the five structures above for the reason it exists
at all: a receipt one verifier accepts and another cannot re-verify is the
failure D9 closes, wherever in the receipt the disagreement starts.

Reference behaviours, in agreement on every class reviewed across all five
structures: the contract's single-walk parser (`seekLabels`, reading `alg`
and `tree-size-2` from the protected header in one pass; the contract
receives the consistency-proof chain as pre-decoded calldata, not CBOR, so
D9's proof-array and tuple rules bind the off-chain decoders that produce
that calldata, not the contract itself), go-merklelog's strict decode mode
with a canonical re-encode check over all five structures and an explicit
rejection of a null inner path (go-merklelog
[PR #15](https://github.com/forestrie/go-merklelog/pull/15)), and canopy's
`decodeCborDeterministic` and `decodeConsistencyProofsFromUnprotected`,
which reject the same non-canonical and null forms (canopy
[PR #264](https://github.com/forestrie/canopy/pull/264)).

*Alternatives considered.* The first cut of the contract parser accepted
any CBOR it could walk, in any key order, with an O(n²) duplicate scan. The
[univocity #43](https://github.com/forestrie/univocity/pull/43) review
found five classes where it and go-merklelog disagreed: a string length
truncated to 32 bits misaligning the cursor, a header not fully consumed,
non-shortest-form arguments, an over-read on a truncated header, and a
map-length overflow. Lenient decoding was rejected because each such class
is a checkpoint one verifier anchors and another cannot re-verify.
Rejecting unread labels of major type 7, the other option once strictness
was chosen, was rejected because a sealer adding a boolean or float label
would make its checkpoints unverifiable, while skipping any well-formed
definite-length item is safe: unread labels contribute to the signed bytes
only. Canonical key order was chosen over order-independent lookup because
it makes duplicate detection one comparison per key and removes the
quadratic scan. The single-walk parser is an implementation choice with no
spec impact and is recorded so that it is not reopened. Tolerating a `null`
inner path, so that objects sealed before go-merklelog normalised it kept
decoding, was considered and rejected: no sealed state predates this
decision (D6), and reading `null` as an empty path is exactly the kind of
per-implementation interpretation D9 exists to close off.

### What is deliberately not bound

`logId`, chain id and contract address stay outside the signature.
Cross-log replay was examined in FOR-568 and refuted: a replayed receipt is
the victim's own key over the victim's own content in a log the attacker
created, which the protocol permits as replication and which is visible
on-chain. No capability is gained and neither consistency nor
non-equivocation is affected. Any of these can be added later under the
same mechanism, as further protected labels, if a reason appears.
`tree-size-1` is not bound either (D1).

The correct statement of what a checkpoint signature asserts, replacing
P14's "binds to exactly one instance root", is: **the signature asserts the
accumulator and the tree size it is the accumulator of; the contract
enforces consistency with the anchored state.**

## Consequences

Positive:

- For a given trusted origin, a signed calldata is accepted at exactly one
  `tree-size-2`. The first-checkpoint freeze and the empty-path extension
  mis-anchor (Context, cases 1 and 2) become key-holder-only, and a key
  holder who signs a wrong size has signed a false statement that the fold
  then rejects.
- Every consistency verifier in the estate enforces the same five checks
  and the same header conformance rule, so an off-chain verifier that
  accepts a receipt agrees with the chain, and a checkpoint the chain
  accepts can be re-verified by every replica.
- The publisher's relay and re-basing of proofs under the head signature
  keep working, since no signed value names the base.
- The draft's verification procedure gains the binding it was missing, so
  third-party implementations get it too.

Negative and accepted:

- A wire-format change touching the draft, the label registry, go-merklelog,
  the arbor sealer and publisher, the contract, four canopy packages and
  two clients. Fixtures are re-cut in three languages.
- No compatibility mode, so each environment has a contract-first publish
  outage and affected logs must be re-anchored.
- One more private-use label pending IANA assignment through the profile
  draft.
- A sealer that emits a non-deterministic protected header, or a tag under
  any label, has its checkpoints rejected everywhere. The sealer emits the
  canonical header; the constraint is on any future encoder.
- A stateless relying party gets no signed "from" size. It verifies a
  receipt against an origin it supplies itself, which is what D5.4 asks of
  every verifier anyway.

## Implementation

Sliced in plan-2609-10: 01 spec, ADR and label (this document, the
registry row, the draft text); 02 go-merklelog and arbor; 03 univocity;
04 canopy shared packages; 05 clients; 06 cross-language KAT, adversarial
re-review, deployment and re-anchoring. 02, 03 and 04 are independent once
the label is locked and ran in parallel; their reviews produced the
2026-09-20 revisions recorded above.

## Alternatives considered (whole design)

Section-level alternatives are recorded under D1, D2, D3, D5, D8 and D9.
The remaining alternatives to the design as a whole:

- **Size in CWT Claims (label 15).** Standards-adjacent for SCITT
  receipts, but a nested map on-chain and a claims dependency Forestrie's
  checkpoints do not otherwise have. Rejected (D4).
- **`be64(tree-size-2) || peaks` as the detached payload.** Keeps the header
  untouched, but changes the payload convention every verifier and the
  draft rely on, and hides the size from any tool that reads the header.
  Rejected in favour of a protected label, which the contract already
  parses for `alg`.
- **Binding `logId`, chain id and address as well.** Refuted as a
  vulnerability; out of scope, not precluded.
- **A compatibility mode accepting unsigned-size receipts.** Would keep the
  keyless substitution reachable on any instance that enabled it. Rejected
  (D6).

## References

- FOR-568 (internal tracker) — the finding, the reopening of 2026-09-19,
  the cross-log replay refutation, and the 2026-09-20 decisions.
- plan-2609-10-signed-checkpoint-size (internal devdocs) and its
  decisions.md, which this record supersedes as the authoritative text.
- univocity [PR #42](https://github.com/forestrie/univocity/pull/42)
  (`src/algorithms/consistentRoots.sol`, `consistentRootsForSizes`);
  [PR #43](https://github.com/forestrie/univocity/pull/43) (signed size and
  header parsing); go-merklelog [PR #11](https://github.com/forestrie/go-merklelog/pull/11);
  arbor [PR #102](https://github.com/forestrie/arbor/pull/102); canopy
  [PR #255](https://github.com/forestrie/canopy/pull/255).
- The 2026-09-19 slice 02 and 2026-09-20 PR #43 adversarial reviews. Their
  public trace is the review discussion on arbor #102 and univocity #43
  and the summary comments on FOR-568 (internal); the full reports are held
  in the owner's review folder outside git.
- [merkle-mountain-range-proofs PR #1](https://github.com/robinbryce/merkle-mountain-range-proofs/pull/1)
  (`consistent_roots_for_sizes`).
- RFC 9942 (COSE Receipts) §4.4; RFC 9943 (SCITT) on CWT Claims in
  receipts; RFC 8949 §4.2.1 (core deterministic encoding).
- [draft-bryce-cose-receipts-mmr-profile](https://github.com/robinbryce/draft-bryce-cose-receipts-mmr-profile)
  — "COSE Receipt of Consistency", "Verifying the Receipt of consistency",
  "Security Considerations", "IANA Considerations".
