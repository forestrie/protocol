# Forestrie receipt trust model

**Status:** LIVE (promoted 2026-08-30 from `forestrie-cli/TRUST-MODEL.md`,
where it was written by plan-2607-33 (private, cited by name)
as a repo-local doc. It is cited as normative by **three rules-of-the-road
files** — `platform.md` (header and P3), `univocity.md` (U1) — which is the
whole of the case for moving it: a document the guardrail set cites is a
platform document, and devdocs owns those. plan-2607-33 sited it in
forestrie-cli and said it should become an **ARC** if it ever became a durable
architecture citation; it is sited under `protocol/` instead, because that
directory is not swept into `archive/YYMM/` at month end and an ARC would be.
forestrie-cli keeps a stub redirect.)

> **Substantive edits made during promotion**, beyond adding question 4 —
> disclosed because this is no longer a verbatim port:
> - Question 1 gained the claim that non-equivocation is **structural**, with
>   no dependence on an honest majority of monitors (rules-of-the-road P4).
> - Question 2 gained a paragraph on the operator's sealing-key custody,
>   re-verified against arbor source for this document (see the note there).
> - Three sections are new: question 4, the vocabulary note, and open
>   questions.
> - Nothing was removed. The `--allow-new-signer` rationale and the
>   plan-2607-24 provenance were dropped in the first draft and have been
>   restored.
**Date:** 2026-08-30
**Audience:** relying parties, monitors, assessors, and anyone deciding what a
Forestrie receipt lets them conclude without trusting the log operator.
**Related:** protocol/README.md (private, cited by name) (internal index and
implementation status), [ADR-0065](../decisions/adr-0065-endorsed-session-key-admission.md)
(§4 — the attribution question), ADR-0045 (offline verify contract, layers
A–C), ADR-0046 (the checkpoint *is* a consistency receipt), ADR-0056
(consistency proof spans the massif entry boundary), rules-of-the-road
P2/P3/P4.

> **Anchors are preserved from the original.** The per-question headings keep
> their wording, and `## Freshen and the attestor` keeps its exact text
> because `forestrie-cli/README.md` deep-links
> `TRUST-MODEL.md#freshen-and-the-attestor` — the anchor lives on *this*
> document, and the stub left behind forwards to it.
>
> One anchor did change: `#the-three-questions` is now
> `#the-four-questions`. Nothing outside the archive linked to it.
>
> The only other citations are two plain-text "Sources:" notes in a single
> internal onboarding deck. They are not links and
> carry no anchors, so they were never a constraint — an earlier draft of
> this block overstated them as "two product decks" that deep-link here.

## Summary

A receipt is a COSE proof that **a leaf is included in a transparency log's
sealed state**. A relying party may care about up to four *independent*
questions about that state. Keeping them apart is the whole model — most
confusion comes from collapsing them into one "the receipt is valid".

Three of those questions concern the **log**: is the history un-forked, who
sealed it, and is the log authorised. The fourth concerns the **leaf**: who was
authorised to sign this particular entry, and can that be checked from public
bytes alone. The fourth question is newer than the other three and is what the
passkey/WebAuthn work added.

## The four questions

### 1. Split-view consistency — *is this a single, un-forked history?*

Answered by the **accumulator** (the log's peak set). Recompute the leaf's
inclusion path to a peak and match it against a *trusted* accumulator. Because
every published accumulator is consistency-gated forward (each is a committed
prefix of every later one — ADR-0056), matching one proves the log has not
forked or rewritten history under you.

This property is **independent of currency.** Any accumulator is a genuine,
non-equivocal commitment up to its own tree size, so an older one is not "less
valid" — staleness only limits *coverage* (whether the snapshot reaches the leaf,
and how much newer history it attests), never the validity of what it does cover.
"Freshness" — *is this the latest accumulator* — is therefore a weaker, separate
axis that bears only on coverage; do not collapse it into split-view. Split-view
is the load-bearing property here; currency is at most the `--rpc-url` "as of
now" delta below.

Trusted-accumulator sources, in ascending currency:

- `--known-accumulator` — a cached, auditable chain read (`fetch-accumulator`).
- `--rpc-url` — a live read; same guarantee plus "as of now".

Never source the accumulator unauthenticated from the log operator's own tile
store — that re-internalises the operator trust this anchor exists to remove.

**Why the operator cannot defeat this.** Non-equivocation is structural, not
observational: the contract refuses to anchor a checkpoint inconsistent with
what it already holds. Security does not depend on a live honest majority of
monitors watching for divergence (rules-of-the-road P4).

### 2. Sealing attestation — *who sealed this state?*

The checkpoint signer's signature over the accumulator: the `.sth`'s pre-signed
peak receipts (COSE label `-65931`) and its owner→sealer delegation cert (label
`1000`). It identifies **the individual log checkpoint signer**, and nothing
finer — the log authorises a *set* of sealers (see below), it does not rank them.

This signature is **load-bearing only when you do not already hold the
accumulator from a trusted source.** At the accumulator rung you have
explicitly chosen to trust the chain-read state over any signature, so *which*
authorised sealer signed is, by your own choice, irrelevant — the signature is
**vestigial there.** It still matters at the signature rungs below, where verify
checks it chains to the owner.

**What the operator holds here.** The sealing key is the one hot-path private
key the Forestrie operator does hold. Stated precisely, because the loose
version is misleading:

- **No long-lived private key is persisted at rest.** That is the property.
- The key is **not** merely ephemeral-and-lost. It is HKDF-derived
  deterministically from a KMS-held seed, keyed by `(epoch, index)`, so the
  *same* key re-derives after a restart or pod churn rather than being
  discarded. That is deliberate: certificates outlive restarts without
  needing an on-demand signer round trip.
- **Scope comes from the certificate, not the key.** The lease certificate
  binds one log, one MMR range and an expiry, and it exists only because the
  log's root key signed it.

So the bound on a compromised sealer is the *lease*, not the key's lifetime:
it can sign within an unexpired lease for the log and range that lease names,
and cannot mint authority for any other key or log. A compromise is
neutralised definitively only by the owner rotating their root and
re-delegating.

*(An earlier draft of this document said the key was "generated in-process…
discarded on restart", carried over from ARC-0022. That predates the
delegation-in-advance work; re-verified against arbor's derivation code for
this revision.)*

### 3. Authority — *is this log authorised, back to the genesis / bootstrap key?*

Answered by **the grants and their inclusion proofs** — the grant hierarchy, in
which each log's authority *is* a receipted, provable inclusion in its parent
log — **not** by the checkpoint signature, and **not** by a per-log genesis
document.

> **`genesis.cbor` is not a per-log artifact.** It is the **univocity-instance
> registration document**: it records the instance's bootstrap/root owner key —
> the key bound into the `ImmutableUnivocity` contract at deploy. There is **one
> per instance (the root log)**, not one per log. So `--genesis` directly roots a
> receipt whose signer chains to that root owner (the root log, or a delegation
> *directly* under it); it does **not**, by itself, root an arbitrary child log.
> Reaching genesis from a child log means walking the grant hierarchy (below).

To establish a child log's authority you follow its grant to its parent, that
grant's inclusion proof, and so on up to the bootstrap key — the "grant-chain
walk". Three ways to obtain that, strongest first:

- **On-chain (chain trust) — the strong, available path.** The contract already
  did the walk at publish, so reading the accumulator from chain
  (`--known-accumulator` / `--rpc-url`) inherits it (see below). No off-chain
  walk needed.
- **Off-chain grant-chain walk** from the grant records + their inclusion proofs
  (rooted at `genesis.cbor`). This is a genuine tile-/receipt-level proof — but
  it is **not yet implemented** (the open verify rung); do not assume it today.
- **Operator storage / APIs surfacing the chain — forestrie-operator trust.**
  Convenient, but re-internalises the very operator trust the log system exists
  to remove; not a trust source.

Crucially, **the contract discharges this at publish.** `publishCheckpoint`
verifies, on-chain:

- the checkpoint is signed by the log's root key **or a valid delegation** of it
  (sealing authority, question 2), and
- the publisher presented a grant whose **inclusion** in the parent log the
  contract re-checks against the parent's on-chain accumulator, within the
  grant's size bounds — link by link, transitively to the bootstrap key bound
  into the contract at deploy.

So **any state read from the chain** (an accumulator snapshot, `publishCheckpoint`
calldata, a `CheckpointPublished` event) inherits the contract's sealing *and*
authority checks for free. That is *why* the accumulator rung needs no genesis
walk: the authority question was already answered, on-chain, when the state was
published.

### 4. Attribution — *who was authorised to sign this leaf?*

The three questions above authenticate the **log and its state**. None of them
says anything about **who signed an individual entry**. That is a separate
question, and for a self-custodied user log it is the one the owner cares about
most: *this record is mine, and only a key I control could have written it.*

Nothing on the chain inspects a leaf signer. The sequencer content-hashes
leaves, the sealer verifies delegation leases, the publisher lifts proofs, and
the contract verifies the root and the delegation. **Admission at the SCRAPI
edge is the only enforcement point for who may sign a leaf**, for every custody
shape (ADR-0065 §1). A design that asks any other component to be authoritative
for the leaf signer fails open for every client that is not that component,
because the SCRAPI is permissionless and the grant is the only credential.

For a plainly-rooted log the answer is direct: the leaf's `kid` and signature
must match the signer the grant binds (`grantData`).

For a **passkey-rooted** log the owner's root key is a WebAuthn authenticator,
which cannot sign silently — every assertion costs a user gesture. So the root
endorses a per-session key that signs entries silently, and the chain from root
to leaf is:

```
logRootKey(logId) on-chain  (= grantData, committed in the parent auth log)
  → endorsement (inside the leaf bytes): verify under the root,
    user verification per the grant's policy flag, validity window from
    the payload
    → session public key
      → leaf: kid == session key, signature under the session key
        → receipt: leaf bytes hash to the receipted index (inclusion),
          receipted idtimestamp within the endorsement's validity window
```

**The endorsement travels inside the leaf it authorises.** This is the design's
load-bearing choice, and it is an auditability choice rather than a
cryptographic one. An endorsement held only in operator storage, or served from
an export endpoint, would be cryptographically sound and still useless to an
independent verifier: the one artifact linking the log's on-chain root to every
entry's signer would be a thing you had to *ask the operator for*. Carried in
the leaf's unprotected header it is committed by the leaf's own content hash,
so it costs nothing extra to prove and cannot go missing.

Tampering is closed in both directions. Editing the endorsement changes the
content hash, so inclusion fails. Substituting a different valid endorsement
changes the session key, so the leaf signature fails.

The window matters because it retires the otherwise-unbounded life of a
superseded session key: once the window lapses the endorsement stops being
admissible, regardless of who holds it, with no revocation list and no per-log
state anywhere. Online, admission checks the window against its own clock with
a small skew tolerance; **offline, the authoritative check is against the
receipted idtimestamp**, which is time-ordered, monotonic, and carried by every
receipt — so the window is checkable from public artifacts alone.

Wire-level detail — header labels, payload shape, the exact failure
vocabulary — is in
[leaf-admission-and-session-endorsement.md](./leaf-admission-and-session-endorsement.md).

## The verify trust ladder, mapped onto the questions

`verify` offers four named anchors. They are not a single "more vs less trust"
line — each answers a different subset:

| Anchor | Split-view (1) | Sealing (2) | Authority (3) |
|---|---|---|---|
| `--known-log-key` | — | signature under a caller-known owner key | key→log binding **asserted** (out-of-band), not proven |
| `--genesis` | — | signature chains to the **root** owner (root log / direct delegation) | root only; a child log needs the grant-chain walk (still open) |
| `--known-accumulator` | covered entries root into a trusted chain read | (not checked — subsumed by the chain) | (not checked — discharged by the contract at publish) |
| `--rpc-url` | as `--known-accumulator`, live | (subsumed) | (discharged at publish) |

The signature rungs (`--known-log-key`, `--genesis`) answer question 2 offline by
checking the signature — and question 3 only as far as the cert reaches
(`--genesis` covers the root log / a direct delegation; a deeper child's
question 3 is the grant-chain walk, still open). The accumulator rungs
(`--known-accumulator`, `--rpc-url`) answer question 1 and let the contract's
publish-time checks stand in for 2 and 3 for *any* log — which is why, in
practice, the on-chain path is the strong authority anchor for an arbitrary
log, not `genesis.cbor`. A receipt never expires and the anchor never needs to
be current — only trusted.

**Question 4 is orthogonal to this ladder.** Attribution is checked from the
leaf bytes and the log's root key, not from a verify anchor, so it composes with
any rung above. A verifier can establish that an entry was signed by a key the
log's owner endorsed while holding no opinion at all about which sealer sealed
the state it sits in.

## Freshen and the attestor

Freshen (`resolve-receipt --receipt <stale> + a tile-free source`) re-anchors a
stale receipt to the current sealed state without tiles. A receipt goes stale
when log growth *buries* the peak it commits to; freshen extends the leaf's
inclusion path from its old peak up to the current accumulator.

```
 original receipt, log size 3 (2 leaves)        grown log, size 7 (4 leaves)
                                                 the size-3 peak (node 2) is buried

         2   <- peak;  accumulator = [2]                    6   <- peak;  accumulator = [6]
        / \                                               / \
       0   1                                             2   5   <- climb node, from the
           ^                                            / \ / \      3->7 consistency proof
           leaf, mmrIndex 1                            0  1 3  4     (or the retained chain)
       old path = [0]                                     ^
       root = H(0,1) = node 2                             leaf, mmrIndex 1  (same leaf)
                                                       fresh path = [0, 5]
                                                       root = H( H(0,1), 5 ) = node 6
```

`old path [0]` is a **prefix** of `fresh path [0,5]` (MMR prefix-composability),
so freshen only appends the climb node. It then attaches `(leaf@1, [0,5])` at
COSE header `396` to the **latest checkpoint's** pre-signed peak receipt for
node 6. The questions attach to that one re-emitted receipt like this:

```
freshened receipt, leaf@1 @ size 7
├─ inclusion path [0,5] --recompute--> node 6
│    SPLIT-VIEW (1): node 6 == trusted size-7 accumulator[0]
│                    (freshen self-check vs the .sth; bound by --known-accumulator / --rpc-url)
│
├─ peak receipt over node 6, signed by the size-7 sealer
│    SEALING   (2) : "an authorised sealer sealed size 7"
│                    CHECKED at verify's signature rung (--genesis / --known-log-key)
│                    IGNORED at the accumulator rung        <- vestigial here only
│
├─ label-1000 delegation cert  (owner --> sealer)
│    AUTHORITY (3) : owner/grant chain to the bootstrap key
│                    enforced by the contract at publishCheckpoint;
│                    re-provable via grants + their inclusion proofs
│
└─ the leaf bytes themselves (unchanged by freshen)
     ATTRIBUTION (4): kid + signature, and for a passkey-rooted log the
                      endorsement carried in the leaf's own unprotected header
```

Freshen does not touch the leaf bytes, so **question 4 is unaffected by
freshening** — an attribution check made against the original receipt holds
against the freshened one, because it was never a property of the receipt in
the first place.

### Why the `.sth` is still required — and why the signer is not a choice

Freshen produces a **new attestation of the current accumulator**, so the only
signature it can legitimately carry is one over a checkpoint at the current size
— i.e. the latest checkpoint's signer. Attaching any other signer's signature
would be forgery. Hence the `.sth` is **load-bearing for emission**: it supplies
the pre-signed peak receipts and the delegation cert that make the freshened
receipt a native, signature-rung-verifiable receipt. "Vestigial" (question 2)
describes the signature *at accumulator-rung verification*, never the freshen
build step.

(For the calldata source the `.sth` must be supplied separately: calldata
carries a *checkpoint-level* COSE signature over the whole accumulator, not the
per-peak receipts label `-65931` that the emission format needs.)

### Attestor rotation is not a downgrade

If the sealer rotated (`K1 → K2`) between the original receipt's checkpoint and
the fresh `.sth`, the freshened receipt is sealed under `K2`. This is **not** a
downgrade attack, even though `K2` may be a less-trusted operational identity
than `K1`:

- The log authorises a *set* of sealers (root + its delegations) and the
  contract enforces **membership** at publish. It does not **rank** members —
  `K1` and `K2` are equally authorised. Any preference between them is
  out-of-band relying-party policy, which the log system never promised to
  uphold.
- A relying party who cares about the specific signer is, by definition, at a
  **signature rung**, where verify checks it: an *unauthorised* signer fails
  closed; a *rotated-but-authorised* one (the routine case) passes — correctly.
- A relying party at the **accumulator rung** has chosen not to check the
  signature at all, so the signer identity cannot matter to them.

There is no coherent configuration where the identity distinction both matters
and is not already handled. The mirror case (an *upgrade* to a more-trusted
signer) is symmetric and equally a non-issue. Freshen therefore emits under the
latest checkpoint's signer and does nothing further — there is **no
signer-change gate** (an earlier `--allow-new-signer` sketch was removed for
exactly this reason: it would have asked the relying party to approve a
distinction the log never promised to uphold).

## "Known-accumulator-verifiable but not genesis-verifiable" is not a gap

A receipt anchored purely at the accumulator rung authenticates the **state**
(the leaf roots into the genuine canonical accumulator) but says nothing, by
itself, about **signer provenance** (that the sealer chains to genesis). These
are the two *different* questions 1 and 2/3 — not a strong check and a weak
one. The state question is answered by the accumulator; the provenance question,
if you want it, is answered at a signature rung or was already discharged by the
contract at publish. Separating them is the design, not a shortfall.

## A note on vocabulary: monitor, assessor, auditor

The wider transparency-log community uses **auditor** broadly, for any party
that independently checks a log's claims — and in Certificate Transparency
specifically for the role that verifies inclusion and consistency proofs.

Forestrie's own documents deliberately use two narrower terms instead, because
the generic one hides a distinction that matters here:

- **Monitor** — a party that watches a log for unexpected entries or for
  divergence. In Forestrie a monitor is a *convenience*, not a security
  dependency: non-equivocation is enforced by the contract at publish, not by a
  quorum of watchers (P4).
- **Assessor** — a party whose standing is itself recorded and staked, in the
  incentivisation and reputation model. This is design direction, not shipped
  behaviour.

Where an external reader would say "auditor", this corpus means "anyone
performing the verification described above" — which, given the properties, is
any holder of the bytes. No relationship with the operator, and no
registration, is required to be that party.

## Open questions

- **The off-chain grant-chain walk is unimplemented.** Question 3 is answerable
  today either on-chain, or off-chain only as far as a certificate reaches. The
  fully off-chain walk from grant records and their inclusion proofs remains
  the open verify rung.
- **Succinct absence is not available.** Non-presence is provable against a
  replicated log; a *succinct* absence proof needs an authenticated secondary
  index, because the exclusion trie's root is not currently anchored. Do not
  design against succinct absence as if it exists (P13).
- **ADR-0045's status is still PROPOSED** although rules-of-the-road P2 cites
  it as the authority for the offline-verify contract. The contract is
  implemented and enforced; the status label lags.

## References

- protocol/README.md — internal index, implementation status,
  and the section-to-source map for everything above.
- [trust-boundaries-and-operator-powers.md](./trust-boundaries-and-operator-powers.md)
  — what each party holds, and what a compromised one can and cannot do.
- [key-custody-and-choice.md](./key-custody-and-choice.md) — the custody
  options behind question 4, and how to leave.
- [checkpoints-and-receipts.md](./checkpoints-and-receipts.md) — the receipt
  and checkpoint wire formats.
- [leaf-admission-and-session-endorsement.md](./leaf-admission-and-session-endorsement.md)
  — the attribution chain at wire level.
- ADR-0046 (the checkpoint *is* a consistency receipt), ADR-0056 (consistency
  proof spans the massif entry boundary), ADR-0045 (offline verify contract),
  [ADR-0065](../decisions/adr-0065-endorsed-session-key-admission.md) (attribution).
- plan-2607-24 (private, cited by name)
  — the four named verify trust anchors this document maps onto the questions
  (FOR-297); the provenance of the ladder above.
- plan-2607-33
  — where this document was originally written, and the three-way split
  between the conceptual model, the per-command recipes, and the CLI help.
