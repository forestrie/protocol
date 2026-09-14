# Forestrie receipt trust model

**Status:** LIVE
**Date:** 2026-08-30
**Audience:** relying parties, monitors, assessors, and anyone deciding what a
Forestrie receipt lets them conclude without trusting the log operator.
**Related:**
[ADR-0045](../decisions/adr-0045-receipt-verify-offline-contract.md) (the
offline verify contract, layers A–C),
[ADR-0065](../decisions/adr-0065-endorsed-session-key-admission.md) (§4 — the
attribution question), the platform invariants
[P2, P3 and P4](../rules/platform.md), and [glossary.md](../glossary.md) for the
terms used below.

## Summary

A receipt is a COSE proof that **a leaf is included in a transparency log's
sealed state**. A relying party may care about up to four *independent*
questions about that state. Keeping them apart is the model: collapsing them
into a single "the receipt is valid" discards the distinction the receipt is
evidence for.

Three of those questions concern the **log**: is the history un-forked, who
sealed it, and is the log authorised. The fourth concerns the **leaf**: who was
authorised to sign this particular entry, and can that be checked from public
bytes alone. The fourth question is newer than the other three and is what the
passkey/WebAuthn work added.

## The four questions

### 1. Split-view consistency — *is this a single, un-forked history?*

Answered by the **accumulator** (the log's peak set). Recompute the leaf's
inclusion path to a peak and match it against a *trusted* accumulator. Because
every published accumulator is consistency-gated forward — each is a committed
prefix of every later one, and the consistency proof spans the massif entry
boundary — matching one proves the log has not forked or rewritten history under
you.

This property is **independent of currency.** Any accumulator is a genuine,
non-equivocal commitment up to its own tree size, so an older one is not "less
valid" — staleness only limits *coverage* (whether the snapshot reaches the leaf,
and how much newer history it attests), never the validity of what it does cover.
"Freshness" — *is this the latest accumulator* — is a separate axis that bears
on coverage alone; do not collapse it into split-view. Split-view is the
load-bearing property here; currency is at most the `--rpc-url` "as of now"
delta below.

Two sources supply a trusted accumulator:

- `--known-accumulator` — a cached, auditable chain read (`fetch-accumulator`).
- `--rpc-url` — a live read; the same guarantee, plus "as of now".

Never source the accumulator unauthenticated from the log operator's own tile
store — that re-internalises the operator trust an accumulator root exists to
remove.

**Why the operator cannot defeat this.** Non-equivocation is structural, not
observational: the contract refuses to anchor a checkpoint inconsistent with
what it already holds. Security does not depend on a live honest majority of
monitors watching for divergence ([platform invariant P4](../rules/platform.md)).

### 2. Sealing attestation — *who sealed this state?*

The checkpoint signer's signature over the accumulator: the `.sth`'s pre-signed
peak receipts (COSE label `-65931`) and its owner→sealer delegation cert (label
`1000`). It identifies **the individual log checkpoint signer**, and nothing
finer — the log authorises a *set* of sealers (see below), it does not rank them.

This signature is **load-bearing only when you do not already hold the
accumulator from a trusted source.** Under an accumulator root you have
explicitly chosen to trust the chain-read state over any signature, so *which*
authorised sealer signed is, by your own choice, irrelevant — the signature is
**vestigial there.** It still matters under a signature root, where verify
checks that it chains to the owner.

**What the operator holds here.** The sealing key is the one hot-path private
key the Forestrie operator does hold. Precisely:

- **No long-lived private key is persisted at rest.** That is the property,
  and the custody boundary is the KMS.
- The key is **not** merely ephemeral-and-lost. It is derived deterministically
  with **HKDF-SHA256** from a seed the operator's KMS re-derives at boot, keyed
  by `(epoch, index)`, so the *same* key re-derives after a restart or pod
  churn rather than being discarded. That is deliberate: certificates outlive
  restarts without needing an on-demand signer round trip. The seed itself is
  never written to a secret store or to disk — see
  [glossary.md](../glossary.md) ("standing delegate key").
- **Scope comes from the certificate, not the key.** The lease certificate
  binds one log, one MMR range and an expiry, and it exists only because the
  log's root key signed it.

So the bound on a compromised sealer is the *lease*, not the key's lifetime:
it can sign within an unexpired lease for the log and range that lease names,
and cannot mint authority for any other key or log. A compromise is
neutralised definitively only by the owner rotating their root and
re-delegating.

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
walk". Three ways to obtain it:

- **On-chain (chain trust) — the path available today.** The contract already
  did the walk at publish, so reading the accumulator from chain
  (`--known-accumulator` / `--rpc-url`) inherits it (see below). No off-chain
  walk needed.
- **Off-chain grant-chain walk** from the grant records + their inclusion proofs
  (rooted at `genesis.cbor`). This is a genuine tile-/receipt-level proof — but
  it is **not yet implemented**; do not assume it today.
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
authority checks for free. That is *why* an accumulator root needs no genesis
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
shape ([ADR-0065](../decisions/adr-0065-endorsed-session-key-admission.md) §1).
A design that asks any other component to be authoritative
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

**The endorsement travels inside the leaf it authorises**, in the leaf's
unprotected header, so it is committed by the leaf's own content hash. That is
an auditability choice rather than a cryptographic one: it keeps the single
artifact linking the log's on-chain root to every entry's signer out of operator
storage, where an independent verifier would have to ask for it. Tampering is
closed in both directions — editing the endorsement changes the content hash, so
inclusion fails; substituting a different valid endorsement changes the session
key, so the leaf signature fails. The reasoning, and the alternatives it was
chosen over, are in
[leaf-admission-and-session-endorsement.md](./leaf-admission-and-session-endorsement.md)
§2.

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
## The trust roots, mapped onto the questions

`verify` does not offer degrees of verification. It offers four **trust roots**,
and the caller says which one they hold. Two are **signature roots**: they rest
on a key, and the operator's signature over the sealed state is checked locally
against it. Two are **accumulator roots**: they match the peak recomputed from
the leaf and its inclusion path against an accumulator the operator does not
control.

The roots are alternatives, not an ordering. Each answers a different subset of
the four questions, and which root is right depends on what the caller already
holds and on what they need to know. A result must therefore say which root it
used and which questions that root did not answer: "valid", on its own, names no
question.

| Trust root | Split-view (1) | Sealing (2) | Authority (3) | Attribution (4) |
|---|---|---|---|---|
| **`--genesis`** — signature root: the forest's genesis document | **Not answered.** A signature root sees only the state the receipt itself carries | **Answered** locally: the signature chains to the root owner key recorded in genesis | **Answered for the root log or a direct delegation** under it; a deeper child log needs the grant-chain walk, which is unimplemented | **Answered** from the leaf bytes and the log's root key, independently of the root in use |
| **`--known-log-key`** — signature root: an owner key the caller holds out of band | **Not answered**, as above | **Answered** locally: the signature verifies under the caller-known owner key | **Asserted, not proven.** The key-to-log binding rests on the channel the key arrived on | **Answered**, as above |
| **`--known-accumulator`** — accumulator root: a snapshot of the log's peaks from an authenticated chain read | **Answered.** The recomputed peak is matched against a state the operator does not control | **Not checked locally.** Implied by the match: the contract refuses to anchor a checkpoint whose signature does not verify | **Not checked locally.** Discharged by the contract at publish, for any log — see question 3 | **Answered**, as above |
| **checkpoint chain** — accumulator root: a retained chain of signed checkpoints, with `--genesis` or a known log key for its base | **Answered** against the caller's own retention: each link's signed consistency proof commits the earlier accumulator forward, so a match at any link holds | **Answered** locally: each link's signature is checked over the accumulator folded from the previous link | **As far as the base root reaches** — the chain inherits the answer of whichever signature root anchors its first link | **Answered**, as above |

`--rpc-url` is not a fifth root. It is a live chain read supplying the
`--known-accumulator` root: the same guarantee, plus "as of now".

The signature roots answer question 2 offline by checking the signature, and
question 3 only as far as the certificate reaches. The accumulator roots answer
question 1, and let the contract's publish-time checks stand in for questions 2
and 3 for *any* log — which is why, for an arbitrary child log, the on-chain
path and not `genesis.cbor` is the route to an authority answer today. A receipt
never expires and a root never needs to be current, only trusted.

A caller who wants both a local signature check and a split-view answer runs the
same bytes under one root of each kind; the arithmetic does not change between
them. Verifying under one root and failing under another is not a contradiction:
the two answer different questions.

**Question 4 composes with every root.** Attribution is checked from the leaf
bytes and the log's root key, not from the root a verifier was given, so a
verifier can establish that an entry was signed by a key the log's owner
endorsed while holding no opinion at all about which sealer sealed the state it
sits in.

The checkpoint-chain root is the fully offline route for a receipt whose peak
later log growth has buried; the retained chain that root consumes is the same
material the freshen path below uses, and the golden set under
[`vectors/golden/burial/`](../vectors/golden/burial/) is a worked example.

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
│                    CHECKED under a signature root (--genesis / --known-log-key)
│                    NOT CHECKED under an accumulator root  <- vestigial there only
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
receipt a native, signature-root-verifiable receipt. "Vestigial" (question 2)
describes the signature *under an accumulator root*, never the freshen build
step.

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
- A relying party who cares about the specific signer is, by definition, under a
  **signature root**, where verify checks it: an *unauthorised* signer fails
  closed; a *rotated-but-authorised* one (the routine case) passes — correctly.
- A relying party under an **accumulator root** has chosen not to check the
  signature at all, so the signer identity cannot matter to them.

There is no coherent configuration where the identity distinction both matters
and is not already handled. The mirror case (an *upgrade* to a more-trusted
signer) is symmetric and equally a non-issue. Freshen therefore emits under the
latest checkpoint's signer and does nothing further — there is **no
signer-change gate** (an earlier `--allow-new-signer` sketch was removed for
exactly this reason: it would have asked the relying party to approve a
distinction the log never promised to uphold).

## "Known-accumulator-verifiable but not genesis-verifiable" is not a gap

A receipt verified under an accumulator root authenticates the **state** (the
leaf roots into the genuine canonical accumulator) but says nothing, by itself,
about **signer provenance** (that the sealer chains to genesis). These are the
two *different* questions 1 and 2/3, not two degrees of one check. The state
question is answered by the accumulator; the provenance question, if you want
it, is answered under a signature root, or was already discharged by the
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
  quorum of watchers ([platform invariant P4](../rules/platform.md)).
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
  open.
- **Succinct absence is not available.** Non-presence is provable against a
  replicated log; the succinct form is not. Stated in full in
  [trust-boundaries-and-operator-powers.md](./trust-boundaries-and-operator-powers.md)
  §6.

## References

- [trust-boundaries-and-operator-powers.md](./trust-boundaries-and-operator-powers.md)
  — what each party holds, and what a compromised one can and cannot do.
- [key-custody-and-choice.md](./key-custody-and-choice.md) — the custody
  options behind question 4, and how to leave.
- [checkpoints-and-receipts.md](./checkpoints-and-receipts.md) — the receipt and
  checkpoint wire formats, and why the sealed checkpoint *is* a consistency
  receipt.
- [leaf-admission-and-session-endorsement.md](./leaf-admission-and-session-endorsement.md)
  — the attribution chain at wire level.
- [log-authority-and-grants.md](./log-authority-and-grants.md) — the grant
  hierarchy question 3 walks.
- [ADR-0045](../decisions/adr-0045-receipt-verify-offline-contract.md) — the
  offline verify contract, layers A–C.
- [ADR-0065](../decisions/adr-0065-endorsed-session-key-admission.md) —
  attribution, and the admission rules that enforce it.
- [rules/platform.md](../rules/platform.md) — the platform invariants that cite
  this document.
