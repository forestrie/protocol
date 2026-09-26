# Forestrie protocol glossary

Shared domain language for Forestrie transparency logs and the contract that
anchors them. Terms are defined once here; the documents under
[`spec/`](spec/) link to this file rather than restating them. Operator,
hosting and product vocabulary is not protocol and is not defined here.

## Log structure

**MMR (Merkle Mountain Range)**:
The append-only tree a Forestrie log is. Entries are leaves; the tree is never
rewritten, only extended. The receipt and proof profile is
[draft-bryce-cose-receipts-mmr-profile](https://datatracker.ietf.org/doc/draft-bryce-cose-receipts-mmr-profile/).
_Avoid_: "the Merkle root" — an MMR has a set of peaks, not one root.

**Entry (leaf)**:
One record in a log: the content hash the sequencer commits, bound to an
idtimestamp. "Entry" is the record; "leaf" is its position in the MMR. A
statement entry commits the exact registered COSE bytes; a grant entry commits
the grant.
_Avoid_: "record" or "event" for the same thing.

**Accumulator (peak set)**:
The set of MMR peaks at a given log size: the log's committed state at that
size. Every published accumulator that extends the anchored state is a
committed prefix of every later one, so matching an old one is a narrower
check, never a lesser one. A checkpoint's detached payload is exactly these
peaks, concatenated raw.
_Avoid_: "the log root"; treating an older accumulator as less valid.

**Peak**:
One of the roots of the perfect subtrees an MMR decomposes into at a given size.
An inclusion path runs from a leaf up to whichever peak covers it.

**Massif**:
The fixed-size block the log's storage and checkpointing are organised in
(roughly 16k entries). Checkpoint bases are massif entry boundaries, so a
chain of consistency proofs verifies boundary to boundary. A complete massif is
immutable and cacheable; the head massif is not.

**Tile**:
A stored block of MMR nodes that a verifier or receipt builder reads to
compute inclusion paths; a massif's node data is served as tiles. "Tile-free"
means a path is obtained without them, from a checkpoint's pre-signed
material.

**Buried peak**:
A peak a receipt commits to that later log growth has replaced, so the receipt
no longer matches the current accumulator. The receipt is still valid; reaching
the current state needs a freshen, or a retained checkpoint chain.

**Freshen**:
Re-anchoring a stale receipt to the current sealed state by extending its
inclusion path from the buried peak to the current accumulator, without tiles.
See [receipt-trust-model.md](spec/receipt-trust-model.md).

**Trust root**:
The thing a caller already holds and evaluates a receipt against: the forest
genesis document, a known log key, a known accumulator, or a retained
checkpoint chain. The four are alternatives, not levels — each answers a
different subset of the four trust questions.
_Avoid_: "verification level"; ranking the roots by strength.

**idtimestamp**:
The 8-byte big-endian identifier the sequencer assigns each entry, packing a
time component, a sequence number and a device or shard id. Monotone and
time-ordered; `unixMs = (idtimestamp >> 24) + epoch × (2^40 − 1)`, current
epoch 1 ([checkpoints-and-receipts.md](spec/checkpoints-and-receipts.md) §5).
It is what an endorsement's validity window is checked against offline. A
receipt does not carry it; the leaf hash binds it.
_Avoid_: deriving ordering from a signature time — only the idtimestamp orders.

**Exclusion trie**:
The authenticated index keyed on idtimestamp that would make succinct absence
provable once its root is anchored. No content-derived value can be its key.

**SCRAPI**:
The SCITT reference HTTP API a Forestrie forest exposes — `register/…` for
grants and signed statements, `logs/…` for reads. Permissionless: the grant is
the only credential, which is why admission is the sole leaf-signer enforcement
point.

**Sequencer**:
The component that assigns idtimestamps and content-hashes entries into the log.
It never inspects an entry's signer.

**Sealer**:
The component that signs a checkpoint over the accumulator, under a delegation
lease from the log's root key, or the owner's own signer when the owner seals
directly. It holds a delegated sealing key, never a log root, in the
delegated case.

## Parties

**Transparency operator**:
The party that runs the admission edge, the sequencer, the sealer and the
publisher for a forest. What it can and cannot do is the subject of
[trust-boundaries-and-operator-powers.md](spec/trust-boundaries-and-operator-powers.md).
_Avoid_: "log operator", "the operator" where the hosting operator is meant.

**Hosting operator**:
The party that onboards a log owner, hosts their client, collects payment and
routes signing requests. Holds no user root in the self-custody shapes.
_Avoid_: "payment operator", "mandate operator".

**Custodian**:
The transparency operator's component that holds KMS custody keys. See
**Custody key**.

**Coordinator (delegation coordinator)**:
The operator service that brokers delegation: it receives delegation
certificates, records which sealing keys a log may use, and holds the
hosted-wallet enable bits. It is not a trust source for any verifier.

**Upgrade admin**:
The single address that can replace the implementation of the upgradeable
contract variant. Absent from the immutable variant. See
[trust-boundaries-and-operator-powers.md](spec/trust-boundaries-and-operator-powers.md)
§4.2.

## Core identity

**Forest**:
The namespace of logs that share one bootstrap root authority log `R` and one
contract instance. SCRAPI paths use `/register/{R}/…` and `/logs/{R}/…`.
_Avoid_: deployment, project.

**Bootstrap root auth log (`R`)**:
The first authority log in a forest. Its bootstrap grant has
`ownerLogId === logId`. After on-chain bootstrap, `R` is the contract's root
log id.
_Avoid_: bootstrap log alone (conflicts with bootstrap grant or bootstrap
transaction).

**Authority log**:
A log whose entries are grants: the log named by a grant's `ownerLogId`, whose
root key signs the grants it issues. `R` is the root authority log; an
intermediate authority log holds grants its parent issued.
_Avoid_: "auth log" without saying which.

**Log ID**:
16-byte UUID — canonical off-chain identity for a transparency or authority
log. On the wire it is carried left-padded in a 32-byte field.
_Avoid_: wire log id, hex64, padded path segment.

**Forest genesis document**:
The CBOR map, written once at instance deployment, that binds `R`, the
bootstrap key, and the chain binding. Wire format in
[log-authority-and-grants.md](spec/log-authority-and-grants.md) §1.1; labels
in [label-registry.md](spec/label-registry.md) §2.3.
_Avoid_: genesis grant, on-chain genesis, "genesis.cbor", a per-log genesis.

**Chain binding**:
The pair `(chain id, contract address)` for the EIP-155 chain and the
contract instance this forest publishes to.
_Avoid_: univocity config, trust root URL.

**Univocity contract address**:
The 20-byte address of the contract instance a forest anchors to, as carried
in the genesis document.
_Avoid_: contract, univocity addr without disambiguation.

**Univocity instance**:
A deployed contract identified by its chain binding. A forest binds to exactly
one instance via its genesis document. Two variants exist: `ImutableUnivocity`,
with no admin, and `UUPSUnivocity`, with an upgrade admin.
_Avoid_: conflating the instance (contract) with a forest or a log.

**Root bootstrap grant**:
The first Forestrie-Grant on `R`; its **`grantData`** must match the forest
genesis bootstrap key (**ES256:** 64-byte `x‖y`; **KS256:** 20-byte address).
Distinct from the forest genesis document.
_Avoid_: genesis when meaning the grant.

**Log root key**:
The key a log's authority is bound to: the `grantData` of the grant that
established the log, which the contract stores as the log's root at first
checkpoint. Signs grants the log issues and sealing delegations. Fixed for the
life of the log.
_Avoid_: "logRootKey" in prose; "root authority".

**Statement signer binding**:
Bytes from a grant's committed **`grantData`** that the register-statement COSE
**`kid`** must equal, derived per root algorithm as specified in
[log-authority-and-grants.md](spec/log-authority-and-grants.md) §2.2. Verified
separately from the grant envelope signer.
_Avoid_: conflating statement `kid` with the authority key that signed the grant
envelope.

**Univocity root bootstrap**:
The on-chain transaction that sets the root log id on the contract. Runs after
the genesis document is written and the root bootstrap grant is sealed.
_Avoid_: forest genesis.

**Forest uniqueness (`logId → R`)**:
Each subject `logId` belongs to exactly one forest `R`, enforced at
registration.

## Keys and grants

**Owner root key vs target root key**:
A creation grant is signed by the **owner authority log's root key**
(`grantData_O`) and establishes the **target log's root key** (`grantData_T`).
They coincide only at the root (`T = O = R`). Child-auth and child-data
envelopes verify against the **owner's** key, not their own (no self-signing).
The grant **envelope** for `T` verifies against `grantData_O`; the
**delegation/checkpoint** for `T` verifies against `grantData_T`.
_Avoid_: verifying a child grant against its own `grantData`; "the grant's own
key" (self-signing) for non-root links.

**Grant issuance vs checkpoint delegation**:
Grant issuance is a **root-key, non-delegatable** operation. The delegation
profile (`forestrie.univocity.delegation.v1`) is **checkpoint-signing only** —
it never authorizes issuing grants.
_Avoid_: conflating delegation certs with grant issuance authority.

**Lease**:
What a delegation confers: the right to seal one log within one inclusive MMR
range. The certificate adds an expiry: the sealer honours it by its own
clock, and an off-chain verifier checks it against the entry's idtimestamp,
never its own clock, so a lapsed certificate still verifies every entry
sequenced within it. The contract checks only the log and the range, so
on-chain a lease runs until the log grows past the range.
_Avoid_: implying a lease can be revoked or shortened.

**Delegation certificate**:
COSE_Sign1 object signed by the log's root key authorizing a delegated sealing
key for a lease. Verified against the log's root key by the coordinator at
submit and by any offline holder. Distinct from the on-chain delegation proof
and from custody keys.
_Avoid_: "material", "delegation material"; conflating with checkpoint COSE
receipts or custody private keys.

**Standing delegate key**:
A sealer-held checkpoint-signing key **shared across all logs a sealer seals**,
derived deterministically at boot from a seed the operator's KMS holds and
never persisted ([trust-boundaries-and-operator-powers.md](spec/trust-boundaries-and-operator-powers.md)
§3). Authority is per-certificate — a lease names one log and one range — so a
shared key confers nothing across logs.
_Avoid_: "the sealer's key" without a standing/ephemeral qualifier.

**Direct signing vs delegated sealing**:
**Direct signing** — the log root key signs the consistency receipt itself
(no delegation proof; on-chain verifier == root). The natural path for a
**self-hosted sealer**. **Delegated sealing** — the root key signs a
delegation certificate to a sealer-held key that signs checkpoints; the
mechanism for **operator-hosted** logs where the root holder and sealer
operator differ.
_Avoid_: treating delegation as mandatory for sealing.

**Custody key**:
A KMS key the transparency operator holds, one per custodial log id, that is
that log's root key: it signs the delegation certificate, the on-chain proof,
and any digest presented under the custodian's service token. The custodial
custody shape in [key-custody-and-choice.md](spec/key-custody-and-choice.md)
§3.5.
_Avoid_: conflating with a delegation certificate, the contract bootstrap
key, or a self-custodied root.

**Delegation lockout (threat)**:
The failure a stolen or mis-issued delegation enables: the holder seals and
anchors extensions the owner did not intend, ahead of the owner's own
sealer, so the owner's sealer finds the anchored state already past it. The
contract accepts only extensions of the anchored history, so the anchored
log is still consistent and every retained receipt still verifies; what the
owner loses is control of what gets appended and sealed until the lease's
range is exhausted. Unbounded under a standing lease (no on-chain expiry),
and not recoverable by re-rooting, because there is none.
_Avoid_: describing it as a fork or a rewrite — the contract refuses those
([trust-boundaries-and-operator-powers.md](spec/trust-boundaries-and-operator-powers.md)
§4.1).

## Checkpoints and on-chain anchoring

**Checkpoint (format v3) / consistency receipt**:
The sealed checkpoint object: a `COSE_Sign1`, tagged (CBOR tag 18) as the
sealer emits it, in the shape of a draft-bryce **Receipt of Consistency** —
protected header `{1: alg, 395: 3, -65933: tree-size-2}` signing the size
it proves to, a detached payload, one consistency proof from the massif
boundary to this seal, and (in the unprotected header)
pre-signed peak receipts and, when delegated, the on-chain delegation proof
and the certificate. It is directly publishable.
_Avoid_: "sibling proof document" (there is none); "MMRState checkpoint" (the
v2 format, removed).

**Checkpoint object (`.sth`)**:
The stored form of a checkpoint, one per massif, replaced on each re-seal.
A retained sequence of them is the checkpoint chain root.

**Detached payload (raw-concat accumulator)**:
The bytes a checkpoint signature is over: the raw concatenation of the MMR
accumulator peaks (descending height), no hashing. The contract recomputes it
from the proof and verifies the signature against it.
_Avoid_: "sha256 commitment" (an earlier form).

**Peak inclusion receipt**:
One detached-payload `COSE_Sign1` per accumulator peak, pre-signed by the
sealing key and carried in the checkpoint at `-65931`. Any holder of the
checkpoint + replicated log data can attach an inclusion proof and mint a
receipt for any entry without the signing key.
_Avoid_: conflating with the checkpoint's own consistency receipt.

**On-chain delegation proof**:
The ABI struct the contract verifies at every publish, binding the sealing key
to `(logId, mmrStart, mmrEnd)` under the root key's signature. It rides the
checkpoint at `-66535`; the publisher wires it into the `publishCheckpoint`
calldata. Distinct from the label-1000 delegation **certificate**; see
[label-registry.md](spec/label-registry.md) §2.2.
_Avoid_: reusing the label-1000 cert as the on-chain proof (they differ).

**Publisher / anchoring**:
The permissionless, gas-only submitter that reads a checkpoint object and calls
`publishCheckpoint`, advancing the contract's anchored accumulator for the log.
Authority stays with the grant/signature chain — "postmark, not gatekeeper".
The transparency operator's publisher chooses what it submits; anyone else may
submit what it withholds.

**Anchor lag**:
The number of sealed checkpoints ahead of the on-chain anchored size — the
publisher's backlog. Caught up by chaining one consistency proof per sealed
massif into a single `publishCheckpoint` call.

## Passkey custody and leaf attribution

Full treatment: [key-custody-and-choice.md](spec/key-custody-and-choice.md) and
[leaf-admission-and-session-endorsement.md](spec/leaf-admission-and-session-endorsement.md).

**Passkey root**:
A WebAuthn platform authenticator credential used as a log's root key. Under
passkey custody the ES256 `grantData` **is** the passkey's public key `x‖y` —
the same value the contract binds as the log root key. Signs ceremony artifacts
only (the sealing delegation, the on-chain proof, and the session-key
endorsement).
_Avoid_: assuming a PRF extension — the credential itself is the root key.

**Session key**:
A non-extractable WebCrypto P-256 key held by the browser, which signs
per-turn user-log entries silently in the unchanged plain-ES256 profile. It is
the passkey's delegate, not the log root. Where no authenticator is available
the session key **is** the root (the software root) and no endorsement exists.
_Avoid_: calling it the user root under passkey custody — that is the passkey.

**Session-key endorsement**:
A COSE Sign1 signed by the passkey root over `{sessionKey, notBefore,
notAfter}`, carried in the unprotected header of **every** user-log entry. It
is the single artifact linking the log's root to each entry's signer, and it
rides inside the entry so that it is committed by the entry's content hash
rather than held as operator state.
_Avoid_: treating it as recoverable from an operator export.

**Endorsement validity window**:
The `notBefore`/`notAfter` pair in an endorsement payload, in **unix
milliseconds, inclusive**, checked against the entry's idtimestamp offline
and against wall clock (with skew tolerance) at admission. Bounds the life of a
superseded session key with no revocation list and no per-log state. Default
seven days, client-chosen.
_Avoid_: comparing it to a signature timestamp — the idtimestamp domain is the
point, because every entry has one and the leaf hash binds it.

**WebAuthn assertion envelope**:
The `[authenticatorData, clientDataJSON]` pair carried in a COSE unprotected
header (`TBD1`, `-65800`) so that a passkey-signed artifact can be verified.
Trustworthy only via the challenge binding: `clientDataJSON.challenge` must
equal `base64url(sha256(Sig_structure))`.
_Avoid_: confusing it with the on-chain `algData`, which is a **3**-element
array carrying additional packed index hints.

**`ALG_ES256_WEBAUTHN`**:
The COSE algorithm identifier for a P-256 key whose signature is a WebAuthn
assertion. Used for delegation proofs, delegation certificates and session-key
endorsements — never a checkpoint-signing algorithm. Distinct from ES256 so
unaware verifiers fail closed on an unknown algorithm rather than attempting a
plain verify.
_Avoid_: using it as the envelope header label; that reuse is a recorded defect.

**Leaf-signer enforcement point**:
SCRAPI admission, and nothing else. The sequencer content-hashes, the sealer
verifies leases, the publisher lifts proofs, and the contract verifies the root
and delegation — **none of them inspects an entry's signer**. A client-side
pre-flight must agree with admission but never substitutes for it.
_Avoid_: assuming the chain or the sealer validates who wrote an entry.

**Attribution** (fourth trust question):
*Who was authorised to sign this entry?* Independent of split-view, sealing and
authority, and answered from the entry's own bytes plus the log's root key. See
[receipt-trust-model.md](spec/receipt-trust-model.md).
_Avoid_: folding it into "authority", which is about the log, not the entry.

**`GF_REQUIRES_USER_VERIFICATION`**:
Grant flag bit 40 in the algorithm-policy band ([label-registry.md](spec/label-registry.md)
§5). When set, a WebAuthn assertion must carry the UV flag. The policy is
declared once in the grant committed in the parent auth log and read
identically by the chain, admission and offline verifiers. User presence is
always required regardless.
_Avoid_: a per-verifier constant or environment variable — the flag is the one
declaration.

## Receipt verification

**Offline receipt verification**:
Cryptographic verification of a SCITT COSE receipt using only captured bytes
(the forest genesis document or another trust root, receipt CBOR, grant or
statement context, the idtimestamp). Layers A–C: receipt signature vs the
trust root the caller holds, MMR inclusion (header 396), leaf binding (grant
commitment or statement content hash + idtimestamp). No network during the
verify step. Layer D (on-chain tip canonicality) is out of scope. See
[checkpoints-and-receipts.md](spec/checkpoints-and-receipts.md) §4 and
[ADR-0045](decisions/adr-0045-receipt-verify-offline-contract.md).
_Avoid_: conflating with server-side register-grant receipt verify (live trust
root resolution).

**Implementation names**:
Where a document names an implementation rather than a role, these are the
public repositories: the TypeScript verifier and encoding libraries and the
admission edge live in forestrie/canopy; the Go operator services (sequencer,
sealer, publisher, custodian) in forestrie/arbor; the Go log library in
forestrie/go-merklelog; the contract in forestrie/univocity. The README lists
them with links.

## Related documentation

- [spec/receipt-trust-model.md](spec/receipt-trust-model.md) — the four
  questions and the trust roots that answer them
- [spec/checkpoints-and-receipts.md](spec/checkpoints-and-receipts.md) — the
  checkpoint and receipt wire formats
- [spec/log-authority-and-grants.md](spec/log-authority-and-grants.md) — the
  grant wire format and the authority hierarchy
- [spec/key-custody-and-choice.md](spec/key-custody-and-choice.md) and
  [spec/leaf-admission-and-session-endorsement.md](spec/leaf-admission-and-session-endorsement.md)
  — the source for every term in the passkey-custody section above
- [spec/label-registry.md](spec/label-registry.md) — every codepoint, with values
- [spec/implementation-status.md](spec/implementation-status.md) — where an
  implementation differs from the text
- [decisions/arc-0019-grant-verification-model.md](decisions/arc-0019-grant-verification-model.md) — the grant verification model
- [decisions/adr-0045-receipt-verify-offline-contract.md](decisions/adr-0045-receipt-verify-offline-contract.md) — the offline receipt verify contract
