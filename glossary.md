# Forestrie platform glossary

Shared domain language for Forestrie transparency logs, Univocity contracts,
and operational services. Repo-specific API names belong in each repo's
`docs/agents/domain.md`.

## Core identity

**Forest**:
The namespace of logs that share one bootstrap root authority log `R`. SCRAPI
paths use `/register/{R}/…` and `/logs/{R}/…`.
_Avoid_: deployment, project (those are forest-1 / GCP ops terms).

**Bootstrap root auth log (`R`)**:
The first authority log in a forest. Its bootstrap grant has
`ownerLogId === logId`. After on-chain bootstrap, `R` matches Univocity
`rootLogId` / `authorityLogId`.
_Avoid_: bootstrap log alone (conflicts with bootstrap grant or bootstrap
transaction).

**Log ID**:
16-byte UUID — canonical off-chain identity for a transparency or authority
log.
_Avoid_: wire log id, hex64, padded path segment.

**Forest genesis document**:
Curator-written CBOR stored at `forests/forest/{uuid-R}/genesis.cbor` in the
grants/logs bucket. Binds `R`, the root trust-anchor public key, and
Univocity chain binding.
_Avoid_: genesis grant, on-chain genesis.

**Chain binding**:
The pair `(chain-id, univocity-contract-address)` for the EIP-155 chain and
ImutableUnivocity contract this forest publishes to.
_Avoid_: univocity config, trust root URL.

**Univocity contract address**:
The 20-byte address of the user-facing ImutableUnivocity contract (Safe deploy
field `imutableUnivocity`), not the Safe multisig address.
_Avoid_: contract, univocity addr without disambiguation.

**Root bootstrap grant**:
The first Forestrie-Grant on `R`; its **`grantData`** must match the forest
genesis bootstrap key (**ES256:** 64-byte `x‖y`; **KS256:** 20-byte address).
Distinct from the forest genesis document.
_Avoid_: genesis when meaning the grant.

**Statement signer binding**:
Bytes from a grant's committed **`grantData`** that the register-statement COSE
**`kid`** must equal. **ES256:** first 32 bytes of 64-byte `x‖y`; **KS256:** full
20-byte address. Verified separately from the grant envelope signer.
_Avoid_: conflating statement `kid` with the authority key that signed the grant
envelope.

**Univocity root bootstrap**:
The on-chain transaction that sets `rootLogId` on the contract. Runs after
forest genesis POST and the root bootstrap grant.
_Avoid_: forest genesis.

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

**BYOK delegation mode (operator-hosted sealing)**:
For user logs hosted by a mandate operator, the user owns the root authority
`K(L)` (BYOK). Mode **B** routes `delegation.required` to the user's own signer
(no operator key custody); Mode **C** uses a user-owned Privy wallet with mandate
as a **revocable additional signer** (Privy-custodied, user-authorized — **not**
full BYOK). Both are single-hop certs verified against the registered
`publicRoot`; the user keeps a kill switch and a protocol-level exit (rotate
`K(L)`). See
ARC-0022 (private, cited by name).
_Avoid_: calling Mode C "full BYOK"; placing the operator in the wallet **owner**
quorum (defeats the kill switch).

**Delegation certificate**:
COSE_Sign1 object signed by the log's root authority `K(L)` authorizing a
short-lived delegated sealing key for an MMR window. Submitted via
`POST /api/delegations/certificate`; verified against the **registered
publicRoot** (ARC-0022 I5). Distinct from **KMS signing material** (custody
keys used to mint certs in operator-hosted modes) and from **control-plane
session** tokens.
_Avoid_: "material", "delegation material"; conflating with checkpoint COSE
receipts or custody private keys.

**Delegation control plane**:
HTTP user-management APIs on the delegation-coordinator (`pending`, `enabled`,
`signing-route`) authenticated by wallet-challenge session. Distinct from the
**operator plane** (`/admin/api/…`), **registration control plane** (ARC-021),
and **public sealing** (certificate submit + verify, ARC-0022 I5).
_Avoid_: conflating with `COORDINATOR_APP_TOKEN` or per-log `issuerToken`.

**Operator plane**:
HTTP operator-only APIs on the delegation-coordinator under `/admin/api/`
(`enabled` service gate, `custody-keys`). Authenticated by
`COORDINATOR_APP_TOKEN` only; wallet-challenge sessions are rejected. Never
BFF-proxied from Mandate browser UX.
_Avoid_: using operator `PUT …/enabled` as a substitute for the user kill
switch (`user_enabled` vs `operator_enabled`).

**Control-plane session**:
Short-lived bearer minted after a wallet-challenge proof; claims bind
`authLogId`, scopes, and coordinator audience.
_Avoid_: calling it an onboard token or OAuth identity token.

**Authority log (`authLogId`)**:
Log whose registered root key `K(authLog)` must sign the control-plane challenge.
Pending entries are filtered by this id; v1 requires session `authLogId` to
match the request.
_Avoid_: treating `authLogId` as an unauthenticated query filter.

**Registered publicRoot**:
Root key material stored on the delegation-coordinator at genesis. Verification
anchor for certificate acceptance (ARC-0022 I5) and control-plane ownership (v1).
_Avoid_: live Univocity lookup for UX auth in v1.

**Proof-of-possession (control plane)**:
Challenge signed with a **candidate** `K(L)` before that root is registered
(genesis/onboarding). Distinct from ownership verification against an existing
registered publicRoot.

**Volumetric abuse protection**:
Rate limiting or WAF rules at the Cloudflare edge (or equivalent ingress) to
block sustained request floods before worker CPU or upstream RPC amplification.
Used on public self-verifying routes such as `POST /api/delegations/certificate`
(see canopy ADR-0008). Distinct from application idempotency (`requestKey`
reservation on the mandate agent) and per-credential signer rate limits.

**Delegated grant validation (univocity)**:
When canopy has `UNIVOCITY_SERVICE_URL` + `UNIVOCITY_API_TOKEN` set,
register-grant forwards each creation grant to univocity `POST /api/grants`
(authoritative chain verification + global `logId → R` uniqueness), surfacing
201/200 → 303, 409 → 409, 4xx → 403.
_Avoid_: treating local genesis x‖y match as the authority for cold child
grants.

**Forest uniqueness (`logId → R`)**:
Each subject `logId` belongs to exactly one forest `R` globally; univocity's
atomic index enforces it and canopy surfaces 409 at the edge.

## Delegation in advance (standing keys)

Terms from the FOR-390 delegation-in-advance design cycle. See
ADR-0050 (private, cited by name) (esp. §"Trust model and
genesis topology") and ARC-0022.

**Standing delegate key**:
A sealer-held checkpoint-signing key **shared across all logs a sealer seals**,
derived deterministically as `HKDF(seed, "delegate"‖epoch‖index) → P-256`, where
`seed = MacSign(kmsMacKey, prefix‖sealerId‖epoch)` is re-derived inside KMS at
boot and never persisted. Deterministic, so advance certificates outlive the
process. Distinct from the legacy **per-log ephemeral delegated key** (generated
in RAM per log, dies with the process). Authority is still per-certificate —
`K(L)` signs `(logId, range, key, expiry)` — so a shared key confers nothing
across logs (ADR-0050 Q1).
_Avoid_: "the sealer's key" without a standing/ephemeral qualifier; implying the
shared key widens blast radius (authority is per-certificate).

**Direct signing vs delegated sealing**:
**Direct signing** — the checkpoint signer `K(L)` signs the consistency receipt
itself (no delegation proof; on-chain verifier == root). The natural,
dependency-free path for a **self-hosted sealer** (it holds `K(L)`; there is no
root-holder/operator split to bridge). **Delegated sealing** — `K(L)` signs a
delegation certificate to a sealer-held key that signs checkpoints; the mechanism
for **operator-hosted** logs where the root holder and sealer operator differ. A
self-hoster may still run a local delegation for key hygiene, but the platform
neither requires nor registers it.
_Avoid_: forcing self-hosted sealers onto the delegation path; treating
delegation as mandatory for sealing.

**Registrar (custodian)**:
The **sole** party that registers a sealer's standing delegate keys with the
delegation-coordinator. Because self-hosted sealing is direct signing, every
delegation participant is a custodian-seeded hosted sealer, so the custodian —
which gates the KMS seed — re-derives the standing public keys at seed issuance
and registers them. There is no self-registering sealer.
_Avoid_: the sealer "registering its own key" (removed); treating registration
as app-token-gated self-service.

**Custodian voucher (delegate-key voucher)**:
A strict-COSE object signed by the **custodian voucher key** over
`(sealerId, epoch, delegatePublicKey)`, attesting a standing key's provenance
from the KMS seed. Stored and advertised by the coordinator with the standing
entry; the kit/signer **verifies it against the pinned registrar key before
`signAdvanceDelegation` binds** the key. The voucher key is a **dedicated signing
key, distinct from the KMS-MAC seed-derivation key** (a MAC key cannot make
public-verifiable signatures).
_Avoid_: conflating the voucher key with the KMS-MAC seed key; conflating the
voucher (which *sealer* a key belongs to) with the delegation certificate (that
*root* authorized a key).

**Pinned registrar key**:
The public half of the custodian voucher key, distributed to signing kits and
tooling. The root holder's trust in an advertised standing key rests on verifying
a voucher against this pinned key — not on coordinator honesty. It defends the
pre-artifact **signing decision** against a compromised coordinator (a distinct
credential and attack-surface domain from the custodian). The "pipe"
self-authenticating-artifact property does not cover this, because a certificate
signed to the wrong key is still self-authenticating against `K(L)`.
_Avoid_: assuming the sealed certificate's self-authentication protects the
signing decision.

**Membership check (delegation issue)**:
The coordinator serves or triggers a delegation **only for a custodian-registered
standing key**. Closes the lockout by construction: a holder of a compromised
`COORDINATOR_APP_TOKEN` can at most trigger a harmless delegation to the real
sealer's key (whose private half it lacks), never inject an attacker-controlled
key. Replaces the legacy arbitrary-key on-demand path.
_Avoid_: treating the issue app-token as sufficient authority to name an
arbitrary delegated key.

**Delegation lockout (threat)**:
The failure a stolen or mis-issued delegation enables: the attacker publishes a
forked-but-consistency-valid `publishCheckpoint`, poisoning the committed
on-chain accumulator so the legitimate owner's true history is no longer a
provable extension — locking them out until they rotate `K(L)`. Bounded (narrow
window / TTL / honest-sealer collision) in the ephemeral model; unbounded under
advance delegation (wide, standing, no on-chain expiry), which is why registrar
authentication is load-bearing.
_Avoid_: assuming the contract's append-only consistency prevents forks by a
*validly delegated* key — it authorizes exactly that.

**Genesis pre-delegation (PUSH)**:
The coordinator firing `delegation.required` for the standing key when a log's
signing route is set up **or** when the standing key registers (whichever is
second; any-order safe). Lets hosted Mode C (hands-off) auto-pre-delegate "the
moment a logId is known," so the first seal is a cache hit. The PULL path
(`GET …/pending-delegation`) remains for signers who poll. Fan-out is bounded to
logs awaiting a first delegation; deterministic re-derivation means restarts do
not re-fire.
_Avoid_: assuming PULL suffices for hands-off Mode C (it reintroduces first-seal
latency).

## Arbor / univocity services

**Trust-root service**:
The univocity HTTP read proxy for contract log state (`logConfig`, `logRootKey`,
`isLogInitialized`). Exposes scoped and logId-only routes.
_Avoid_: auth-log service.

**Forest registry**:
Univocity's in-memory list of forests loaded from genesis R2 objects.

**Authority resolver**:
Univocity's trusted lookup `GET /api/logs/{logId}/authority`: resolve
`logId → R` (global index), establish `K(logId)` by the hybrid rule (on-chain
`logRootKey` when initialized, else the chain-valid stored `grantData`,
anchored at `bootstrapConfig()`), and return
`{ rootKey, chainId, contract, source }`. Non-mutating; the sealer verifies
the delegation locally against the returned key.
_Avoid_: sending the cert to univocity or expecting a 401 allow/deny verdict.

**Owned grant store**:
Univocity-owned S3/R2 objects under `forests/`: genesis
(`forests/forest/{uuid-R}/genesis.cbor`), auth-log grants
(`…/grants/auth-log/{uuid}.cbor`), data-log grants
(`…/grants/data-log/{uuid}.cbor`), and the global index
(`forests/index/forest/{uuid-subject}` → ASCII UUID of `R`, `If-None-Match: *`
on create). Persists only until a log's first checkpoint; no long-term backup.
_Avoid_: "canopy grant storage" (canopy no longer owns it).

**Custody key**:
Asymmetric KMS key in the custody ring used by the operator to sign
**delegation certificates** on behalf of a hosted log (operator-hosted sealing
modes). CryptoKey id equals the normalized log id (32 lowercase hex). Holds
**KMS signing material** — not the user's BYOK root `K(L)` in Mode B.
_Avoid_: conflating with a **delegation certificate** (the COSE object
submitted to the coordinator), the **contract bootstrap key** (on-chain
Univocity `bootstrapConfig()` / e2e PEM), or the user's root private key.

**Ensure (custodian)**:
Idempotent get-or-create of a custody key in KMS via HTTP `POST /api/keys`.
_Avoid_: "create key" when meaning ensure semantics.

**Seal hint**:
The trigger message that wakes the sealer to run `CheckpointLog()` for a massif,
carrying `{"object": {"key": "<massif object key>"}}` — the same shape whatever
the transport (R2 event notification, ranger-published queue message, or
long-poll coordinator). A hint is **at-least-once and carries no authority**:
the sealer always re-derives its work from R2 state, so a lost, duplicate, or
spurious hint is harmless and never affects correctness (ADR-0007).
_Avoid_: treating a hint as a command or as the source of truth; "seal event"
(reserve "R2 event notification" for the specific Cloudflare-delivered backstop).

**Nudge**:
The **verb** — the act of delivering a seal hint. "Ranger nudges the sealer"
(publishes a hint to the queue) or "ranger nudges the seal-coordinator" (Phase 2
long-poll). The noun for the payload is always **seal hint**, not "a nudge".
_Avoid_: using "nudge" as a distinct message type or implying it carries
different semantics from a hint on another transport.

## Checkpoints and on-chain anchoring

**Checkpoint (format v3) / consistency receipt**:
The sealed checkpoint object (`…/checkpoints/…/{massif}.sth`), from ADR-0046 a
tagged `COSE_Sign1` (CBOR tag 18) draft-bryce **Receipt of Consistency**:
protected header `{1: alg, 395: vds=3}`, a detached payload, one consistency
proof (previous checkpoint → this seal), and (in the unprotected header)
pre-signed peak receipts and, when delegated, the on-chain delegation proof.
It is directly publishable — the publisher submits it with no sibling document.
_Avoid_: "sibling proof document" (superseded by ADR-0046); "MMRState checkpoint"
(the v2 format, removed).

**Detached payload (raw-concat accumulator)**:
The bytes a checkpoint signature is over: the raw concatenation of the MMR
accumulator peaks (descending height), no hashing. The univocity contract
recomputes it from the proof and verifies the signature against it
(`buildDetachedPayloadCommitment`, raw concat since **v0.1.6**; FOR-321).
_Avoid_: "sha256 commitment" (the pre-v0.1.6 form).

**Peak inclusion receipt**:
One detached-payload `COSE_Sign1` per accumulator peak, pre-signed by the log
key and carried in the checkpoint (`SealPeakReceiptsLabel`). Any holder of the
checkpoint + replicated log data can attach an inclusion proof and mint a
receipt for any entry without the signing key (MMR low-update-frequency).
_Avoid_: conflating with the checkpoint's own consistency receipt.

**On-chain delegation proof**:
The COSE-shaped `DelegationProof` (plan-0003 `OnchainDelegationProof`) the
custodian issues, binding the sealing key to `(logId, mmrStart, mmrEnd)`. It
rides the checkpoint (`SealDelegationProofLabel`, surfaced via
`CheckpointReceipt.Extras`); the publisher wires it into the `publishCheckpoint`
`delegationProof` calldata. FOR-314 Outcome B — distinct from the label-1000
delegation **certificate**.
_Avoid_: reusing the label-1000 cert as the on-chain proof (they differ).

**Publisher / anchoring**:
The arbor `services/publisher` — a permissionless, gas-only-EOA submitter that
reads a v3 checkpoint object and calls `publishCheckpoint`, advancing the
contract's `logState(logId)` accumulator. Authority stays with the
grant/signature chain — "postmark, not gatekeeper".

**Anchor lag**:
The number of sealed checkpoints ahead of the on-chain `logState` size — the
publisher's backlog metric. Caught up by chaining one consistency proof per
sealed checkpoint into a single `publishCheckpoint` call.

## Payments and registration

**Univocity instance account**:
Every deployed Univocity instance is its own fee account (ADR-0059): the
account id is the `univocityInstanceId` — the canonical CAIP-10 lowercased
rendering of the chain binding. Admission (paid or vetted redeem, or ops
break-glass mint) **reserves** the instance; genesis completes the
reservation (`reserved` → `registered`). Ongoing checkpoint fees draw down
prepaid checkpoint credits; enforcement is forward-only via the kill switch.
_Avoid_: "payment-authoritative instance"; conflating the account with the
x402 **payer** (anyone may pay an account's bills — sponsorship is a
payment-side arrangement, not a graph edge).

**Registration block** (`registrationBlock`):
The chain head observed when an instance's reservation completes to
`registered` at genesis, recorded on the chain-binding record. It is the
account's **metering floor**: the accrual indexer's first-sight scan starts
there (inclusive), so checkpoints anchored between registration and first
sight are counted, and nothing before the service relationship is billed.
Best-effort (`null` on RPC failure; ops-repairable). Canopy
plan-2607-04 / FOR-477.
_Avoid_: "deployment block" — a rejected earlier framing; the operator does
not bill pre-registration self-anchored checkpoints, so the contract's
deployment height is not the billing fact.

**Payment-authoritative registration** _(retired)_:
Pre-ADR-0059 class marking a root as backed by an onboard token, with
"regular" forests inheriting coverage through `endorsedBy` edges. Retired in
plan-2607-43 slice 02: every instance root is its own account, the class and
edge are never written, and legacy records are read-tolerated only.
_Avoid_: any use in new designs.

**Regular registration** _(retired)_:
Pre-ADR-0059 class for a forest whose payment coverage was inherited from a
payment-authoritative ancestor via an endorsement grant. Retired with the
class split (see above).
_Avoid_: any use in new designs.

**Univocity instance**:
A deployed ImutableUnivocity contract identified by its chain binding
`(chain-id, univocity-contract-address)`. The unit a BYOK operator deploys and
registers. A forest binds to exactly one instance via genesis chain binding.
_Avoid_: conflating the instance (contract) with a forest, a log, or a
registration record.

**`CANOPY_PAYMENTS_ONBOARD_TOKEN`**:
A canopy-issued bearer that is the **operating credential for one reserved
univocity instance** (ADR-0059 decision 8): every token carries a mandatory
chain binding, its admission (`admittedBy: ops | payment | auto`) is
recorded, and the one-off onboard fee — where charged — purchases the
instance reservation, not any ongoing liability. Ongoing checkpoint fees are
a separate, prepaid-credits concern. Deliberately not an OAuth / identity
token; canopy persists the set of issued tokens (hash at rest) and validates
genesis against it.
_Avoid_: conflating with `COORDINATOR_APP_TOKEN` or per-log `issuerToken`;
describing it as vouching for "all activity" — that reimbursement framing is
retired.

**Onboard request**:
A pending application stored by canopy for a mandate fork operator to obtain
an onboard token. Created via public `POST /api/onboarding/requests` after
Univocity deployment is verified. Has lifecycle status (`pending`, `approved`,
`rejected`, `expired`, `redeemed`). Distinct from mandate **Mode C wallet
onboarding** (Privy user wallet setup).
_Avoid_: "onboarding request"; calling it an onboard token before redeem.

**Redeem code**:
A one-time secret returned when an onboard request is created. The mandate
operator presents it on `POST …/redeem` to receive the minted onboard token
after canopy ops approval. Stored at rest as a hash only.
_Avoid_: conflating with the onboard token or wallet-challenge session bearer.

**Payment-registration graph** _(retired)_:
The pre-ADR-0059 cross-forest `endorsedBy` graph by which canopy tracked
payment coverage. Retired in plan-2607-43 slice 02: there is no cross-forest
payment structure — each instance is its own account, and a sponsor simply
pays another account's bills. The per-forest Univocity authority hierarchy
is unrelated and unchanged.
_Avoid_: any use in new designs; "endorsed-by" as an on-chain relationship
(it never was one).

**Endorsement grant** _(retired as genesis authorization)_:
The `GF_DERIVED` completed grant that authorized a "regular" forest's
genesis. That authorization mode is retired (genesis is onboard-bearer
only); the wire-level `GF_DERIVED` flag and the data-plane derived-leaf
append remain available for non-payment attestation uses.
_Avoid_: presenting one at genesis — it is refused with a pointer at the
onboarding flow.

## Orchestrator and system testing

**Release product**:
The immutable artefact captured once at orchestrator **release**: exact service
refs, kit npm versions, and Univocity **release pins**. Stored as
`release-manifest.jsonc` with `kind: release-manifest`.
_Avoid_: lane manifest, wire manifest.

**Lane test envelope**:
Tier-specific test context merged at promote: `catalog`, `secretsProfile`.
Stored as `lane-test-manifest.jsonc`. "Tier" here means the promotion target
(`dev` / `stage`) — its only meaning since the numbered test tiers were retired
(ARC-0025, FOR-531).
_Avoid_: full wire manifest, release template.

**Promote merge**:
Combining release product + lane test envelope into a wire manifest for
preflight and the **lane suite**'s Playwright runs.
_Avoid_: template hydration, lane YAML graft.

**Release pin**:
Exact version or tag of a build artefact (kit version, Univocity
`releaseTag`, service git ref) — not a lane-local deploy output.
_Avoid_: imutableAddress at capture time (that is preflight deploy output).

## Passkey custody and leaf attribution

Full treatment: protocol/README.md (private, cited by name), in particular
[key-custody-and-choice.md](spec/key-custody-and-choice.md) and
[leaf-admission-and-session-endorsement.md](spec/leaf-admission-and-session-endorsement.md).

**Passkey root**:
A WebAuthn platform authenticator credential used as a log's root key. Under
passkey custody the ES256 `grantData` **is** the passkey's public key `x‖y` —
the same value univocity binds as `logRootKey`. Signs ceremony artifacts only
(the sealing delegation, the on-chain proof, and the session-key endorsement).
_Avoid_: assuming a PRF extension — the credential itself is the root key.

**Session key**:
A non-extractable WebCrypto P-256 key held by the browser, which signs
per-turn user-log entries silently in the unchanged plain-ES256 profile. It is
the passkey's delegate, not the log root. Where no authenticator is available
the session key **is** the root and no endorsement exists.
_Avoid_: calling it the user root under passkey custody — that is the passkey.

**Session-key endorsement**:
A COSE Sign1 signed by the passkey root over `{sessionKey, notBefore,
notAfter}`, carried in the unprotected header of **every** user-log entry. It
is the single artifact linking the log's on-chain root to each entry's signer,
and it rides inside the entry so that it is committed by the entry's content
hash rather than held as operator state.
_Avoid_: treating it as recoverable from a `/receipts` export — that route was
removed, not kept as a fallback.

**Endorsement validity window**:
The `notBefore`/`notAfter` pair in an endorsement payload, in **unix
milliseconds, inclusive**, checked against the *receipted idtimestamp* offline
and against wall clock (with skew tolerance) at admission. Bounds the life of a
superseded session key with no revocation list and no per-log state. Default
seven days, client-chosen.
_Avoid_: comparing it to a signature timestamp — the idtimestamp domain is the
point, because every receipt carries one.

**WebAuthn assertion envelope**:
The `[authenticatorData, clientDataJSON]` pair carried in a COSE unprotected
header (`TBD1`) so that a passkey-signed artifact can be verified. Trustworthy
only via the challenge binding: `clientDataJSON.challenge` must equal
`base64url(sha256(Sig_structure))`.
_Avoid_: confusing it with the on-chain `algData`, which is a **3**-element
array carrying additional packed index hints.

**`ALG_ES256_WEBAUTHN`**:
The COSE algorithm identifier for a P-256 key whose signature is a WebAuthn
assertion. A **delegation-proof and certificate algorithm only** — never a
checkpoint-signing algorithm. Distinct from ES256 so unaware verifiers fail
closed on an unknown algorithm rather than attempting a plain verify.
_Avoid_: using it as the envelope header label; that reuse is a recorded bug.

**Leaf-signer enforcement point**:
canopy SCRAPI admission, and nothing else. Ranger content-hashes, the sealer
verifies leases, the publisher lifts proofs, and univocity verifies the root
and delegation — **none of them inspects an entry's signer**. A client-side
pre-flight (the scribe DO) must agree with admission but never substitutes for
it.
_Avoid_: assuming the chain or the sealer validates who wrote an entry.

**Attribution** (fourth trust question):
*Who was authorised to sign this entry?* Independent of split-view, sealing and
authority, and answered from the entry's own bytes plus the log's on-chain
root. See [receipt-trust-model.md](spec/receipt-trust-model.md).
_Avoid_: folding it into "authority", which is about the log, not the entry.

**`GF_REQUIRES_USER_VERIFICATION`**:
Grant flag bit 40 (canopy wire byte 2, mask `0x01`) in univocity's native
algorithm-policy band. When set, a WebAuthn assertion must carry the UV flag.
The policy is declared once in the grant committed in the parent auth log and
read identically by the chain, admission and offline verifiers. User presence
is always required regardless.
_Avoid_: a per-verifier constant or environment variable — the flag is the one
declaration.

## Receipt verification

**Offline receipt verification**:
Cryptographic verification of a SCITT COSE receipt using only captured bytes
(genesis document, receipt CBOR, grant or statement context). Layers A–C:
receipt signature vs genesis trust anchor, MMR inclusion (header 396), leaf
binding (grant commitment or statement content hash + idtimestamp). No SCRAPI,
coordinator, or univocity HTTP during the verify step. Layer D (on-chain tip
canonicality) is out of scope. See [ADR-0045](decisions/adr-0045-receipt-verify-offline-contract.md).
_Avoid_: conflating with server-side register-grant receipt verify (live trust
root resolution).

**@forestrie/receipt-verify**:
Shared TypeScript package (canopy monorepo workspace) implementing offline
receipt verify per ADR-0045. Consumed by `@canopy/api`, `@forestrie/canopy-e2e-kit`,
and operator CLI tooling. `@forestrie/canopy-e2e-kit` **0.4.0** is the offline
verify slice (exports + dependency on this package).
_Avoid_: duplicating verify logic in the estate's integration test suite
specs or one-off scripts.

## Example dialogues

**Dev:** We mint a grant on data log `D` — how do we know which Univocity
contract to verify against?

**Expert:** You need bootstrap `R` from the SCRAPI path or receipt URL, then
`GET /api/forest/{R}/genesis`. The forest genesis document carries chain
binding; the trust anchor x‖y is separate and is what register-grant checks
today.

**Dev:** Is that the same as the bootstrap grant?

**Expert:** No. The genesis document is curator provisioning in R2. The
bootstrap grant is the first leaf on `R`'s authority MMR.

**Dev:** Sealer got a massif event with only `logId` — how does it pick the
contract?

**Expert:** It calls univocity `GET /api/logs/{logId}/public-root`. Univocity
loaded forests from genesis in the grants bucket, probed `isLogInitialized`,
and calls the right contract. Sealer never sees `chainId` or the contract
address unless it chooses to read optional CBOR fields later.

## Related documentation

- protocol/README.md — wire formats, the trust model, and key
  custody; the authoritative source for every term in the passkey-custody
  section above
- architecture.md (private, cited by name) — platform overview
- [decisions/arc-0019-grant-verification-model.md](decisions/arc-0019-grant-verification-model.md) — grant auth model
- adr/adr-0034-forest-genesis-chain-binding-required.md (private, cited by name) — genesis POST requires chain binding
- adr/adr-0035-univocity-owned-grant-store-and-authority-correspondence.md (private, cited by name)
- adr/adr-0036-global-logid-r-uniqueness.md (private, cited by name)
- adr/adr-0037-forests-storage-and-uuid-log-ids.md (private, cited by name)
- [decisions/adr-0045-receipt-verify-offline-contract.md](decisions/adr-0045-receipt-verify-offline-contract.md) — offline receipt verify API
