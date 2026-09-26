# ADR-0050 — Delegation in advance: standing delegate keys + coverage-matched retrieval

**Status:** ACCEPTED — one of the accepted decisions the specification under
[`spec/`](../spec/) rests on.  
Promoted on 2026-09-26 from the operator's private decision record, where it
was written as Proposed; the implementation it records is live in arbor
([`services/pkgs/delegatekeys/derive.go`](https://github.com/forestrie/arbor/blob/main/services/pkgs/delegatekeys/derive.go),
[`services/custodian/src/handle_delegate_seed.go`](https://github.com/forestrie/arbor/blob/main/services/custodian/src/handle_delegate_seed.go)).
Where the shipped code differs from the text below, [As implemented](#as-implemented)
says how.  
**Date:** 2026-07-13 (revised on review the same day; extended 2026-07-14 and
2026-07-25)  
**Related:** [spec/receipt-trust-model.md](../spec/receipt-trust-model.md)
(question 2, the sealing key as specified today),
[spec/trust-boundaries-and-operator-powers.md](../spec/trust-boundaries-and-operator-powers.md)
§3, [spec/delegation-and-webauthn-envelopes.md](../spec/delegation-and-webauthn-envelopes.md)
(the delegation certificate),
[ADR-0045](./adr-0045-receipt-verify-offline-contract.md) (the offline
verifier contract),
[arbor ADR-0007](https://github.com/forestrie/arbor/blob/main/docs/adr/adr-0007-low-latency-sealer-trigger.md)
(low-latency sealer trigger), and ARC-0022, the operator's architecture record
for BYOK user-log delegation and operator-hosted sealing

## Context

Checkpoint sealing requires a delegation certificate: the log's root key
`K(L)` signs `(logId, mmrStart, mmrEnd, delegatedPublicKey, expiresAt)`
authorizing a short-lived sealer-held key for an MMR window. Today this is
strictly **on demand**: the sealer generates the delegated key only when a
seal first needs it, the coordinator records a pending entry, the root-key
holder signs (webhook push or wallet pull), and the sealer's request is
answered only when a certificate **exactly matching the request triple**
`(mmrStart, mmrEnd, delegatedPublicKey)` exists
(`delegation-store.ts handleIssue` → `certificateKeyFor`).

Measured on the operator's test deployment (2026-07-13): this on-demand
round-trip is the dominant residual seal latency — first seal of a fresh log
~16s (vs ~3–4s warm), and every pod restart re-pays it per active log
because the delegated private key dies with the process. The sealer's range
pad (`DELEGATION_RANGE_PAD`) mitigates the *warm* path but is operator
policy compensating for a structural constraint: **a signer cannot sign a
delegation before the sealer has invented the key it must bind.**

## Decision

Make delegation-in-advance possible while keeping lazy on-demand as the
fallback:

1. **Standing sealer delegate keys, shared across logs, derived from a
   KMS-custodied seed.** The sealer maintains a small set of standing
   delegate keys derived locally as
   `HKDF(seed, "delegate" ‖ epoch ‖ index)` → P-256 scalar, where the
   **seed itself is derived deterministically inside KMS** via an
   HMAC-SHA256 MAC key (Cloud KMS purpose `MAC`, HSM-capable):
   `seed = MacSign(kmsMacKey, "forestrie/sealer-delegate-seed/v1" ‖ sealerId ‖ epoch)`,
   obtained at boot through the custodian (the existing KMS proxy; a
   narrow fixed-prefix derivation endpoint, not a general MAC oracle). The
   seed is therefore **never at rest anywhere** — not in the secret store,
   not on disk, not in R2 — it exists only in sealer memory and is
   re-derivable only by principals holding KMS `macSign` IAM on that key:
   the same perimeter, IAM, and audit logging as the custody keys.
   Self-hosted sealers substitute a locally-held seed behind the same
   provider interface. Keys are registered with the delegation coordinator
   (`POST /api/sealer/delegate-keys`, app-token auth; the sealer stays
   outbound-only).
2. **Signers can delegate before any seal is needed, with no special
   casing.** The coordinator's pending-delegation listing is **uniform**:
   every entry is "a key you may delegate to", carrying the demanded
   window when one exists (on-demand pendings) and no window otherwise
   (the standing delegate key, which is always listed for a log with a
   registered public root and signing route). Signers handle every entry
   identically — sign a certificate binding the offered key, covering at
   least the demanded window if present, with a horizon and TTL of their
   choosing (conventionally `mmrStart = 0`). Webhook modes receive the
   same uniform `delegation.required` delivery at signing-route setup as
   they do for demand pendings. There is no `kind` discriminator: advance
   and demand differ only in whether a minimum window is stated.
3. **Coverage-matched retrieval.** `POST /api/delegations` — the sealer's
   existing acquire-or-request call (a POST because a miss has side
   effects: it records the pending demand and dispatches the signer
   webhook; the *publish* path is and remains
   `POST /api/delegations/certificate`) — answers with the newest
   unexpired stored certificate for the log **covering** the requested
   window and bound to a registered delegate key (or the request key),
   instead of the exact triple. The sealer requests its **true seal
   window**; `DELEGATION_RANGE_PAD` is removed.
4. **Stale submissions rejected.** `POST /api/delegations/certificate`
   rejects certificates that are expired on arrival (60s skew) or strictly
   superseded (an existing cert for the same `(logId, delegatedKey)` with
   ≥ horizon and ≥ expiry). Overlapping ranges are accepted. Validation is
   uniform for advance and demand submissions: root-signature valid, bound
   key known (registered delegate key or a pending demand key), not stale;
   an accepted certificate clears any pending demands it covers.
5. **`GET /api/logs/{logId}/delegation` (public)** returns the current
   (newest, unexpired, highest-horizon) certificate so signers and tooling
   can check freshness and anticipate renewal. Certificates are public
   material — every published checkpoint already embeds one (unprotected
   label 1000) — so the endpoint is unauthenticated behind the operator's
   standard edge volumetric protection; the only disclosure beyond
   published state is a not-yet-used range/key, which carries no
   authority.

### Epoch and rotation

The epoch is an **explicit operator-maintained integer** (config/rotation
state), not a clock. Nothing verifies it — it is a derivation-input and
key-name component — so it needs no global time source. Rotation: bump the
epoch (new seed → new delegate keys), register the new keys, and keep epoch
N−1 keys loaded until certificates bound to them expire (N/N−1 overlap);
signers re-delegate on their next renewal. The KMS MAC key itself rotates
independently on the custodian's normal key-rotation cadence (a KMS key
version change is equivalent to an epoch bump and is handled the same way).
An idtimestamp-derived epoch ("one clock") was considered and rejected: it
couples rotation cadence to traffic (idle logs never rotate), and the
subsystem is already necessarily two-clock — certificate `expiresAt` is
wall-clock unix time — so deriving the epoch from idtimestamps would not
actually unify anything.

## Viability: does this eliminate on-demand seal latency?

Yes, for every path that matters, because the only thing on-demand issuance
was waiting for is the signer round-trip, and advance signing moves that
round-trip off the seal path entirely:

- **First seal of a fresh log:** with a genesis-time advance delegation the
  sealer's first issue request returns a covering certificate immediately —
  first-receipt latency collapses to the warm number (~3–4s on the test
  deployment today, <2s after arbor ADR-0007 phase 2). Measured indirectly on
  2026-07-13: when a covering certificate already existed, hint→receipt was
  6.3s pre-ceiling — pure wake + execute, no issuance term.
- **Subsequent seals:** already served by the in-process lease cache; with
  signer-anticipated renewal (signers watch `GET …/delegation` expiry or
  re-sign on webhook/timer) the renewal round-trip also happens ahead of
  need, so no seal ever waits on a signature.
- **Pod churn:** the seed re-derives via KMS at boot and the delegate keys
  re-derive from it, so every outstanding advance certificate survives
  restarts. The measured churn cost (one issuance round-trip per active
  log per restart; an issuance storm on redeploys) disappears. Signing
  remains local — no per-signature KMS round-trips (a checkpoint carries
  1 + one-per-peak signatures, 10–25 at scale, so KMS-resident signing
  would add ~0.5–1.5s per seal and KMS quota coupling; see Considered
  options).
- **The lazy path is retained** (pending entry + webhook/pull signing) for
  signers who choose not to pre-delegate; it must never block other logs
  (unchanged per-log grouping), and the sealer's in-process deferral
  retry still improves it independently.

## Security equivalence (three questions)

**Q1 — shared standing key vs per-log ephemeral: equivalent.** Authority
lives entirely in the certificate: `K(L)` signs the tuple including
`logId`, so a certificate for log A confers nothing over log B even when
both bind the same delegated public key. Verification (coordinator,
sealer-local, on-chain `delegationVerifier`) is per-certificate and
unchanged in cost or definiteness. On compromise: a process-level exploit
of the sealer exposes *all* in-memory delegated keys today; sharing changes
nothing about that blast radius. Operationally, sharing means rotation
invalidates many logs' advance certs at once — an availability
consideration handled by the N/N−1 epoch overlap, not a security one.

**Q2 — request not range-bound, delegation range/time-bound: equivalent.**
The request range was never load-bearing for trust: the root key signs
exactly `(logId, range, key, expiry)` in every model, and every verifier
checks the *certificate*, not the request. Today's exact-match retrieval is
an indexing choice, not a security control. Coverage retrieval preserves
all invariants: the sealer still verifies the returned certificate covers
its true seal window and binds a key it holds; on-chain
`publishCheckpoint` still enforces `mmrIndex ∈ [start, end]`; TTL still
bounds time. The signer *gains* explicit control of pre-authorization
breadth (range and TTL), which is where per-log policy set at genesis
belongs — and which makes the operator-side `DELEGATION_RANGE_PAD`
deletable.

**Q3 — deterministic key generation: yes, KMS-anchored, and it is
load-bearing.** Without deterministic derivation, advance certificates die
with the pod (the cert binds a public key whose private half was
memory-only), silently reintroducing the on-demand path exactly when it
hurts (deploys). The KMS-MAC-derived seed makes certificates durable across
restarts with **no private material at rest anywhere**: derivation
capability is an IAM permission (`macSign` on the dedicated MAC key), not a
stored secret, and every derivation is a KMS audit-log event — giving
detection, revocation (IAM), and HSM-backing options that a stored seed
cannot. The honest residual: a compromised sealer process still holds live
delegate keys and can sign arbitrary checkpoints for logs with unexpired
certificates — exactly today's exposure, unchanged by this design, bounded
by certificate TTLs and range horizons that the *signers* now control.

## Verification-path impact audit (review, 2026-07-13)

Every existing method of verifying that the root key holder delegated
signing was audited against this design (design review; empirical tests on
the operator's test deployment):

| Verifier | Semantics today | Impact / required change |
|----------|-----------------|--------------------------|
| **On-chain `publishCheckpoint`** (`delegationVerifier.sol`) | Verifies a **compact second signature** over `domain ‖ logId ‖ mmrStart ‖ mmrEnd ‖ delegatedKey` against the stored root, and checks `mmrIndex ∈ [start, end]` (coverage). **No expiry on-chain.** | Works with wide certs — but the coordinator's issue response currently rebuilds the proof from the **request** range (`onchainProofFromStored(req.mmrStart, …)` + the stored signature). Exact-match retrieval masks this; under coverage retrieval it pairs a signature over the cert range with the request range and `P256.verify` fails. **The proof must be built from the certificate's stored range — a mandatory fix (V1).** |
| **Compact signature availability** | The wallet signs the compact payload alongside the COSE cert (`onchainSignature`); the coordinator verifies it against the public root before storing. It is currently optional in submissions. | **Advance delegations must include it** — without it `lease.OnchainProof` is nil and the publisher cannot publish that log's checkpoints. The coordinator and the signer kit make it required. |
| **Sealer-local `VerifyDelegationLease`** | Exact-matches cert range to the request. | Relaxed to coverage of the true seal window. Cache and on-chain checks were already coverage. |
| **Offline receipt verification** (`receipt-verify`, `forestrie verify`; contract in [ADR-0045](./adr-0045-receipt-verify-offline-contract.md)) | **Broken today, independent of this ADR**: the verifier tries genesis trust-root keys only; the delegation-chain step (label-1000 cert under root → receipt under delegated key) was never implemented. Empirically confirmed 2026-07-13: `forestrie verify` on a live delegated receipt fails `stage=signature signature_invalid`. | The chain-walk implementation must use **coverage** (cert covers the leaf/checkpoint window) and **expiry-at-issuance** semantics (a receipt verifies forever; the cert's `expiresAt` bounds when it could have been *issued*, checked against the checkpoint/leaf idtimestamp — never against verification time). ADR-0050 changes nothing here but makes wide/advance certs the norm the implementation must handle. |

### The two signatures — artifact flow (V3)

A root-key holder produces **two signatures** per delegation; both travel in
public artifacts once sealed, and each is verified independently:

```
 ROOT KEY HOLDER (K(L))
   │  signs TWICE over the same (logId, mmrStart, mmrEnd, delegatedKey):
   │
   ├─(1) COSE cert ────────── payload {1:logId,3:start,4:end,5:COSE_Key,
   │      (+ expiresAt, nonce)          8:issuedAt,9:expiresAt,10:nonce}
   │
   └─(2) compact onchain sig ─ over  domain‖logId‖start‖end‖keyX‖keyY
          (NO expiry)                 (delegationVerifier.sol payload)

        POST /api/delegations/certificate {…, certificate, onchainSignature}
                              │  coordinator verifies BOTH against the
                              ▼  registered publicRoot, stores row
        ┌──────────────────────────────────────────────┐
        │ delegation_certificates (issuance-time CACHE) │
        └──────────────────────────────────────────────┘
                              │  issue response (cert + onchainProof —
                              ▼   both from the ROW: V1 fix)
        SEALER seals; embeds BOTH in the checkpoint (.sth, public R2):
          unprotected[1000]                    = (1) COSE cert
          unprotected[SealDelegationProofLabel] = (2) compact proof
                              │
          ┌───────────────────┴────────────────────┐
          ▼                                        ▼
   PUBLISHER reads (2) FROM THE            OFFLINE VERIFIER reads (1)
   CHECKPOINT → publishCheckpoint          FROM THE RECEIPT/CHECKPOINT
   calldata → delegationVerifier.sol       → cert under genesis root →
   (range coverage, no expiry)             checkpoint under delegated key
                                           (coverage +
                                            expiry-at-issuance)
```

### Operator-coupling analysis

Building the issue-response proof from the certificate row (the V1 fix)
does **not** couple users to canopy operators, and in fact tightens the
decoupling: the proof becomes *exactly the bytes the signer signed*, with
no operator-side recombination. The coordinator's database is an
**issuance-time cache/router only** — once a checkpoint is sealed, both
signatures are embedded in the public R2 artifact, the publisher constructs
calldata **from the checkpoint** (not the coordinator), and offline
verification reads the cert **from the receipt**. Long-term and archival
verification, receipt self-service, and on-chain re-publication are all
possible from the public artifacts alone; if the coordinator disappeared,
every outstanding sealed checkpoint remains verifiable and publishable.
The only coordinator-coupled activity is *future issuance* — inherent to
the sealing relationship with whichever operator runs the sealer, unchanged
by this ADR, and portable (certificates are public material; a signer can
delegate to a successor operator's sealer keys at any time).

### Trust-model status of receipts/checkpoints (V2)

The missing offline chain-walk does **not** undermine the trust model — it
is unimplemented tooling, not a broken chain. The artifacts are
cryptographically closed: genesis binds the root; the embedded COSE cert
binds root → delegated key + range + expiry; the checkpoint binds delegated
key → accumulator; nothing requires trusting the operator or the
coordinator. Independently, the **chain-anchored path is signature-free by
design** (recompute the peak, compare with the on-chain accumulator) and
works today. What the gap costs, temporarily, is the *offline convenience
path*: relying parties must use chain-anchored verification or the
operator API until the chain-walk is implemented. One trust-relevant
pitfall is pinned for the implementation: checking cert `expiresAt` against
*verification* time would wrongly invalidate old receipts — it must be
checked against the checkpoint/leaf idtimestamp (expiry bounds issuance,
not verification), preserving "cache the checkpoint forever".

**Consequence made explicit (V4):** because the on-chain check has no
expiry, a delegation's on-chain authority within its range is *permanent*.
This is true of today's padded certs too, but this ADR moves horizon choice
to the signer — so horizon selection is a durable on-chain grant and the
per-log genesis policy should present it that way.

## Trust model and genesis topology (design review, 2026-07-14)

The first implementation, deployed with the feature off, left four coupled
design holes around *establishing trust in the standing key* and *triggering
pre-delegation at genesis*. A design review resolved them. The motivating
threat is a **lockout**: a delegation bound to an attacker-controlled key lets
the attacker publish a *forked but consistency-valid* extension to the log's
on-chain register (`publishCheckpoint` enforces monotonic size **and**
consistency against the committed accumulator,
[`univocity/src/contracts/_Univocity.sol`](https://github.com/forestrie/univocity/blob/main/src/contracts/_Univocity.sol)),
poisoning the committed accumulator so the legitimate owner's true history is
no longer a provable extension — locking them out until they rotate `K(L)`
(ARC-0022 §8). This risk existed in the ephemeral on-demand model too, but was
*bounded* by narrow windows, short TTLs, and the honest-sealer collision
backstop; advance delegation removes those bounds (wide, standing, no on-chain
expiry per V4), so **authenticating the delegated key's provenance becomes
load-bearing** rather than merely hygienic.

### Self-hosted sealing is direct signing (branches 1, 4)

Delegation exists only to bridge the split between the root-authority holder and
the sealer operator (ARC-0022 §1). A self-hoster who holds `K(L)` and runs their
own sealer has no such split and **signs checkpoints directly with `K(L)`** —
already a first-class on-chain path (no delegation proof ⇒ verifier == root,
`_Univocity.sol` `_verifyCheckpointSignature`). Delegation would be pure overhead
(delegating between two co-located keys they both hold). A self-hoster wanting
`K(L)` offline may run a *local* delegation entirely within their own trust
domain; the platform neither requires nor registers it. **Consequence:** two
clean regimes — direct-sign self-host (no external sealing dependency) and
delegated hosted (custodian at boot + coordinator for coverage/issue) — with no
hybrid middle. Because the only delegation participants are custodian-seeded
hosted sealers, the custodian is the **sole registrar by construction**, not by
policy.

### Registrar and standing-key trust (branches 1, 2, 4)

- **The custodian is the sole registrar.** At seed issuance it re-derives the
  standing **public** keys and registers each with the coordinator, together
  with a **custodian-signed COSE voucher** over `(sealerId, epoch, pubkey)`. The
  voucher is signed by a **dedicated custodian signing key, distinct from the
  KMS-MAC seed-derivation key** (a MAC key cannot produce public-verifiable
  signatures), and is strict SCITT/COSE per the conformant-encoding mandate. The
  earlier sealer self-registration client is **removed** — no self-registering
  sealer exists on the delegation path.
- **The issue/demand path serves or triggers delegation only for
  custodian-registered keys** (membership check). A holder of a compromised
  `COORDINATOR_APP_TOKEN` can no longer inject an arbitrary delegated key; the
  worst it can do is trigger a *harmless* delegation to the real sealer's
  registered key, whose private half it does not hold. This closes the lockout
  at issue time. A **standing-key-signed demand request** is retained as
  *optional future hardening* against webhook-trigger nuisance/DoS — **not built
  now** (the advance model wants standing keys, not the per-window ephemeral keys
  that signed-request would also enable, so its marginal benefit does not justify
  the wire-format + verification surface today).
- **The root holder verifies the voucher before binding.** `signAdvanceDelegation`
  / the kit checks the custodian voucher against a **pinned registrar key**
  before signing. This protects the root holder's *signing decision* — which
  precedes any sealed artifact and is therefore **not** covered by the
  self-authenticating-artifact ("pipe") property (a certificate signed to the
  wrong key is still perfectly self-authenticating against `K(L)`) — against a
  **compromised coordinator**, which is a credential and attack-surface domain
  distinct from the custodian (internet-facing Worker+DO vs KMS-IAM-gated
  service). Membership-at-issue lives inside the coordinator and so does not
  defend this surface; the voucher does.

### Genesis orchestration (branch 3)

Standing keys are per-sealer, shared across logs, and registered at sealer boot,
so they (and their vouchers) **pre-exist any log**. Genesis pre-delegation is
therefore just "fire the standing entry's `delegation.required` to the new log's
signing route" — no per-log key generation, no waiting on the sealer.

- The coordinator fires the genesis **PUSH** when a signing route is set up, **or
  when the standing key registers, whichever is second** (any-order safe). Fan-out
  is bounded to logs **awaiting their first standing delegation**; deterministic
  re-derivation means a sealer restart re-registers the *same* key, so existing
  certificates stay valid and are **not** re-fired.
- The **PULL** path (`GET …/pending-delegation`) is retained for signers who
  prefer to poll and for renewal anticipation.
- **Hands-off signers** (ARC-0022's mode C, where a hosted wallet signs on the
  owner's behalf) rely on the PUSH — without it the first seal reintroduces
  on-demand latency for exactly the users who chose hands-off. Signers who hold
  their own key (mode B) may consume the webhook or poll. **Self-host** is N/A.

### Availability posture and boot (supersedes the "degrade to on-demand" note)

The custodian is **required at boot for hosted sealers**: no seed ⇒ no standing
key ⇒ no registered key ⇒ no delegation. The demand path **no longer degrades to
arbitrary-key on-demand** — that path is closed — so the earlier Consequences
statement ("unavailable ⇒ the sealer degrades to on-demand-only, which is exactly
today's behaviour") is **superseded**: cold start during a custodian outage cannot
seal. A **running** sealer keeps its standing private key in RAM and survives
custodian outages; only cold-start-during-outage is affected. Requirements:
sealer and custodian **start in any order** (the sealer **retries seed derivation
with backoff rather than crashlooping**), and both **recover cleanly after pod
restarts** via deterministic KMS-MAC re-derivation (same seed → same keys →
outstanding certificates valid). A local **emergency seed at rest** was rejected:
it would reintroduce exactly the exfiltratable at-rest material KMS-MAC derivation
exists to eliminate; custodian HA is the mitigation instead.

## Considered options

- **Seed in the operator's secret store** — original draft.
  Rejected on review: a durable, exfiltratable secret at rest in a
  third-party SaaS perimeter, with no use-time audit trail; KMS-MAC
  derivation keeps the capability inside the custody-key IAM perimeter
  with logging, and leaves nothing at rest.
- **KMS-wrapped random key persisted in R2** — wrap/unwrap via custodian.
  Rejected: security comparable to KMS-MAC derivation (attacker needs
  KMS IAM either way) but adds load-bearing state — losing the wrapped
  blob orphans every outstanding certificate — plus wrap-format and
  lifecycle management that pure derivation avoids.
- **KMS-resident delegate key, custodian signs every signature** —
  strongest custody (key never exists outside KMS, HSM path) but a
  checkpoint needs 1 + one-per-peak signatures (10–25 at scale):
  ~0.5–1.5s added per seal, KMS quota/cost coupling, and a hard custodian
  dependency on the self-hostable sealer path. Revisit if threat model
  changes; the peak-receipt structure (independently pre-signed peaks) is
  load-bearing and must not be restructured to enable batch signing.
- **Coverage retrieval only, keys still on demand** (the low-latency
  sealer work's item as originally scoped): fixes retrieval but signers
  still cannot sign before the sealer invents a key — first seals stay
  on-demand. Subsumed by this ADR.
- **Per-log delegate keys:** no security gain (Q1), multiplies signer
  interactions and registration state; rejected.
- **Range pad as permanent policy:** operator-side compensation for a
  signer-side decision; removed in favour of signer-owned horizons.
- **Coordinator tracks sealed size to reject below-horizon certs:** adds a
  sealer→coordinator state coupling and failure mode for marginal hygiene;
  rejected — staleness is expiry/supersession only.
- **`kind` discriminator on pending entries:** rejected on review — advance
  and demand entries are handled identically by signers and submit
  validation; the only real difference is the presence of a demanded
  window, so the schema says exactly that and nothing more.

## Consequences

- New coordinator surface: delegate-key registration, uniform pending
  entries (standing key always listed), public current-delegation read,
  coverage-matched issue, staleness rejection on submit. New custodian
  surface: the fixed-prefix seed-derivation endpoint over a dedicated KMS
  MAC key. New sealer subsystem: boot-time seed derivation + HKDF key
  schedule + registration client; lease construction resolves the private
  key by matching the certificate's bound public key against the standing
  set.
- `DELEGATION_RANGE_PAD` is removed once advance delegation lands
  (falsifiable outcome: latency unchanged even with tightly-bound
  delegations, because anticipation moved to the signer).
- E2e/kits can pre-delegate as soon as a logId is known — the wallet-mode
  pull-signing loop is no longer required *during* registration flows.
- No new secret at rest. The new operator obligations are IAM policy on
  the KMS MAC key, the epoch rotation runbook, and custodian availability
  at sealer boot (unavailable ⇒ the sealer degrades to on-demand-only,
  which is exactly today's behaviour).
- Verification paths (offline receipt verify, on-chain, coordinator) are
  untouched — certificates are unchanged in shape and meaning.
- **Issue-time expiry filter (behaviour change; found on review).** Coverage
  retrieval only returns certificates with `expires_at > now`; the prior
  exact-match path returned a stored certificate regardless of expiry. This is
  a correctness improvement (an expired delegation is unusable), but operators
  should expect a `202` + re-issue for a log whose only certificate has lapsed,
  rather than a stale `200`. A pre-migration certificate (NULL coverage
  columns) is served through a scoped exact-match fallback so those logs do not
  regress during the migration window.
- **Rollout ordering (design hole found on review).** Coverage retrieval can
  return a certificate bound to a *rotated* delegate key; the sealer can only
  use it once it resolves the private key from the returned certificate
  (`DelegateKeySet.KeyFor`). Deploy order is therefore the coordinator
  (additive) → the sealer's consumption of the returned key → enable; keep
  `DELEGATE_KEY_EPOCH=0` until the sealer side ships so a sealer is never
  handed a certificate it cannot sign with.

---

## Resolved detail — 2026-07-25: what "the webhook" is, and who receives it

The lazy path retained above ("pending entry + webhook/pull signing") refers to
exactly one mechanism: the coordinator's **`delegation.required`** event. Two
points are now settled and are not open to interpretation elsewhere in this ADR:

- **It is not the sealer nudge.** That name belongs to ranger publishing seal
  hints, specified in
  [arbor ADR-0007 low-latency-sealer-trigger](https://github.com/forestrie/arbor/blob/main/docs/adr/adr-0007-low-latency-sealer-trigger.md).
  The two mechanisms are unrelated; only the delegation event is meant wherever
  this ADR says "webhook".
- **The receiving endpoint may be instance-level, not per log.** An instance
  owner running many logs registers one webhook, copied into each log's config
  row at registration. Signers who "choose not to pre-delegate" therefore do not
  incur per-log webhook setup. Where no webhook exists at all, delegation works
  **only** by pre-emptive supply — which is the same choice this ADR already
  frames, stated as a supported configuration rather than a degraded one.

The delegation event payload is unchanged: `DelegationRequiredEvent` already
carries `logId`, so an instance-level receiver knows which log to sign for. A
receiver serving many logs **must** verify that `logId` is one it owns before
signing.

---

## As implemented

Recorded on promotion (2026-09-26) against arbor `main`. The decision above
stands; these are the places where the shipped code is more specific than, or
differs from, the text written before it.

**The derivation, exactly.** The custodian's seed-derivation endpoint
(`POST /api/delegate-seed`) computes the seed as the HMAC-SHA256 `MacSign`, in
Cloud KMS, of the ASCII string
`forestrie/sealer-delegate-seed/v1/<sealerId>/<epoch>` (slash-separated, epoch
in decimal), under a dedicated MAC key; it refuses epoch 0 and any `sealerId`
not on its allowlist
([`handle_delegate_seed.go`](https://github.com/forestrie/arbor/blob/main/services/custodian/src/handle_delegate_seed.go)).
The key is then HKDF-SHA256 over that seed with an empty salt and the info
string `forestrie/delegate-key/v1/<epoch>/<index>`; 40 bytes of output are
reduced modulo *n* − 1 and incremented, giving a P-256 scalar in [1, *n* − 1]
([`derive.go`](https://github.com/forestrie/arbor/blob/main/services/pkgs/delegatekeys/derive.go)).
The sealer and the custodian both call this one function, so the key the
sealer signs with and the public key the custodian registers cannot drift.

**One key per epoch, not a set.** The proposal's "small set of standing
delegate keys" is, in the code, index 0 only. The sealer derives epoch N and,
when N > 1, epoch N − 1, each at index 0, and advertises the epoch-N key; the
custodian registers and vouches for index 0 of the epoch it was asked for.

**Epoch 0 keeps the on-demand, ephemeral model.** `DELEGATE_KEY_EPOCH` has no
default and the sealer refuses to start without it. At `0` delegation in
advance is off: the sealer generates a random per-log P-256 key when a seal
first needs one, requests an exact-range certificate for it, and still widens
that request by `DELEGATION_RANGE_PAD` (default 65536 MMR nodes). So the range
pad was not removed; it survives on this path only. At `1` or above the sealer
loads the derived keys, requests coverage of its true seal window with no pad,
accepts a certificate whose range covers that window, and signs with whichever
held key the returned certificate binds. The specification's description of
the sealing key — derived at boot, never at rest, one key across logs — is the
description of a sealer running at epoch 1 or above.

**Locally held seed is a test seam.** The proposal lets self-hosted sealers
substitute a locally held seed. The code keeps that seam (`DELEGATE_SEED`) for
tests only, consistent with the later ruling that self-hosters sign
checkpoints directly with `K(L)`.

**Boot without the custodian.** With epoch ≥ 1, a first failed key load
hands off to a background retry (exponential backoff, 1 s to 30 s) and the
sealer keeps running. Until the keys load, the sealer has no standing key and
falls through to the on-demand request with a random key; where the
coordinator enforces registered-key membership, that request records no
pending demand and fires no webhook, so the seal waits. That is the "cold
start during a custodian outage cannot seal" posture above, reached through
the coordinator's check rather than by the sealer refusing.

**Registration is best-effort and time-bounded.** The custodian registers
the standing key and its voucher after deriving the seed, and a registration
failure does not fail the seed response; the sealer's next boot retries.
Each registration carries a `notAfter` 720 hours after registration.

**KMS key-version rotation is not covered by the epoch overlap.** The
custodian always uses the newest enabled version of the MAC key. A new version
therefore changes every seed, as an epoch bump would, but the sealer's N − 1
overlap is re-derived under the same new version, so certificates bound to
keys from the previous key version are not kept usable across the change; the
signers must re-delegate.
