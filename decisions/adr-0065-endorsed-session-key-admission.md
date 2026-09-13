# ADR-0065: Endorsed session-key admission (the endorsement rides every leaf)

**Status:** ACCEPTED — one of the accepted decisions the specification under
[`spec/`](../spec/) rests on. Records the live-run finding of 2026-08-29 and
the review of the same day, in which every ruling below was ratified.
**Date:** 2026-08-29
**Categories:** [DELEGATION, WEBAUTHN, CUSTODY, VERIFICATION, ADMISSION,
WIRE-FORMAT]
**Related:** [ADR-0064](./adr-0064-passkey-session-key-endorsement.md)
(the endorsement artifact this ADR admits and moves to payload v2 —
amended by this ADR), [spec/delegation-and-webauthn-envelopes.md](../spec/delegation-and-webauthn-envelopes.md)
(the `-65800` envelope and its user-presence / user-verification policy split),
[ARC-0019](./arc-0019-grant-verification-model.md) §6 (statement signer
binding = `grantData`), univocity
[ADR-0008](https://github.com/forestrie/univocity/blob/main/docs/adr/adr-0008-webauthn-assertion-delegation-alg.md)
(the on-chain algorithm and the `GF_REQUIRES_USER_VERIFICATION` policy band),
[spec/leaf-admission-and-session-endorsement.md](../spec/leaf-admission-and-session-endorsement.md)
(the shipped wire-level rules)

## Context

ADR-0064 split custody of a passkey-rooted user log: the passkey is the
log root — `grantData` = passkey x‖y, the key univocity binds as
`logRootKey` and verifies delegations against — and a non-extractable
WebCrypto session key, endorsed once by the passkey, signs the per-turn
leaves. ADR-0064 §4 stated the offline chain root → endorsement → leaves
and promised zero per-leaf format change.

The first live run of that design (2026-08-29, the deployed browser client
against a live lane) proved every ceremony half — passkey root
pinned, session key endorsed at the deployed origin (assertion flags
UP|UV|BE|BS), the two-gesture WebAuthn sealing delegation accepted by
the live coordinator, the UV grant issued, the agent leaf receipted —
and then **every user leaf was refused by canopy SCRAPI admission with
`403 signer_mismatch`**. No attested turns, nothing to seal, and the
WebAuthn delegation proof never reached a checkpoint or the chain.

Two facts, both verified in-source, make this a design gap rather than a
bug:

1. **canopy admission binds a statement to `grantData` twice and is the
   only place that does.** `register-signed-statement.ts:209-242`
   requires `kid == statementSignerBindingBytes(grant)` (= `grantData[0:32]`
   for a 64-byte ES256 owner, `grant/statement-signer-binding.ts`) *and*
   verifies the statement signature under the key imported from
   `grantData`. Downstream, ranger content-hashes leaves, the sealer
   verifies delegation leases, the publisher lifts, and univocity
   verifies the root and the delegation — **nothing on the chain ever
   inspects a leaf signer**. ADR-0064 moved the leaf signer to the
   session key (envelope kid = session x, ARC-0019 §6) and gave canopy
   no way to learn the endorsement, so the endorsed key was
   unverifiable at the sole enforcement point. Phase 4a never hit this
   because there the session key *was* the root.
2. **The endorsement lived nowhere public.** It existed only in DO
   storage and the `/receipts` export — no log, receipt, or on-chain
   artifact carried the one link from the chain's root to every leaf
   signer. That is an unauditable verification story: the artifact an
   auditor needs most was operator-held state.

## Decision

### 1. canopy admission is THE enforcement point — for everything

Architectural principle, recorded here and in the platform invariants: **canopy
SCRAPI admission is the enforcement point for who may sign a leaf of a
log, for every custody shape.** The scribe DO's own check is a
client-side pre-flight that must agree with canopy, never a substitute
for it; the sealer and the chain attest the root and the delegation,
not the leaves. Any mechanism that asks a component other than canopy
to be authoritative for the leaf signer fails open for every client
that is not that component — the SCRAPI is permissionless and the grant
is the only credential.

### 2. The endorsement rides every leaf, in the unprotected header

The endorsement is carried **inside each leaf's own COSE Sign1**, in the
unprotected header at a new label:

```cddl
endorsed-leaf = COSE_Sign1<
  protected: {
    1: -7,                    ; ES256 — unchanged 4a per-turn profile
    3: tstr,                  ; content type, unchanged
    4: bstr .size 32          ; kid = SESSION key x (ARC-0019 §6, unchanged)
  },
  unprotected: {
    -65801: bstr              ; session-key endorsement v2 (§3), COSE Sign1 bytes
  },
  payload: bstr               ; unchanged
>
```

- **Label `-65801`** is reserved for the session-key endorsement.
  **`-65800` is the WebAuthn assertion envelope and MUST NOT
  be reused**: a `-65800` entry on a plain-ES256 leaf is a fail-closed
  rejection by the `@forestrie/encoding` envelope branch
  (`unexpected_webauthn_envelope`), never an endorsement.
- The endorsement is a COSE Sign1 in its own right (§3), embedded as
  bytes. It is **not** covered by the leaf's signature (unprotected),
  and does not need to be: it is self-authenticating under the passkey
  root, and it **is** covered by the leaf commitment — canopy's
  `contentHash` is SHA-256 of the entire statement bytes
  (`register-signed-statement.ts:292`), so the endorsement is in the MMR
  with the leaf.
- The **browser attaches the endorsement before signing** and the DO
  forwards the client's bytes untouched (`#registerUserLeaf` performs no
  decoration). The artifact the user signs and retains *is* the
  registered artifact; nothing on the proof path relies on fetching
  bytes back from a service.
- Under 4a custody (no passkey; the session key is the root) no
  endorsement is attached and nothing changes.

Cost: ~350 bytes of storage and bandwidth per leaf. The MMR is
unaffected (it holds hashes). ADR-0064 §4's "zero per-leaf format
change" is withdrawn for leaf *bytes*; the leaf **signature profile** is
untouched.

### 3. Endorsement payload v2 — validity window in the idtimestamp domain

The ADR-0064 §2 artifact keeps its envelope, kid, challenge binding and
fail-closed rules verbatim, and gains a validity window:

```cddl
endorsement-v2 = COSE_Sign1<
  protected: {
    1: -65800,                ; ALG_ES256_WEBAUTHN
    3: "application/vnd.forestrie.session-key-endorsement.v2+cbor",
    4: bstr .size 32          ; kid = passkey root x
  },
  unprotected: {
    -65800: [authenticatorData: bstr, clientDataJSON: bstr]  ; ADR-0063 §2
  },
  payload: {
    "sessionKey": bstr .size 64,   ; session public key x‖y
    "notBefore": uint,             ; unix milliseconds, inclusive
    "notAfter": uint               ; unix milliseconds, inclusive
  }
>
```

- Payload keys are the three text strings above, deterministic CBOR
  (RFC 8949 §4.2.1), integers as unsigned CBOR ints (major type 0);
  **no other keys**. The protected content type is the `.v2` identifier,
  so the version is signed.
- `notBefore`/`notAfter` are **unix milliseconds** — the time component
  of the log's idtimestamp (go-merklelog `massifs/idtimestamp.go`:
  `ms = (id >> TimeShift) + EpochMS(epoch)`). A leaf is inside the
  window iff `notBefore ≤ leafIdtimestampMs ≤ notAfter`. Choosing the
  idtimestamp domain is deliberate: idtimestamps are time-ordered,
  monotonic and linux-time representative, and every receipt carries
  one, so the window is checkable offline from public artifacts.
- **Malformed windows are rejected**: `notAfter ≤ notBefore`, or
  `notBefore` further in the future than the verifier's skew tolerance.
- **Window length is the client's choice** (default 7 days). It is safe
  to leave to the client because it bounds only the client's own
  session key: a longer window lengthens the user's own exposure and
  grants no capability beyond what the grant already scopes. A
  service-side maximum is optional hardening, not a requirement.
- **v1 endorsements (`…session-key-endorsement+cbor`, payload without
  the window) are rejected, not grandfathered.** The only live
  passkey-rooted log at the time of this decision is the demo, which
  re-onboards.

This **retires** ADR-0064's accepted risk "old endorsements never
expire": a superseded session key stops being admissible when its
window lapses, regardless of who holds it, with no per-log state
anywhere.

### 4. canopy admission rules (normative, fail-closed)

`register-signed-statement` derives the pair **(kid binding, signature
verify key) from exactly one source**:

1. **No `-65801` entry:** `grantData`, exactly as today — kid ==
   `grantData[0:32]` (or the 16-byte custodian kid for KMS-signed
   bootstrap statements), signature verified under the `grantData` key.
2. **`-65801` entry present:** the endorsement MUST verify as a §3
   artifact under the **`grantData` root** — the verifier's trust anchor
   is the coordinate pair *from `grantData`*, so `kid == root x` is
   pinned, with `requireUserVerification` iff `grant_user` carries
   `GF_REQUIRES_USER_VERIFICATION` (the grant is in
   evidence at admission, unlike the DO at onboarding). The window is
   checked against canopy's clock. The binding then becomes the
   endorsed `sessionKey`'s x, and the statement signature is verified
   under the endorsed session key.

Rules:

- A present-but-invalid endorsement is a **403 and admission never
  falls back** to the `grantData` binding. Problem-details reasons are
  distinct: `endorsement_invalid` (malformed, wrong alg, wrong content
  type, v1), `endorsement_root_mismatch` (does not verify under this
  grant's `grantData` — **including a bad signature**, see the
  amendment below), `endorsement_uv_required`, `endorsement_expired`
  (window, both directions, and malformed windows). `signer_mismatch`
  is reserved for kid ≠ the resolved binding.

> **Amended 2026-08-30 — bad signature is `endorsement_root_mismatch`,
> not `endorsement_invalid`.** As drafted, this section listed "bad
> signature" under `endorsement_invalid`. The implementation reports it
> as `endorsement_root_mismatch`, and the implementation is right: the
> verifier's trust anchor is a raw coordinate pair taken from
> `grantData`, so "this signature does not verify" and "this endorsement
> was issued under a different root" are **the same observation** and
> cannot be told apart without a second anchor to test against. Keeping
> them as separate reasons would have promised a distinction the
> verifier cannot make. `endorsement_invalid` therefore covers only
> failures decidable before signature verification — shape, algorithm,
> content type, version.
>
> Related: a separate `endorsement_not_yet_valid` distinction exists in
> `@forestrie/receipt-verify` but is **unreachable at admission**, where
> the not-before skew tolerance absorbs it and it collapses into
> `endorsement_expired`. Offline verifiers do distinguish the two, since
> they check the receipted idtimestamp with no skew. Found by verifying
> the shipped code against this ADR during the protocol documentation
> pass; wire-level detail in
> [`spec/leaf-admission-and-session-endorsement.md`](../spec/leaf-admission-and-session-endorsement.md)
> §5.3.
- The custodian 16-byte branch is **not consulted** when an endorsement
  is present.
- **The window check runs on every request, structurally outside any
  cache.** A cache of verified endorsements is an optimisation only:
  isolate-local, bounded, keyed by `sha256(endorsementBytes) ‖ grantData`,
  storing "verified OK" and nothing else — it can never admit more than
  an uncached verify would.
- UV policy has one declaration — the grant flag committed in the parent
  auth log — read identically by the chain (`_checkDelegationAlgConstraints`),
  canopy admission, and offline verifiers. The DO's onboarding
  `USER_ROOT_REQUIRE_UV` ([ADR-0064](./adr-0064-passkey-session-key-endorsement.md)
  ruling 3) remains its own pre-flight
  knob because at onboarding no grant exists yet.

### 5. One verification path, from public artifacts only

An auditor — the user, or a neutral third party with no relationship to
the operator — reconstructs the chain from public artifacts alone:

```
logRootKey(logId) on-chain  (= grantData, committed in the parent auth log)
  → endorsement (-65801, inside the leaf bytes): -65800 verify under the root,
    UV per the grant flag, window from the payload
    → sessionKey x‖y
      → leaf: kid == session x, ES256 signature under the session key
        → receipt: leaf bytes hash to the receipted index (inclusion),
          receipted idtimestamp ∈ [notBefore, notAfter]
```

`@forestrie/receipt-verify` owns this path (`verifyEndorsedLeaf`), a
**major** release (v2 payload). The export-fed path of ADR-0064 §4
(`resolveEndorsedSessionKey` over `userRootEndorsementB64`) is
**removed, not kept as a fallback** — there is exactly one way to
verify an endorsed leaf and no route back to verifying it under the
root. `/receipts` may continue to export `userRootEndorsementB64` and
`userSessionPublicKeyXY` for the UI's custody display; they are not
verification inputs.

Inclusion proofs are not complicated by this: proving inclusion already
requires the exact registered statement bytes (the leaf hash is derived
from `contentHash` over the full Sign1), and those bytes now carry the
endorsement. Tampering with the endorsement changes `contentHash`, so
inclusion fails; substituting a different valid endorsement changes the
session key, so the leaf signature fails — closed both ways.

## Accepted risks (carried, retired, new)

- **Carried from ADR-0064:** in-page compromise can still attest
  content while the page is open (option A's residual — the passkey
  gates authorisation, not per-turn content); no freshness proof of the
  gesture itself; the endorsement is public and replayable (presenting
  it adds no capability — a leaf still needs the session private key).
- **Retired:** "old endorsements never expire" — bounded now by the
  window (§3).
- **Scope:** the payload carries no `logId`; one passkey root owning
  several logs may reuse one endorsement across them. That is the same
  person and the same non-extractable browser key, and scope comes from
  the grant; and since the endorsement now rides inside each committed
  leaf, its effective scope is the leaf it is attached to. Recorded as
  retained.
- **Clock:** admission's window check depends on canopy's clock; skew
  tolerance is small and the offline check against the receipted
  idtimestamp is the authoritative one.

## Alternatives considered

**A request header (`Forestrie-Signer-Endorsement`) beside the grant.**
Stateless and zero per-leaf bytes — and the first recommendation. Rejected
as a fussier API than necessary and, decisively, because the
endorsement would then live outside the committed leaf: auditors would
again depend on an export for the link from root to signer.

**An unprotected header on the grant Sign1.** Works: the grant
commitment covers fields, not the object (`grant-commitment.ts`:
`logId ‖ grantFlags ‖ maxHeight ‖ minGrowth ‖ ownerLogId ‖ grantData`),
so the grant's unprotected map is neither committed nor
authority-signed and could carry the endorsement. It merely repackages
the header alternative inside the Authorization value, at the cost of
the grant object no longer being immutable authority output and two
principals' claims sharing one signed object. Not chosen.

**Committed in the grant (`grantData` or a new preimage field).** Cannot
work cheaply: the preimage formula is contract code; `grantData` is the
64-byte root that univocity reads as `logRootKey` and canopy
auto-forwards on that exact shape; extending either is a univocity +
canopy + arbor change; and every session-key rotation would re-issue
the grant — a new owner-log leaf and, for paid grants, an x402 burn.
It also inverts custody: the authority would attest the session key,
which is ADR-0064's rejected "authority co-endorsement" by the back door.

**The endorsement as the user log's first leaf** (and again per
rotation). Admissible today with no canopy change (kid = root x) and
gives a receipted succession record. **Deferred**: not needed for
auditability once every leaf carries its endorsement, the parent auth
log is fully transparent, and it adds a second artifact type to
register, order, and hold turns behind.

**Epoch/freshness binding to the current grant; an MMR index range in
the endorsement.** Both assessed and set aside. Freshness against a
per-batch `grant_user` costs a gesture per batch (breaking the
one-gesture-ever budget); binding to a long-lived grant loses the
freshness meaning. An index range cannot be enforced at admission (the
sequencer assigns the index afterwards) — though the
browser does know its own indices (its first statement is index 0 and
every receipt returns an index), which is what made the
**idtimestamp window (§3) the contained form of the same idea**.
Recorded as **future exploration** for a v3 payload if a use case for
index scoping appears.

**`grantData` = session key; authority-issued second grant over the
session key; on-chain per-log signer set; countersigned leaves; the
passkey signing every leaf.** Rejected for the reasons in ADR-0064
§Alternatives: the session key must never be
the on-chain root; the authority must not mint leaf signers; leaf policy
does not belong on the chain; a gesture per leaf breaks the
budget.

## Consequences

- **canopy** (`@forestrie/encoding`, `@forestrie/receipt-verify`,
  canopy-api): the `-65801` label; the v2 endorsement build/verify and
  `verifyEndorsedLeaf` (receipt-verify major); admission signer
  resolution with the four new problem reasons and the window check
  outside the cache; system specs for every fail-closed rule; a lane-A
  deploy.
- **thinker**: the browser attaches the endorsement before signing; the
  onboarding endorsement moves to v2 with a scheduled re-endorsement
  gesture as the window nears lapse (surfaced like the sealing-lease
  countdown); the DO pre-flight mirrors canopy's exact check and
  forwards bytes untouched; the export-fed offline path is removed from
  `verify-receipts.mjs` and the ProofPanel; `/goldens` captures a v2
  endorsement golden from a real authenticator.
- **arbor / univocity**: no change — confirmed in-source; nothing
  downstream of admission inspects a leaf signer, and the chain's
  `logRootKey`, delegation verification and UV policy are untouched.
- **platform invariants**: the grant-verification rule reworded (the grant is
  verified under the owner authority; the statement under `grantData` **or** a
  session key the `grantData` root has endorsed within the endorsement's
  validity window) and the §1 principle recorded — see
  [rules/platform.md](../rules/platform.md) P10.

## References

- [ADR-0064](./adr-0064-passkey-session-key-endorsement.md) — the
  endorsement artifact (v1), DO pin semantics, accepted risks.
- [spec/delegation-and-webauthn-envelopes.md](../spec/delegation-and-webauthn-envelopes.md)
  — the `-65800` envelope, the challenge binding, the user-presence /
  user-verification policy, and the fail-closed rules.
- [spec/leaf-admission-and-session-endorsement.md](../spec/leaf-admission-and-session-endorsement.md)
  — the shipped admission rules, failure vocabulary and offline route.
- canopy: `packages/apps/canopy-api/src/scrapi/register-signed-statement.ts`
  (admission, `contentHash`), `src/scrapi/grant-auth.ts`,
  `src/grant/statement-signer-binding.ts`, `src/grant/grant-commitment.ts`;
  `packages/shared/encoding/src/verify-cose-sign1.ts` (`-65800` branch);
  `packages/libs/receipt-verify/src/session-key-endorsement.ts` (v1 →
  v2).
- [go-merklelog](https://github.com/forestrie/go-merklelog)
  `massifs/idtimestamp.go` — the idtimestamp time component.
