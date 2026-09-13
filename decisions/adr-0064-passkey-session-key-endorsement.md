# ADR-0064: Passkey session-key endorsement (user-log leaf signing)

**Status:** ACCEPTED — one of the accepted decisions the specification under
[`spec/`](../spec/) rests on. Decided 2026-08-23, with four refining rulings
taken the same day. **Amended by
[ADR-0065](./adr-0065-endorsed-session-key-admission.md) (2026-08-29)**:
the endorsement moves to payload v2 (validity window) and rides every
leaf's unprotected header so canopy admission can verify the endorsed
signer; §4's "zero per-leaf format change" is narrowed and the
"immortal superseded endorsements" risk is retired — see the amendment
notes inline below. The custody split (§1) and pin semantics (§3) stand.
**Date:** 2026-08-23
**Categories:** [DELEGATION, WEBAUTHN, CUSTODY, VERIFICATION, WIRE-FORMAT]
**Related:** [spec/delegation-and-webauthn-envelopes.md](../spec/delegation-and-webauthn-envelopes.md)
(the WebAuthn assertion envelope this ADR applies to a new artifact type),
[ARC-0019](./arc-0019-grant-verification-model.md) §6 (the user-envelope
profile: kid = root x),
[spec/leaf-admission-and-session-endorsement.md](../spec/leaf-admission-and-session-endorsement.md)
(the shipped wire-level rules)

## Context

A WebAuthn passkey emits only WebAuthn assertions, and **every assertion
costs a user gesture**. Phase 4a introduced per-turn user envelopes: `chat.svelte.ts` signs one plain-ES256 COSE Sign1 per chat
turn with a non-extractable WebCrypto P-256 key (the 4a "user root").
If the passkey became that root directly, either every chat turn costs
a Touch ID (breaking the accepted gesture budget — gestures at the ~6h
lease cadence only), or the leaves go unsigned.

Per-turn `-65800` leaves are additionally rejected on cost-containment
grounds: they would push the WebAuthn envelope into **every receipt's
leaf**, where the accepted position is that the second signature envelope
stays confined to ceremony artifacts.

So the passkey root needs a way to authorise a silent per-turn signer
without signing per-turn — an indirection.

## Decision

### 1. Custody split: passkey signs ceremonies, session key signs leaves

The passkey is the **log root** and signs ceremony artifacts only (the
delegation certificate and on-chain proof — see [spec/delegation-and-webauthn-envelopes.md](../spec/delegation-and-webauthn-envelopes.md)). The 4a
non-extractable WebCrypto P-256 key is **demoted from root to session
key**: it keeps signing the plain-ES256 per-turn user envelopes,
unchanged in format. The link between them is a single **endorsement**
artifact, signed once by the passkey at onboarding (one extra gesture).

Where no authenticator is available, 4a stands unchanged: the session
key *is* the root, and no endorsement exists.

### 2. The endorsement artifact — the WebAuthn envelope, typed payload

The endorsement is a COSE Sign1 in the WebAuthn assertion envelope, with explicit
domain separation (ruling 1 — a bare 64-byte payload under a
generic `-65800` envelope would be confusable with any future artifact
signing 64 bytes):

```cddl
endorsement = COSE_Sign1<
  protected: {
    1: -65800,                ; ALG_ES256_WEBAUTHN
    3: "application/vnd.forestrie.session-key-endorsement+cbor",
    4: bstr .size 32          ; kid = passkey root x (ARC-0019 §6 shape)
  },
  unprotected: {
    -65800: [authenticatorData: bstr, clientDataJSON: bstr]  ; the envelope
  },
  payload: { "sessionKey": bstr .size 64 }   ; session public key x‖y
>
```

- The content type (label 3) sits in the **protected** header, so
  `Sig_structure` covers it — the artifact's type is signed.
- Challenge binding, `webauthn.get` type check, low-s P1363 signature,
  and the fail-closed rules are taken verbatim from the envelope
  specification; this ADR adds one rule: a `-65800` artifact claiming this content type whose
  payload is not exactly the map above is a verification failure.
- No `iat`/expiry claim: the artifact is offline-forever by design
  (ruling 1 took the typed shape without a timestamp).

> **Amended by ADR-0065 (2026-08-29).** This v1 payload is **superseded**
> by the v2 payload `{sessionKey, notBefore, notAfter}` under content
> type `application/vnd.forestrie.session-key-endorsement.v2+cbor`
> (ADR-0065 §3) — a validity window in the idtimestamp domain (unix
> milliseconds), default 7 days, client-configurable. v1 artifacts are
> rejected by v2 verifiers, not grandfathered.

### 3. DO verification and pin semantics at `POST /user-root`

The scribe DO verifies the endorsement at `POST /user-root` using the
`@forestrie/encoding` ≥0.6.0 `verifyCoseSign1WithParsedKey` `-65800`
branch, keyed by the posted passkey root x‖y, then pins. Semantics
(ruling 2 — **root-TOFU, no downgrade**):

- **Root**: trust-on-first-use under the wcc-1 session; a later post
  naming a *different* root is 409, exactly the 4a rule.
- **Session key**: rotatable under the pinned root — a post with the
  same root, a new session key, and a fresh valid endorsement over that
  key re-pins the session key. Rotation is one gesture, no support flow.
- **No custody downgrade**: once a passkey root is pinned, a bare
  4a-shape post (64-byte key, no endorsement) is rejected fail-closed.
  In-page script must never be able to silently swap the user off
  passkey custody.

**UV at onboarding** (ruling 3): the endorsement precedes the
grant (`postUserRoot` runs at bootstrap before first DO touch), so
`GF_REQUIRES_USER_VERIFICATION` has no grant to live in at that moment.
User verification on the endorsement assertion is therefore **service
configuration**, not grant policy: the demo DO passes
`requireUserVerification: true`. User presence is always required.
Ceremony assertions remain grant-flag governed.

### 4. Receipts export and the offline chain — owned by `receipt-verify`

`/receipts` exports the endorsement beside `userRootPublicKeyXY` (which
now names the **passkey** root). Offline verification chains:

```
grant (root = passkey x‖y)
  → endorsement (-65800 verify against the passkey root)
    → session public key x‖y
      → plain-ES256 per-turn leaves (unchanged 4a profile)
```

Ruling 4, taken beyond the proposal: this verification path lands in
**`@forestrie/receipt-verify` 0.12.0, released before the browser work
merges** — third-party offline verification of endorsed logs is real
from day one, not a browser-local script. The leaf profile is untouched:
zero per-leaf format change anywhere in the platform.

> **Amended by ADR-0065 (2026-08-29) — admission gap found in the first
> live run.** The claim above held for the leaf
> *signature profile* but not for admission: canopy SCRAPI is the only
> component on the chain that enforces the leaf signer, and it binds
> the statement to `grantData` (the passkey root) by kid equality and
> signature verification — so every session-signed leaf was refused
> `403 signer_mismatch` at the first live run, and the endorsement,
> living only in DO storage and this export, was on no public audit
> path. Narrowed to: **zero change to the leaf signature profile; leaf
> bytes gain the endorsement in the unprotected header (label
> `-65801`), committed via `contentHash`**, and the chain above is
> verified from the leaf bytes alone (`receipt-verify`
> `verifyEndorsedLeaf`); the export-fed path described here is removed.

## Accepted risks (explicit)

- **In-page compromise can still attest content.** The session key
  signs silently, so XSS can attest fabricated per-turn content while
  the page is open. This residual is deliberately retained: the passkey
  gates *authorization*
  (ceremonies — the ability to seal and delegate), not per-turn
  *content*. It cannot steal either key.
- **No freshness.** The endorsement carries no nonce or server
  challenge; the DO cannot prove the gesture happened recently. By
  design — offline verifiers need the artifact valid forever.
- ~~**Old endorsements never expire.** After rotation, a superseded
  endorsement remains a cryptographically valid artifact. Harmless:
  leaf admission is gated by the DO's *current* pin, so damage is
  bounded to what the log admitted while the old key was pinned — which
  the log records.~~ **RETIRED by ADR-0065 (2026-08-29):** the v2
  payload's validity window bounds every endorsement; canopy admission
  enforces it on every request and offline verifiers check the
  receipted idtimestamp against it. (The premise "leaf admission is
  gated by the DO's current pin" was also wrong — canopy is the
  enforcement point; ADR-0065 §1.)
- **The endorsement is public and replayable** (it ships in every
  receipts export). Replaying it at another DO pins a root the replayer
  cannot use: the first leaf requires the session private key, which is
  non-extractable. The pin is additionally bound to the wcc-1 session
  that posts it.

## Alternatives considered

**Per-turn `-65800` leaves (passkey signs every turn).** Rejected: a
Touch ID per chat turn breaks the accepted gesture budget (gestures at
the ~6h lease cadence), and pushes the WebAuthn envelope into every leaf
against the accepted cost containment.

**Authority co-endorsement (authority signs both keys into
`grant_user`).** Rejected: it breaks the 64-byte owner shape canopy
auto-forwards, and an authority able to mint leaf signers surrenders
the self-custody property this design exists to protect (§1). Multi-key
endorsement remains the **recovery** story, never the leaf story.

**Per-ceremony session-key endorsement (endorse inside each delegation
certificate).** Rejected: the delegation certificate endorses the DO's
*sealing* key; overloading it with the user-envelope signer couples two
unrelated lifetimes (lease ~6h vs session key ~indefinite) and forces a
re-endorsement gesture per lease for no custody gain.

## Consequences

- Onboarding costs **one** extra gesture; rotation costs one gesture;
  recovery rides passkey sync — session-key loss is just a rotation,
  passkey loss is covered by the platform sync story.
- `receipt-verify` grows the endorsement path (0.12.0) — a release
  train ahead of thinker 4.1 on the critical path.
- The DO's `POST /user-root` grows three enforcement rules (root-TOFU,
  endorsed rotation, downgrade rejection) and a UV config knob.
- A pre-endorsement DO holding a 4a root accepts an **upgrade** post
  (same session key, now endorsed under a new passkey root) as a
  root-change — which is 409 under root-TOFU. Upgrading an existing 4a
  log therefore requires the 4a reset/top-up path; fresh logs onboard
  directly. Accepted for the demo.

## References

- [spec/delegation-and-webauthn-envelopes.md](../spec/delegation-and-webauthn-envelopes.md)
  — the envelope, the challenge binding, the fail-closed rules, and the
  user-presence / user-verification policy split.
- [ADR-0065](./adr-0065-endorsed-session-key-admission.md) — payload v2, the
  validity window, and the admission rules that supersede §4 here.
- [spec/leaf-admission-and-session-endorsement.md](../spec/leaf-admission-and-session-endorsement.md)
  — the shipped artifact, admission rules and offline route.
- [ARC-0019](./arc-0019-grant-verification-model.md) §6 — the statement-signer
  binding profile (kid = root x).
- Verifier: canopy `packages/shared/encoding/src/verify-cose-sign1.ts`
  (`-65800` branch, `requireUserVerification`); offline:
  `libs/receipt-verify`.
