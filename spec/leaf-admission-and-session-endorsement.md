# Leaf admission and the session-key endorsement

**Status:** LIVE
**Date:** 2026-08-30
**Audience:** implementers of a Forestrie client or verifier, and anyone
checking that an entry in a self-custodied log was signed by a key its owner
authorised.
**Related:** [receipt-trust-model.md](./receipt-trust-model.md)
(question 4, attribution),
[delegation-and-webauthn-envelopes.md](./delegation-and-webauthn-envelopes.md)
(the assertion envelope this artifact reuses),
[label-registry.md](./label-registry.md),
[ADR-0064](../decisions/adr-0064-passkey-session-key-endorsement.md),
[ADR-0065](../decisions/adr-0065-endorsed-session-key-admission.md),
[glossary.md](../glossary.md).

## Summary

A passkey cannot sign silently — every WebAuthn assertion costs a deliberate
user gesture. A conversational log writes an entry per turn. Those two facts
cannot both be satisfied by having the root key sign entries, so the root
**endorses** a session key that signs them, and the endorsement is the single
artifact linking the log's on-chain root to every entry's signer.

This document specifies that artifact, where it travels, and the exact rules
under which an entry is admitted or refused.

## 1. The custody split

| Key | Held by | Signs | Gesture cost |
|---|---|---|---|
| **Root** (passkey) | The platform authenticator | Ceremony artifacts only — the delegation certificate and the on-chain proof, plus the endorsement itself | One per signature |
| **Session key** (non-extractable WebCrypto P-256) | The browser, unexportable by script | Every per-turn entry, in the unchanged plain-ES256 profile | None |

The session key is *demoted*, not introduced: it was the log root before
passkey custody existed, and where no authenticator is available it still is —
in that configuration no endorsement exists and nothing in this document
applies.

The split is deliberate about what it does and does not protect. The passkey
gates **authorisation** — the ability to seal, to delegate, to move the log's
authority. It does not gate per-turn **content**: script running in the page
can ask the session key to sign, because that is the whole point of a key that
signs without a gesture. What an attacker cannot do is steal either key,
re-root the log, or extend its authority.

## 2. Where the endorsement travels, and why it matters

**The endorsement rides inside each entry, in the COSE unprotected header at
`TBD2`.**

This is the design's load-bearing decision, and it is an **auditability**
choice rather than a cryptographic one. The artifact was already sound when it
lived in operator storage and a `/receipts` export; it was still useless to an
independent verifier, because the one link from the log's on-chain root to
every entry's signer was a thing you had to ask the operator for. That is not a
verification story — it is a request.

Carried in the entry, three things follow:

- **It is committed for free.** Admission content-hashes the *entire* statement
  bytes, so the endorsement enters the log's commitment with the entry. No
  extra artifact to register, order, or hold turns behind.
- **It cannot go missing.** The artifact the user signs and retains *is* the
  registered artifact. Nothing on the proof path depends on fetching bytes back
  from a service.
- **Tampering is closed both ways.** Editing the endorsement changes the
  content hash, so inclusion fails. Substituting a different valid endorsement
  changes the session key, so the entry's signature fails.

The cost is roughly 350 bytes per entry. The Merkle structure is unaffected —
it holds hashes.

## 3. The endorsement artifact

An untagged COSE Sign1, embedded in the entry as a byte string.

```cddl
endorsement = COSE_Sign1<
  protected: {
    1: -65800,                ; ALG_ES256_WEBAUTHN
    3: tstr,                  ; content type, v2 identifier (below)
    4: bstr .size 32          ; kid = the passkey root's x coordinate
  },
  unprotected: {
    TBD1: [authenticatorData: bstr, clientDataJSON: bstr]
  },
  payload: {
    "sessionKey": bstr .size 64,   ; session public key x‖y
    "notBefore":  uint,            ; unix milliseconds, inclusive
    "notAfter":   uint             ; unix milliseconds, inclusive
  }
>
```

- **Content type is in the *protected* header**, so the artifact's type is
  signed. The v2 identifier is
  `application/vnd.forestrie.session-key-endorsement.v2+cbor`.
- **v1 is rejected, not grandfathered.** The v1 identifier
  (`…session-key-endorsement+cbor`, payload without a window) fails
  verification outright.
- **Payload keys are exactly those three text strings.** Any other key count is
  a decode failure — the shape is checked, not merely read.
- `signature` is the raw 64-byte P1363 `r ‖ s`, low-s normalised.
- The envelope, challenge binding and `webauthn.get` check are exactly as in
  [the delegation document](./delegation-and-webauthn-envelopes.md) §1; this
  artifact reuses that machinery unchanged.

### 3.1 Why the payload is typed rather than bare

A bare 64-byte payload under a generic WebAuthn envelope would be confusable
with any future artifact that signs 64 bytes. The explicit content type in the
protected header is the domain separation.

### 3.2 The validity window

`notBefore` and `notAfter` are **unix milliseconds**, and both bounds are
**inclusive**. The domain is deliberate: it is the time component of the log's
own idtimestamp, and every receipt carries one — so the window is checkable
offline from public artifacts, with no clock and no service call.

An entry is inside the window iff
`notBefore <= leafIdtimestampMs <= notAfter`.

Malformed windows are rejected: `notAfter <= notBefore`, or a `notBefore`
further in the future than the verifier's skew tolerance.

**Window length is the client's choice**, defaulting to seven days. This is
safe to leave to the client because it bounds only the client's own session
key: a longer window lengthens the user's own exposure and grants no capability
the grant does not already scope. A service-side maximum would be optional
hardening, not a requirement.

The window is what retires the otherwise-unbounded life of a superseded
session key. Once it lapses the endorsement stops being admissible regardless
of who holds it — no revocation list, no per-log state anywhere.

## 4. The endorsed entry

```cddl
endorsed-leaf = COSE_Sign1<
  protected: {
    1: -7,                    ; ES256 — the unchanged per-turn profile
    3: tstr,                  ; content type, unchanged
    4: bstr .size 32          ; kid = the SESSION key's x coordinate
  },
  unprotected: {
    TBD2: bstr                ; the endorsement above, as COSE Sign1 bytes
  },
  payload: bstr               ; unchanged
>
```

The **entry's signature profile is untouched** — it is the same plain-ES256
entry it always was. Only the bytes grew, and only in the unprotected header.

The endorsement is **not** covered by the entry's signature, and does not need
to be: it is self-authenticating under the passkey root, and it is covered by
the entry's content hash.

**The browser attaches the endorsement before signing**, and the Durable Object
forwards the client's bytes untouched — it performs no decoration. This matters
for the audit story: there is exactly one byte sequence, produced by the user,
and it is the one that gets committed.

`TBD1` must never appear on an entry. A WebAuthn envelope on a plain-ES256
entry is a fail-closed rejection, never an endorsement.

## 5. Admission — the normative rules

Admission at the SCRAPI edge is **the only enforcement point in the platform
for who may sign an entry**, for every custody shape. Nothing downstream
inspects an entry's signer: the sequencer content-hashes, the sealer verifies
leases, the publisher lifts proofs, the contract verifies the root and the
delegation. A pre-flight elsewhere — including the client's own — is a
courtesy, never a substitute.

### 5.1 Exactly one signer source

The pair *(kid binding, signature verification key)* is derived from **exactly
one** source:

| Condition | Binding | Verification key |
|---|---|---|
| No `TBD2` entry | `grantData` — the first 32 bytes of a 64-byte ES256 owner, or the full bytes for a 16-byte custodian kid | The key imported from `grantData` |
| `TBD2` present | The endorsed `sessionKey`'s x coordinate | The endorsed session key |

When an endorsement is present the **custodian 16-byte branch is not
consulted**.

### 5.2 Verification order

1. The endorsement must verify as a §3 artifact **under the `grantData`
   root** — the trust anchor is the coordinate pair from the grant, so
   `kid == root x` is pinned.
2. User verification is required **iff** the grant carries
   `GF_REQUIRES_USER_VERIFICATION`. User presence is always required.
3. The window is checked against the service clock, with a small
   forward-tolerance for skew.
4. The binding becomes the endorsed session key's x; the entry's signature is
   verified under the endorsed session key.

### 5.3 Fail-closed, with distinct reasons

**A present-but-invalid endorsement is a refusal, and admission never falls
back to the `grantData` binding.** Falling back would let anyone strip a valid
endorsement and be admitted under the `grantData` binding instead.

| Reason | Fires when |
|---|---|
| `signer_mismatch` | `kid` does not equal the resolved binding. Reserved for exactly that |
| `endorsement_invalid` | Malformed, wrong algorithm, wrong content type, or v1 |
| `endorsement_root_mismatch` | Verifies as an artifact, but not under this grant's `grantData` |
| `endorsement_uv_required` | The grant requires user verification; the assertion lacks the flag |
| `endorsement_expired` | Outside the window, in either direction, or a malformed window |

> **Why a bad signature is a root mismatch.** The trust anchor is a raw
> coordinate pair taken from the grant, so "this signature does not verify"
> and "this endorsement was issued under a different root" are the *same
> observation* — there is no second anchor to test against that would separate
> them. Reporting them as distinct reasons would promise a distinction the
> verifier cannot make. `endorsement_invalid` therefore covers only failures
> decidable *before* signature verification: shape, algorithm, content type,
> version. (ADR-0065 §4 originally listed bad signatures under
> `endorsement_invalid`; it was amended on 2026-08-30 to match.)

> **Implementation note — one reason is unreachable at admission.** A separate
> `endorsement_not_yet_valid` distinction exists in the verification library
> but collapses into `endorsement_expired` at the admission edge, because the
> service's skew tolerance already absorbs the not-yet-valid case. Offline
> verifiers can and do distinguish the two.

### 5.4 The window check cannot be cached

The window check runs on every request, **structurally outside any cache**. A
cache of verified endorsements is an optimisation only: it may store "this
endorsement verified against this root" and nothing else, so it can never admit
more than an uncached verify would.

*No such cache currently exists.* The constraint is recorded because it governs
one if it is ever added.

## 6. Offline verification

There is exactly **one** route, and no fallback. An entry without an
endorsement is not verified under the root here — that is the plain path for
root-signed logs. The earlier export-fed route, which resolved the endorsement
from a `/receipts` payload, was **removed rather than retained as a fallback**:
the endorsement an auditor needs is inside the committed entry.

Four stages, in order:

| Stage | Checks |
|---|---|
| `endorsement` | The §3 artifact verifies under the root; user verification per policy |
| `leaf` | `kid` equals the endorsed session key's x; the entry's signature verifies under it |
| `window` | The receipted idtimestamp falls within `[notBefore, notAfter]` — **no skew tolerance** |
| `receipt` | The entry's bytes hash to the receipted index; inclusion verifies |

Inputs are the log root as raw `x‖y` (the `grantData`, which the contract binds
as `logRootKey`), the **exact** registered entry bytes, the receipt, and the
receipted idtimestamp. Nothing else, and no network.

**Online and offline check the same window against different clocks**, and the
difference is intentional. Admission uses wall-clock time with a small skew
tolerance, because at admission the entry has no idtimestamp yet — the
sequencer has not assigned one. Offline uses the receipted idtimestamp, which
is monotonic, time-ordered and carried by every receipt. **The offline check is
the authoritative one**; the online check is a fast refusal that keeps
unverifiable entries out of the log in the first place.

## 7. Constants that must agree

Three timing constants are declared independently and must remain consistent.
Nothing but comments currently enforces it.

| Constant | Value | Declared in | Purpose |
|---|---|---|---|
| Not-before skew | 5 minutes | The admission edge **and** the client Durable Object, separately | Forward tolerance for clock skew |
| Not-before backdate | 60 seconds | The browser | Endorsements are backdated so a just-issued one is never rejected as future-dated |
| Renewal window | 24 hours | The browser | Re-endorsement is scheduled this far before the window lapses |
| Default window | 7 days | The verification library | Client-overridable |

The backdate is sized against the skew, in a different repository, with no code
linkage.

## 8. Rotation, recovery and what an attacker gets

**Rotation** is one gesture: post the same root with a new session key and a
fresh endorsement over it. There is no support flow and no per-log state to
update.

**Custody cannot be downgraded.** Once a passkey root is pinned, a
bare 4a-shape post — a raw key with no endorsement — is refused. Script in the
page must never be able to move the user off passkey custody silently.

**The root is trust-on-first-use and cannot be changed.** A later post naming a
different root is refused. This is why upgrading an existing software-rooted
log to a passkey means starting a new log: a log's root cannot be swapped, and
that immovability is precisely what stops anyone else swapping it either.

**Replay gains nothing.** The endorsement is public and appears in every
export. Presenting it confers no capability — writing an entry still needs the
session *private* key, which is non-extractable.

**Scope.** The payload carries no log id, so one passkey root owning several
logs may reuse one endorsement across them. That is the same person and the
same non-extractable browser key, scope comes from the grant, and since the
endorsement now rides inside each committed entry its effective scope is the
entry it is attached to. Recorded as accepted.

## Open questions

- **A UV policy divergence exists between the admission edge and the client
  pre-flight.** The edge derives the requirement from the grant flag; the
  client Durable Object derives it from deployment configuration. They can
  disagree, and when they do a turn the user has already paid for is refused
  after the fact — the exact failure the pre-flight exists to prevent. Tracked
  as a bug.
- **ADR-0065 §4's failure-reason table does not match the shipped mapping**
  (§5.3). The code is correct; the ADR should be amended.
- **Index scoping was deferred, and a use case has since appeared.** A payload
  carrying an MMR index range was assessed and set aside: a range cannot be
  enforced at admission, because the sequencer assigns the index afterwards.
  The observation that made it tractable — a browser does know its own indices
  — is what produced the idtimestamp window instead, as the contained form of
  the same idea. It buys tighter scoping than a time window; it is not needed
  for auditability, which the current design already delivers.

  What has changed is the *motivation*. Grant-funded work — one party buying
  bounded provability that a second party draws down — needs an allowance
  scoped to a **signer**, and the publish grant cannot express one: its ceiling
  bounds the log, not an issuer (see
  [log-authority-and-grants.md](./log-authority-and-grants.md) §7). Giving each
  task its own log sidesteps that; carrying an explicit "this signer may add
  *n* entries from index *i*" permission expresses it directly. The second is
  enforceable **only here, at admission** — the contract sees checkpoints, never
  per-entry signers — and a *starting* index makes the check a bounded forward
  count rather than a scan, which is what the rejected *range* form could not
  offer. The open part is not the check but the carrier: the grant map is
  closed, so such a permission needs a derived-policy home. Worth a recorded decision under
  `decisions/` before anything depends on it.
- **Registering the endorsement as the log's first entry** was also deferred.
  It is admissible today with no change and would give a receipted succession
  record. Not needed once every entry carries its own endorsement, and it adds
  a second artifact type to register and order.

## References

- [receipt-trust-model.md](./receipt-trust-model.md) — where this fits among
  the four trust questions.
- [delegation-and-webauthn-envelopes.md](./delegation-and-webauthn-envelopes.md)
  — the assertion envelope and challenge binding this artifact reuses.
- [key-custody-and-choice.md](./key-custody-and-choice.md) — the custody
  options and how to leave.
- [ADR-0064](../decisions/adr-0064-passkey-session-key-endorsement.md) — the custody
  split and the original artifact.
- [ADR-0065](../decisions/adr-0065-endorsed-session-key-admission.md) — payload v2,
  the window, and the admission rules.
