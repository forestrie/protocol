# Key custody and choice

**Status:** LIVE
**Date:** 2026-08-30
**Audience:** anyone deciding where their log's root of trust should live, and
implementers of the custody paths.
**Related:** protocol/README.md (private, cited by name),
[trust-boundaries-and-operator-powers.md](./trust-boundaries-and-operator-powers.md),
[receipt-trust-model.md](./receipt-trust-model.md) (question 4),
[leaf-admission-and-session-endorsement.md](./leaf-admission-and-session-endorsement.md).

## Summary

The property this system exists to protect is **log ownership that is
self-custodied — or at minimum not operator-custodied**. A log must be
authorised by a key its owner controls, and the record must remain verifiable
offline by anyone, forever.

Everything in this document is judged against that one property. It describes
every key in the system, who holds it, what it can sign, how long it lives, and
— the part that makes the choice real — how to leave.

## 1. Every key, and who holds it

| Key | Held by | Signs | Lifetime |
|---|---|---|---|
| **Instance bootstrap key** | The forest curator | The root log's authority | Set once at contract construction, immutable |
| **Log root key** | The log's owner | Grants it issues; its sealing delegations | The life of the log — cannot be changed |
| **Session key** | The owner's browser, non-extractable | Per-turn entries | Rotatable, bounded by its endorsement window |
| **Delegated sealing key** | The operator's sealer, in memory | Checkpoints, within one log and MMR range | A lease, hours; never persisted, discarded on restart |
| **Publisher key** | Whoever submits the transaction | The chain transaction, and nothing authoritative | Irrelevant to authority |

The last row is the one people misread. The publisher pays gas. It is **never
authoritative** — submission is permissionless, and the contract does not check
who sent the transaction. Anyone can publish a well-formed checkpoint, which is
exactly why no operator can censor or stall one.

## 2. The constraint that shapes everything

A WebAuthn authenticator cannot sign arbitrary bytes, and **every assertion
costs a deliberate user gesture**. Those two facts do more to shape this design
than any cryptographic consideration.

A conversational log writes an entry per turn. If the root key signed entries,
either every turn costs a biometric prompt or the entries go unsigned. Neither
is acceptable, so the root signs *arrangements* — delegations and endorsements
— and a silent key signs entries. That indirection is not a compromise bolted
on; it is the only shape that satisfies both constraints.

It also explains why the obvious browser-wallet routes fail:

- **A browser extension wallet will never export a private key**, so it cannot
  produce the delegation signature the sealing path needs.
- **A smart-contract account has no signing key at all.** Its "signature" is an
  on-chain predicate, and verifying it requires chain state at a block height —
  which directly contradicts *offline, forever*.

## 3. The custody ladder

Four shapes, in ascending custody strength. All four produce logs that verify
identically; they differ in who could forge the authorisation.

| | Root key lives in | Biometric | Operator can forge? | Notes |
|---|---|---|---|---|
| **Software root** | The browser profile, non-extractable to script | No | No | The default; one-way upgrade path |
| **Passkey root** | Platform authenticator hardware | Yes | No | Syncs via the platform keychain |
| **BYOK, user-operated signer** | Wholly with the user, off-platform | Per policy | No | The purist form |
| **BYOK, hosted convenience** | A user-owned wallet in a custodial enclave | Per policy | No, but the enclave provider could | Revocable, with a user-held stop |

### 3.1 Software root

A non-extractable P-256 key generated in the browser. Script can ask it to
sign but cannot read, copy or export it. Everything works day to day exactly as
with a passkey.

The real difference is that the root is only as durable as that browser
profile, and there is no recovery: losing it means the log remains fully
verifiable but can no longer be extended or re-delegated.

An earlier demo form of this — a raw exportable key in browser storage — was
self-custodied only in the narrowest sense, since any script injection could
read it and forge the log's authorisation permanently. Non-extractability is
what makes this rung meaningful.

### 3.2 Passkey root with an endorsed session key

The authenticator holds the root. It signs ceremonies only: the sealing
delegation, and one endorsement of the browser's session key. The session key
then signs entries silently, within a validity window.

This is the shape the
[endorsement document](./leaf-admission-and-session-endorsement.md) specifies.
What it buys over a software root is that the root is **hardware-bound and
platform-synced** — it survives losing the browser profile, and it cannot be
used without the user's presence.

What it deliberately does **not** buy: protection of per-turn *content*. Script
in a compromised page can ask the session key to sign, because a key that signs
without a gesture is exactly what the gesture budget requires. The passkey
gates authorisation — the ability to seal, delegate, and move authority — not
the content of individual turns. This is a stated, accepted residual, not an
oversight.

### 3.3 BYOK with a user-operated signer

The user holds the root entirely, off the operator's infrastructure, and
operates their own signer. The operator's delegation agent **brokers** the
exchange — it relays the sealer's public key and validates the returned
certificate — and holds no root key at any point.

This is the reference form of the property. A compromised operator cannot sign,
because it has neither the root nor any signer right; it can only withhold or
misroute, and withholding is visible.

### 3.4 BYOK with hosted convenience

The root lives in a user-owned wallet inside a custodial enclave, with the
operator added as an **additional signer** — able to sign within policy, and
nothing more.

Two structural rules make this a custody choice rather than a surrender:

- **The user is the sole owner.** An additional signer can sign within policy
  but cannot change owners, signers or policies, cannot export the key, and
  cannot delete the wallet. Placing the operator in the owner quorum would
  collapse the property entirely, and is explicitly prohibited.
- **The stop needs both bits, and the user holds one.** Sealing requires both a
  user-enable and an operator-enable. The user can clear theirs unilaterally
  and the operator cannot bypass it.

The residual risk is real and should be stated to users plainly: this rung
trusts the enclave provider for confidentiality and for the integrity of its
ownership model. That residual is the documented reason a purist chooses §3.3.

## 4. The root cannot be changed, and that is the feature

A log's root key is fixed for the life of the log. It is the value the contract
binds, the value the grant commits, and the anchor every endorsement verifies
under. There is no re-rooting operation.

The consequence users notice is that **upgrading custody is one-way**: moving
from a software root to a passkey means starting a fresh log, because the old
log's root cannot be swapped. That is not a missing feature. The immovability
is precisely what stops anyone *else* swapping it — an operator, a compromised
page, or a support process.

It also bounds what a compromise can achieve. An attacker who fully controls
the page can attest content while it is open; they cannot re-root the log,
extend its authority, or make any of it survive the session.

## 5. Rotation, recovery, exit

**Rotation** of the session key is one gesture: present the same root, a new
session key, and a fresh endorsement. No support flow, no per-log state to
update. A superseded endorsement stops being admissible when its window lapses,
so rotation needs no revocation mechanism.

**Recovery** is deliberately *not* solved by changing the signature format. A
passkey recovers through platform keychain sync — the same mechanism that syncs
any other passkey. Where stronger recovery is wanted, the answer is for the
authority to endorse **more than one key** per log, not to make the root
mutable. Losing a software root, by contrast, is unrecoverable: the log stays
verifiable but frozen.

**Exit needs no operator cooperation.** A user can re-assign their registered
root on-chain and re-delegate to a different sealer without the hosting
operator's involvement. This is the strongest of the guarantees here, because
it is the one that makes the others credible: an exit that depends on the
operator is not an exit, it is a lock-in. It is also the only thing that
definitively neutralises a compromised sealer, since a lease already issued
runs until it expires.

**Resetting** forgets what the browser holds — keys, wallet, local message
text. It does not and cannot delete entries already committed; those are
permanent by design. Without the local copy, though, nobody can show what the
committed hashes stand for.

## 6. What each rung actually protects against

| Adversary | Software root | Passkey | BYOK user-operated | BYOK hosted |
|---|---|---|---|---|
| Script injection in the page | Can sign turns while open; cannot steal the key | Same; cannot seal or delegate without a gesture | Same | Same |
| Loss of the browser profile | **Log frozen, unrecoverable** | Recovers via keychain sync | Unaffected | Unaffected |
| Compromised hosting operator | Cannot forge | Cannot forge | Cannot sign at all | Can sign within policy until revoked |
| Compromised log operator (sealer) | Bounded to an unexpired lease, one log, one MMR range, and consistent with prior anchored state | Same | Same | Same |
| Enclave provider compromise | n/a | n/a | Out of scope | **Can abuse the root** — mitigated only by exit |

The strongest attacks require **collusion** between the hosting operator and
the log operator, because they are distinct trust domains — and in the hosted
rung, collusion with the enclave provider too.

## Open questions

- **The passkey rung is not yet end to end.** The sealer cannot verify a
  passkey-signed delegation certificate, so a passkey-rooted log cannot
  currently be sealed. Tracked as a bug.
- **Origin pinning has no policy channel.** The on-chain verifier implements
  it; nothing can enable it per log. It was designed to ride the same grant-flag
  mechanism as user verification.
- **Multi-key endorsement for recovery is designed, not built.** It is the
  intended answer to root loss and remains unimplemented.
- **Custody upgrade requires a new log.** Accepted, and a direct consequence of
  §4 — but it is the sharpest edge a user meets, and it deserves a better
  product answer than "start again" if passkey adoption grows.

## References

- protocol/README.md — `path:line` citations and status.
- [trust-boundaries-and-operator-powers.md](./trust-boundaries-and-operator-powers.md)
  — the adversary analysis these rungs sit inside.
- [leaf-admission-and-session-endorsement.md](./leaf-admission-and-session-endorsement.md)
  — the endorsement mechanism behind the passkey rung.
- [delegation-and-webauthn-envelopes.md](./delegation-and-webauthn-envelopes.md)
  — how a passkey signs a delegation at all.
- ARC-0022 — the BYOK modes, security invariants, kill switch and exit, in
  full.
