# Key custody and choice

**Audience:** anyone deciding where their log's root of trust should live, and
implementers of the custody paths.
**Related:**
[trust-boundaries-and-operator-powers.md](./trust-boundaries-and-operator-powers.md),
[receipt-trust-model.md](./receipt-trust-model.md) (question 4),
[leaf-admission-and-session-endorsement.md](./leaf-admission-and-session-endorsement.md),
[glossary.md](../glossary.md).

## Summary

The property this system exists to protect is **log ownership that is
self-custodied — or at minimum not operator-custodied**. A log must be
authorised by a key its owner controls, and the record must remain verifiable
offline by anyone, forever.

Everything in this document is judged against that one property. It describes
every key in the system, who holds it, what it can sign, how long it lives, and
how to leave.

## 1. Every key, and who holds it

| Key | Held by | Signs | Lifetime |
|---|---|---|---|
| **Instance bootstrap key** | The forest curator | The root log's authority | Set once at contract construction, immutable |
| **Log root key** | The log's owner | Grants it issues; its sealing delegations | The life of the log — cannot be changed |
| **Session key** | The owner's browser, non-extractable | Per-turn entries | Rotatable, bounded by its endorsement window |
| **Delegated sealing key** | The operator's sealer | Checkpoints, for each log that has leased it, within that lease's MMR range | HKDF-derived at boot from a KMS-held seed, so a restart re-derives it — no long-lived private key is persisted at rest. Each lease lasts until the log grows past its range on-chain, and until the certificate's expiry off-chain |
| **Custody key** | The operator's custodian, in KMS | For a custodial log, everything the root signs: the delegation certificate, the on-chain proof, and any digest presented under the service token | The life of the log; one key per custodial log id |
| **Publisher key** | Whoever submits the transaction | The chain transaction, and nothing authoritative | Irrelevant to authority |
| **Upgrade admin key** | Whoever holds the upgradeable contract variant's admin address | Replacement of the contract implementation | Until replaced by an upgrade; there is no transfer operation |

The publisher row is the one most often misread. The publisher pays gas and is
**never authoritative** — submission is permissionless, and the contract does not check
who sent the transaction. Anyone can publish a well-formed checkpoint, which is
exactly why no operator can censor or stall one.

## 2. The constraint that shapes everything

A WebAuthn authenticator cannot sign arbitrary bytes, and **every assertion
costs a deliberate user gesture**. Those two facts do more to shape this design
than any cryptographic consideration.

A conversational log writes an entry per turn. If the root key signed entries,
either every turn costs a biometric prompt or the entries go unsigned. Neither
is acceptable, so the root signs *arrangements* — delegations and endorsements
— and a silent key signs entries. That indirection is what satisfies both
constraints; no arrangement without it does.

It also shapes the two wallet routes:

- **A browser extension wallet signs only with the EIP-191 prefix**, so it
  cannot produce the raw signature over a COSE `Sig_structure` that a
  delegation needs. The obstacle is the prefix, not key export.
- **A smart-contract account has no signing key.** Its "signature" is an
  on-chain predicate. The contract and the server-side verifier both accept
  it through ERC-1271, and a KS256 forest can be bootstrapped to a Safe. The
  cost is that verifying such a root needs chain state at a block height, so
  *offline, forever* does not hold for that root shape; a relying party
  verifying it needs a chain reader.

## 3. The five custody shapes

Five shapes. All five produce logs that verify identically; they differ in who
holds the root, in who can sign with it and for how long, and in what the user
has to operate. They are alternatives, not a progression: which one is right
depends on what the owner can hold and what they need to be protected against.
§6 gives that comparison adversary by adversary.

| | Root key lives in | Who can sign with the root | For how long | Notes |
|---|---|---|---|---|
| **Software root** | The browser profile, non-extractable to script | The owner; any script in the page while it is open, with no gesture | The life of the profile | The default; one-way upgrade path |
| **Passkey root** | Platform authenticator hardware | The owner, one gesture per signature | The life of the credential | Syncs via the platform keychain |
| **BYOK, user-operated signer** | Wholly with the user, off-platform | The user's own signer | As the user decides | The reference form of the property |
| **BYOK, hosted wallet** | A user-owned wallet in a custodial enclave | The user; the operator as an additional signer within policy while both enable bits are set; the enclave provider | Until the user clears their enable bit, for the operator | The stop is a coordinator feature |
| **Custodial** | The operator's KMS | The operator's custodian, for any digest presented under the service token | The life of the log | The operator holds the root outright |

### 3.1 Software root

A non-extractable P-256 key generated in the browser. Script can ask it to
sign but cannot read, copy or export it. Everything works day to day exactly as
with a passkey.

Two differences. The root is only as durable as that browser profile, and
there is no recovery: losing it means the log remains fully verifiable but can
no longer be extended or re-delegated. And **the root signs without a
gesture**, so script running in the page can ask it for anything the owner
could: a delegation certificate and on-chain proof naming a key the attacker
chooses, with a certificate expiry the caller sets and no on-chain expiry, or
a grant, which is permanent. Non-extractability means the attacker cannot take
the key away; it does not bound what they sign while the page is open, and
nothing server-side can tell the difference.

An earlier demo form of this — a raw exportable key in browser storage — was
self-custodied only in the narrowest sense, since any script injection could
read it and forge the log's authorisation permanently. Non-extractability is
what makes this option meaningful.

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
gates authorisation — the ability to seal, delegate, and issue grants — not
the content of individual turns. This is a stated, accepted residual, not an
oversight. It is also the difference from the software root: under a passkey,
every root signature costs a gesture, so an injected script cannot obtain a
delegation or a grant.

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

The residual risk is real and should be stated to users plainly: this option
trusts the enclave provider for confidentiality and for the integrity of its
ownership model, and the two-bit stop is enforced by the operator's
coordinator, not by any contract or verifier. That residual is the reason to
choose §3.3 instead.

### 3.5 Custodial

The operator's custodian holds one KMS key per custodial log id, and **that
key is the log's root**: it signs the delegation certificate, the on-chain
proof, and any digest a caller presents under the custodian's single service
token. The owner operates nothing and holds nothing.

This shape exists for logs whose owner wants none of the above, and it is
named here so that the "operator never holds a user root" property is scoped
honestly: it holds for the four shapes above and not for this one. A relying
party who needs the property should confirm the log's shape.

## 4. The root cannot be changed, and that is the feature

A log's root key is fixed for the life of the log. It is the value the contract
binds, the value the grant commits, and the anchor every endorsement verifies
under. There is no re-rooting operation.

The consequence users notice is that **upgrading custody is one-way**: moving
from a software root to a passkey means starting a fresh log, because the old
log's root cannot be swapped. The immovability is what stops anyone *else*
swapping it — an operator, a compromised page, or a support process.

It also bounds what a compromise can achieve. An attacker who fully controls
the page cannot re-root the log. Under a passkey root they can attest content
while the page is open and nothing more. Under a software root they can also
obtain a delegation and a grant (§3.1), and a grant survives the session.

## 5. Rotation, recovery, exit

**Rotation** of the session key is one gesture: present the same root, a new
session key, and a fresh endorsement. No support flow, no per-log state to
update. A superseded endorsement stops being admissible when its window lapses,
so rotation needs no revocation mechanism.

**Recovery** is deliberately *not* solved by changing the signature format. A
passkey recovers through platform keychain sync — the same mechanism that syncs
any other passkey. Where recovery must survive more than platform sync, the
answer is for the authority to endorse **more than one key** per log, not to
make the root mutable. Losing a software root, by contrast, is unrecoverable: the log stays
verifiable but frozen.

**Exit needs no operator cooperation.** The root cannot be re-assigned (§4),
so exit means one of two things: the owner delegates sealing under the same
root to a different sealer, which needs no one's permission because the
delegation is a root signature and submission is permissionless; or the owner
starts a new log. This is the strongest of the guarantees here, because it is
the one that makes the others credible: an exit that depends on the operator
is not an exit, it is a lock-in. It does not cut short a lease already issued:
that sealer can still publish within its range until the log grows past it,
and a relying party retaining checkpoints is what detects misuse in the
meantime.

**Resetting** forgets what the browser holds — keys, wallet, local message
text. It does not and cannot delete entries already committed; those are
permanent by design. Without the local copy, though, nobody can show what the
committed hashes stand for.

## 6. What each option actually protects against

| Adversary | Software root | Passkey | BYOK user-operated | BYOK hosted wallet | Custodial |
|---|---|---|---|---|---|
| Script injection in the page | Can sign turns while open; **can obtain a delegation and a permanent grant**; cannot take the key | Can sign turns while open; cannot seal, delegate or grant without a gesture | Same as passkey | Same as passkey | n/a |
| Loss of the browser profile | **Log frozen, unrecoverable** | Recovers via keychain sync | Unaffected | Unaffected | Unaffected |
| Compromised hosting operator | Cannot forge | Cannot forge | Cannot sign at all | Can sign within policy while enabled; the stop is its own coordinator's | n/a |
| Compromised transparency operator (sealer) | Bounded to each lease's log and MMR range, until the log grows past it; within a lease, can replace the anchored accumulator, which retained checkpoints detect (see [trust-boundaries-and-operator-powers.md](./trust-boundaries-and-operator-powers.md) §4.1) | Same | Same | Same | Same, and also holds the root (below) |
| Compromised custodian | n/a | n/a | n/a | n/a | **Holds the root** — can delegate, grant and sign anything |
| Enclave provider compromise | n/a | n/a | Out of scope | **Can abuse the root** — mitigated only by exit | n/a |

Several of these defeats need no collusion: the enclave provider alone, the
custodian alone, an injected script alone under a software root, and the
sealer alone within a lease. What does need collusion is set out in
[trust-boundaries-and-operator-powers.md](./trust-boundaries-and-operator-powers.md)
§5.

## Open questions

- **Custody upgrade requires a new log.** Accepted, and a direct consequence of
  §4 — but it is the sharpest edge a user meets, and it deserves a better
  product answer than "start again" if passkey adoption grows.

Origin pinning's policy channel and multi-key endorsement for recovery are
recorded in [implementation-status.md](./implementation-status.md).

## References

- [trust-boundaries-and-operator-powers.md](./trust-boundaries-and-operator-powers.md)
  — the adversary analysis these options sit inside.
- [leaf-admission-and-session-endorsement.md](./leaf-admission-and-session-endorsement.md)
  — the endorsement mechanism behind the passkey option.
- [delegation-and-webauthn-envelopes.md](./delegation-and-webauthn-envelopes.md)
  — how a passkey signs a delegation at all.
- [glossary.md](../glossary.md) — the BYOK delegation modes, the delegation
  certificate, the custody key, and the terms used in §3.
