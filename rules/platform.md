# Platform invariants

The invariants the protocol rests on: what a change must not break. Each
links to the document under `spec/` that carries its reasoning; none adds a
fact those documents do not state.

---

### P1 — Pipe, not store
Only content **hashes** (digests) enter the log; statement bytes and primary
data MUST NOT persist server-side. **Why:** neutrality and regulated-data
custody stay with the customer — an operator or indexer holding content
re-introduces the trusted intermediary Forestrie exists to remove.
[trust-boundaries-and-operator-powers.md](../spec/trust-boundaries-and-operator-powers.md)
§2 (the edge crossing).

### P2 — Receipts verify offline, key-free, forever
Verification (receipt signature, MMR inclusion, leaf binding) MUST be pure over
bytes: no network, SCRAPI, coordinator, RPC, or wallet call, and a receipt
never expires. **Why:** offline verification is the headline product claim;
coupling verify to a live service silently falsifies it.
[ADR-0045](../decisions/adr-0045-receipt-verify-offline-contract.md)
· [checkpoints-and-receipts.md](../spec/checkpoints-and-receipts.md) §4.1.

### P3 — Keep the four trust questions separate
Split-view (accumulator) / sealing (signer) / authority (grant chain) /
**attribution** (who was authorised to sign THIS leaf) are **independent**;
"the receipt is valid" is meaningless without saying which. The first three
concern the log, the fourth the leaf, and it is answered from the leaf's own
bytes plus the on-chain root — so it composes with every trust root rather than
belonging to any one of them. Never source the accumulator unauthenticated from
the operator's own tile store.
**Why:** most trust confusion comes from collapsing them, and sourcing state
from the operator re-internalises the trust the log removes.
[receipt trust model](../spec/receipt-trust-model.md)
· [ADR-0065](../decisions/adr-0065-endorsed-session-key-admission.md) (attribution).

### P4 — Non-equivocation is enforced by the immutable contract, not watchers
Split-view protection is structural on-chain: the contract takes the base of
every consistency proof from the size and accumulator it already holds, pins
the proof's shape to its sizes, requires the signed target size to match, and
refuses a checkpoint that does not extend the anchored state, whoever signed
it. Security MUST NOT depend on a live honest-majority of monitors. **Why:**
security that depends on a live watcher population degrades when nobody is
watching; the anchor makes divergence impossible *by contract*.
[receipt trust model](../spec/receipt-trust-model.md) (question 1)
· [trust-boundaries-and-operator-powers.md](../spec/trust-boundaries-and-operator-powers.md)
§4.1.

### P5 — On-chain is the amortised anchor, never the hot path
One checkpoint anchors a whole massif (~16k entries); nothing on the write/read
hot path may gate on a chain read. **Why:** entries write at internet speed and
gas amortises to fractions of a cent per entry — per-entry anchoring destroys
both.
[checkpoints-and-receipts.md](../spec/checkpoints-and-receipts.md) §1.2
(one proof per massif boundary) · [glossary.md](../glossary.md) (massif)
· [checkpoints-and-receipts.md](../spec/checkpoints-and-receipts.md) §4.1
(nothing in verification reads the chain).

### P6 — Authority is receipt-based; submission is permissionless
Authority = a valid **grant inclusion proof** + a correctly **signed
consistency receipt**. The contract MUST NOT check `msg.sender` for submission
authority. **Why:** no operator can censor or stall a well-formed write, and
proof of authority is portable, not identity-held.
[ARC-0019](../decisions/arc-0019-grant-verification-model.md)
· [log-authority-and-grants.md](../spec/log-authority-and-grants.md) §7.

### P7 — A grant is a prepaid provability entitlement; payment never gates authority
The requester of work **buys** capacity; the performer **draws it down**. A
grant is not a payment escrow (escrow lives at the settlement layer). Payment
identity is never an input to grant verification, and no verifier or contract
reads payment state. A parent's committed flag may make the operator's
registration API require payment before it registers a *child* grant; that is
a gate on registration at the operator, not on authority. **Why:** a
performer's record cannot be suppressed by a requester who refuses acceptance,
and a lapsed payment cannot silently revoke authority.
[log-authority-and-grants.md](../spec/log-authority-and-grants.md) §7
· [label-registry.md](../spec/label-registry.md) §5 (bit 35).

### P8 — Grants are irrevocable; capacity ends by exhaustion or non-renewal
`maxHeight` is a contract-enforced **entry ceiling / high-water mark**, not a
decrementing balance; refundable grants are a non-goal. Capacity ends only by
exhaustion or a parent declining to renew — never by revocation. **Why:**
irrevocability is exactly what makes a performer's evidence unsuppressable.
[log-authority-and-grants.md](../spec/log-authority-and-grants.md) §7.

### P9 — Append-only, forward authority only
Committed history is permanent. A parent may only decline **future** growth; it
MUST NOT rewrite, censor, or sign in a child's place — a frozen child re-anchors
under its own root. **Why:** revocation of committed history would reinstate the
trusted operator; point-in-time finality is the product.
[log-authority-and-grants.md](../spec/log-authority-and-grants.md) §7
· [trust-boundaries-and-operator-powers.md](../spec/trust-boundaries-and-operator-powers.md)
§4.

### P10 — Grant verification is three-part and non-substitutable
Verify **receipt inclusion** + **grant envelope (the `Forestrie-Grant` COSE
Sign1) signature against the `ownerLogId` authority** + **statement-signer
binding** (`kid` == the grant's binding, and the statement signature under that
signer — `grantData`, or a session key the `grantData` root has endorsed,
[ADR-0065](../decisions/adr-0065-endorsed-session-key-admission.md)). The issuance key (parent authority) is distinct from the endorsed
signer key (`grantData`); NEVER verify the *grant* envelope against `grantData`,
and NEVER verify a *statement* against the parent authority.
**Why:** each part blocks a different forgery — collapsing them opens
replay/substitution.
[ARC-0019](../decisions/arc-0019-grant-verification-model.md) §§4–6
· [log-authority-and-grants.md](../spec/log-authority-and-grants.md) §5.

### P11 — Identity is a separate, key-derived layer
A statement's signer is identified by its `kid`, which must equal the binding
derived from the grant's `grantData` or the endorsed session key; nothing
else about the signer is registered or certified anywhere in the protocol.
The signing path MUST NOT depend on a certificate or registration. **Why:**
zero-config, offline, SCITT-compliant — identity composes *above* the log
rather than being owned by it.
[log-authority-and-grants.md](../spec/log-authority-and-grants.md) §2.2 and §5
· [leaf-admission-and-session-endorsement.md](../spec/leaf-admission-and-session-endorsement.md)
§5.1.

### P12 — Signed is not sequenced
A signature never establishes ordering; only the sequencer's monotone
`idtimestamp` does, and only checkpoint anchoring bounds it. The exclusion
trie is keyed on that `idtimestamp`, so **no content-derived key can be a
trie key**.
**Why:** conflating signing with sequencing is the root of false
ordering/absence claims.
[checkpoints-and-receipts.md](../spec/checkpoints-and-receipts.md) §5.

### P13 — Absence is first-class, but succinct absence is not free
A verifier can prove non-presence against a **replicated** log (regime a).
**Succinct** absence (regime b) requires a *new authenticated secondary index*
and an anchored trie root. Do not design against succinct absence proofs as if
they exist. **Why:** absence detection distinguishes "never happened" from
"happened and was withheld" — but the succinct form needs what
[implementation-status.md](../spec/implementation-status.md) records as
unbuilt.
[trust-boundaries-and-operator-powers.md](../spec/trust-boundaries-and-operator-powers.md)
§6.

### P14 — One instance root, set once; global logId→R uniqueness
Every forest binds to exactly one contract instance (`chainId` + contract)
through its genesis document; the instance's bootstrap key is **set once at
construction and immutable**; and a log id belongs to exactly one forest,
enforced at registration. A checkpoint signature asserts the accumulator and
the size it is the accumulator of; it is the **contract** that binds the
checkpoint to the instance, by enforcing consistency with the anchored state
— the signature itself names no instance, chain or log. **Why:** this 1:1
binding is what authority resolution and permissionless per-forest publishing
key off — and what blocks logId reuse across forests.
[log-authority-and-grants.md](../spec/log-authority-and-grants.md) §1 and §1.1
· [checkpoints-and-receipts.md](../spec/checkpoints-and-receipts.md) §1.3
· [key-custody-and-choice.md](../spec/key-custody-and-choice.md) §1
· [glossary.md](../glossary.md) (forest uniqueness).

### P15 — Published artifacts declare their own cache policy; completeness decides immutability
The forest genesis document and complete massifs are `immutable`; the head
massif, **all checkpoints**, receipts and negative (404) responses are
`no-store`. The table in the checkpoint document is the policy; this rule
adds nothing to it. **Why:** heuristic caching of mutable objects fails
silently — a stale proof, or a cached 404 that blocks a later write.
[checkpoints-and-receipts.md](../spec/checkpoints-and-receipts.md) §6.

### P16 — Conformant COSE/CBOR everywhere, with one named exception
Every format is strict SCITT/COSE with RFC 8949 §4.2 core deterministic
encoding, on encode **and** on decode. The one exception is the **checkpoint
envelope**, whose protected header uses length-first canonical map key order
(shorter key encodings first, then bytewise); the two orders agree only while
every map label is a single byte, and the checkpoint header carries `395` and
`-65933`. A verifier of checkpoints MUST require that order for the header, as
ADR-0066 D9 states, and MUST NOT re-encode a checkpoint expecting byte
identity with a bytewise-order encoder. **Why:** on-chain verifiability and
interop depend on exact bytes; a lax or tag-mangling codec produces receipts
the contract rejects, and changing the header order would change every
checkpoint the sealer emits.
[ADR-0068](../decisions/adr-0068-checkpoint-envelope-canonicalisation-exception.md)
· [ADR-0066](../decisions/adr-0066-sec-signed-checkpoint-size.md) D9
· [checkpoints-and-receipts.md](../spec/checkpoints-and-receipts.md) §1.3.

---

Accepted direction that is not implemented — bonded reputation, the
succinct-absence index, multi-key recovery — is listed under "Designed, not
built" in [implementation-status.md](../spec/implementation-status.md), and
is not a check target.
