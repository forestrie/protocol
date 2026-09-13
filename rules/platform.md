# Rules of the road — platform (general)

Cross-repo invariants. Load this file for **every** Forestrie review or plan,
alongside the one repo file that matches the code. Repo files specialise these
into concrete checks — they never restate them.

Reasoning links go to the Forestrie protocol repository (this repository) and the
[receipt trust model](../spec/receipt-trust-model.md).

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
Split-view protection is structural on-chain: the contract refuses to anchor an
inconsistent checkpoint. Security MUST NOT depend on a live honest-majority of
monitors. **Why:** transparency logs that rely on external watchers as a public
good fail; the anchor makes divergence impossible *by contract*.
[receipt trust model](../spec/receipt-trust-model.md) (question 1)
· [trust-boundaries-and-operator-powers.md](../spec/trust-boundaries-and-operator-powers.md)
§4.1.

### P5 — On-chain is the amortised anchor, never the hot path
One checkpoint anchors a whole massif (~16k entries); nothing on the write/read
hot path may gate on a chain read. **Why:** entries write at internet speed and
gas amortises to fractions of a cent per entry — per-entry anchoring destroys
both.
[checkpoints-and-receipts.md](../spec/checkpoints-and-receipts.md) §1.2.

### P6 — Authority is receipt-based; submission is permissionless
Authority = a valid **grant inclusion proof** + a correctly **signed
consistency receipt**. The contract MUST NOT check `msg.sender` for submission
authority. **Why:** no operator can censor or stall a well-formed write, and
proof of authority is portable, not identity-held.
[ARC-0019](../decisions/arc-0019-grant-verification-model.md)
· [log-authority-and-grants.md](../spec/log-authority-and-grants.md) §7.

### P7 — Payment grants authority; a grant is a prepaid provability entitlement
The requester of work **buys** capacity; the performer **draws it down**. A
grant is not a payment escrow (escrow lives at the settlement layer). **Why:** a
performer's record cannot be suppressed by a requester who refuses acceptance.
[log-authority-and-grants.md](../spec/log-authority-and-grants.md) §7.

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
Statement issuer/subject default to registration-free, key-derived identity
(ES256 `iss` = hex `kid`; KS256 = CAIP-10; `sub` = payload SHA-256). The signing
path MUST NOT depend on a certificate or registration. **Why:** zero-config,
offline, SCITT-compliant — identity composes *above* the log rather than being
owned by it.
[glossary.md](../glossary.md) (statement signer binding).

### P12 — Signed is not sequenced
A signature never establishes ordering; only the sequencer's monotone
`idtimestamp` does, and only checkpoint anchoring bounds it. The Urkle trie is
keyed on that `idtimestamp`, so **no content-derived key can be a trie key**.
**Why:** conflating signing with sequencing is the root of false
ordering/absence claims.
[checkpoints-and-receipts.md](../spec/checkpoints-and-receipts.md) §5.

### P13 — Absence is first-class, but succinct absence is not free yet
A verifier can prove non-presence against a **replicated** log today (regime a).
**Succinct** absence (regime b) requires a *new authenticated secondary index*
because the trie root is currently unanchored. Do not design against succinct
absence proofs as if they exist. **Why:** absence detection distinguishes "never
happened" from "happened and was withheld" — but the succinct form is unbuilt.
[trust-boundaries-and-operator-powers.md](../spec/trust-boundaries-and-operator-powers.md)
§6.

### P14 — One instance root, set once; global logId→R uniqueness
Every checkpoint binds to exactly one instance root (`chainId` + contract); the
root/bootstrap key is **set once at construction and immutable**, and global
`logId → R` uniqueness is enforced atomically at grant POST. **Why:** this 1:1
binding is what authority resolution, fee liability, and permissionless
per-forest publishing all key off — and what blocks logId reuse / grant replay.
[log-authority-and-grants.md](../spec/log-authority-and-grants.md) §1
· [glossary.md](../glossary.md) (forest uniqueness).

### P15 — Published artifacts declare their own cache policy; completeness decides immutability
Complete massifs are `immutable`; head massifs, **all checkpoints**, and
negative (404) responses are `no-store`; payment tokens, revocation status, and
latest-checkpoint receipts MUST NOT be cached. **Why:** heuristic caching of
mutable objects fails silently — a stale proof, or a cached 404 that blocks a
later write.
[checkpoints-and-receipts.md](../spec/checkpoints-and-receipts.md) §6.

### P16 — Conformant COSE/CBOR everywhere; `@forestrie/encoding` owns the wire layer
Strict SCITT/COSE + RFC 8949 §4.2 canonical CBOR is mandatory (encode **and**
decode); `cbor-x` is banned. Layering is acyclic — no `verifier → builder` edge.
**Why:** on-chain verifiability and interop depend on exact bytes; a lax or
tag-mangling codec produces receipts the contract rejects.
[label-registry.md](../spec/label-registry.md)
· [checkpoints-and-receipts.md](../spec/checkpoints-and-receipts.md) §1.

---

## Not-yet-live (design guardrails, not check targets)

These are accepted *direction* but not implemented — plan toward them, do not
review against them as if shipped:

- **Reputation is bonded, tracked, and slashed** (assessor standing = on-chain
  history + bond + delegated stake), so recognition and Sybil cost are the same
  property, set by hierarchy position. Design direction only; nothing in
  `spec/` describes shipped behaviour for it.
- **Succinct-absence secondary index** — see P13; the trie root is unanchored
  today, and how to anchor it is open.
