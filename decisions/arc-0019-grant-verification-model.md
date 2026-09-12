# ARC-0019: Grant verification (receipt-based inclusion, grant-statement signature, and signer binding)

**Status**: DRAFT  
**Date**: 2026-03-19 (§6.3 revised 2026-08-09 — the issuer/endorsed-signer split is implemented, not planned)  
**Related**: [Plan 0005](https://github.com/forestrie/canopy/blob/main/docs/plans/plan-0005-grant-receipt-unified-resolve.md), [Statement COSE encoding](https://github.com/forestrie/canopy/blob/main/docs/arc/arc-statement-cose-encoding.md), [canopy implementation map](https://github.com/forestrie/canopy/blob/main/docs/arc/canopy-grant-verification-implementation.md)

## Purpose

This document is the **platform reference** for how Forestrie verifies that an auth grant is allowed for a request. It is referenced by subplans, plans, and API docs wherever grant auth or inclusion is specified.

**§0** states the **logical model**. **§§1–6** state **verification obligations** (when they apply, circularity, checkpoint signer, grant-statement signature, receipts, register-entry binding). **§6.3** documents the **implemented** split of **issuance (envelope) signer** vs **endorsed statement signer**: parent **K(P)** issues grants whose **`grantData`** names a **different** party allowed to sign **`POST …/entries`** — this is live and enforced today (revised 2026-08-09; the earlier "planned evolution" framing was stale). **§7** is **summary pseudocode**. Canopy implementation map: [canopy grant verification implementation](https://github.com/forestrie/canopy/blob/main/docs/arc/canopy-grant-verification-implementation.md).

Three verification aspects:

1. **Grant statement signature (register-grant)** — the **transparent statement** (COSE Sign1 wrapping the grant) MUST be **cryptographically verified**, and the signing identity MUST be the **checkpoint signer** for the **authority log the grant leaf is appended under** (`ownerLogId`), or an **authorised delegate** thereof (§4). This is what makes **checkpoint signer** the sole party that can **issue** grants whose leaves extend that subtree: **data log** creation/extension, **child AUTH_LOG** creation, and (by induction on the tree) their descendants—because every such grant is a leaf in some owner authority MMR, and only **K(ownerLogId)** (or its delegate) may sign the issuance envelope.

2. **Receipt-based inclusion verification** — show that the grant’s leaf is included in the relevant authority MMR, using a **grant receipt** (COSE Sign1 carrying an MMR inclusion proof) (§5). Aligns with proving consistency against accumulator state before a checkpoint would be **accepted** on-chain (§0).

3. **Signer binding (register-signed-statement)** — Forestrie-Grant wire **v0** is a CBOR map with keys **1–6** only (no **`kind`**, **`signer`**, **`version`**, **`exp`**, **`nbf`**); see **§6.0**. The **statement**’s signer (e.g. COSE `kid`) MUST match **`grantData`** via **`statementSignerBindingBytes(grant)`** (§6). The **`grant`** bitmap MUST satisfy **`isStatementRegistrationGrant`** (data-log checkpoint grant **or** root auth bootstrap shape). **§6.1** gives plain language and **`GF_*` vs `GC_*`**. **Who may issue** the grant is **§4** only: transparent-statement signature vs **K(ownerLogId)** (or delegate). **§6.3** documents the **implemented** split product model — parent issues (envelope verified against the **`ownerLogId`** authority, never against `grantData`), child **`grantData`** endorses the statement signer — so issuance key and endorsed statement signer are **distinct keys** today, not collapsed.



---

## 0. Logical model

### 0.1 Formal overview

Let $\mathcal{A}$ be the set of AUTH_LOG Merkle logs.

Let $A_n \in \mathcal{A}$ denote the AUTH_LOG at level $n \in \mathbb{N}$.

Define the parent relation by

$$
\operatorname{parent}(A_n) =
\begin{cases}
A_{n-1} & n > 0, \\
A_0     & n = 0.
\end{cases}
$$

#### Grants

Let $G_i^{(n)} \in A_n$ denote the grant at index $i$.

Each grant carries parameters

$$
\operatorname{range}(G_i^{(n)}) \in \mathbb{N}, \qquad
\operatorname{granularity}(G_i^{(n)}) \in \mathbb{N}.
$$

Grants authorise publication of receipts:

$$
G_i^{(n)} \vdash \operatorname{publish}(C_j, S)
$$

#### Receipts (checkpoints)

A checkpoint is a consistency proof (receipt) for an MMR.

$$
C_j = \operatorname{receipt}(A_n, k)
$$

$$
\operatorname{index}(C_j) = k
$$

Each receipt proves that the log has grown append-only to index $k$.

#### Contract acceptance

Let $S$ denote the split-view protecting smart contract.

A receipt is accepted iff its consistency proof verifies against the current accumulator state:

$$
\operatorname{accepts}(S, C_j)
\iff
\operatorname{verifyConsistency}(C_j,
\operatorname{peaks}(S, A_n))
$$

#### MMR accumulator

The contract stores only the MMR peaks:

$$
\operatorname{peaks}(S, A_n)
$$

Acceptance updates the accumulator:

$$
\operatorname{accepts}(S, C_j)
\;\Longrightarrow\;
\operatorname{peaks}(S, A_n)
\leftarrow
\operatorname{updateMMR}(
\operatorname{peaks}(S, A_n),
C_j
)
$$

#### Constraints from grants

Publication is constrained by the grant:

$$
\operatorname{index}(C_j) \leq \operatorname{range}(G_i^{(n)})
$$

$$
\forall C_j, C_{j+1} :
\Delta(C_j, C_{j+1}) \leq
\operatorname{granularity}(G_i^{(n)})
$$

Thus, grants expire via index exhaustion rather than revocation.

> **Consolidated in ARC-0028 (private, cited by name).** This
> line, ARC-0017 §3.4 and ARC-0016 §4.2 together settle the question of grant
> lifecycle; ARC-0028 §4 records refundable grants as a non-goal on that basis
> and derives what irrevocability buys. ARC-0028 §3.3 is also a **consumer of
> §6.3 below** — the issuance-signer / endorsed-statement-signer split that lets
> a grant be funded by one party and drawn down by another. That split is
> **implemented** (§6.3, revised 2026-08-09), so ARC-0028's dependency on it is
> already met on the platform-capability axis.

#### Global consistency

Accepted receipts define a globally consistent log view:

$$
\operatorname{accepts}(S, C_j)
\;\Longrightarrow\;
\operatorname{globally\_consistent}(A_n)
$$

### 0.2 Informal illustrations (non-normative)

**Parent log** — example sequence on $A_0$:

$$
A_0 = (G_b,\; L_0,\; G_1,\; G_2,\; L_i)
$$

Here $G_b$ can be read as a **bootstrap** grant, $G_1$, $G_2$ as further grants, and $L_*$ as non-grant leaves (e.g. data-log or other entries), illustrating that grants and other leaves share the same append-only structure.

**Child log** — example on $A_1$ (a descendant authority log):

$$
A_1 = (L_0,\; L_1,\; G_2,\; L_i)
$$

**Receipt over child log** — a checkpoint for $A_1$ up to index $1$:

$$
C_0 = \operatorname{receipt}(A_1, 1)
$$

**Publication** — grant $G_1$ authorises publishing that receipt to the contract:

$$
G_1 \vdash \operatorname{publish}(C_0, S)
$$

**Contract verification** — acceptance uses peaks for $A_1$:

$$
\operatorname{verifyConsistency}(C_0,
\operatorname{peaks}(S, A_1))
$$

**MMR update intuition** — after acceptance, peaks advance:

$$
\operatorname{peaks}(S, A_1)
\;\rightarrow\;
\operatorname{updateMMR}(\cdot, C_0)
$$

### 0.3 Mapping to Canopy (this ARC)

| Model (§0.1)                                         | Role in Canopy                                                                                                                                                                                                                                                                                                                                                                                           |
| ---------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| AUTH_LOG $A_n$                                       | The **owner authority log** identified by the grant’s **`ownerLogId`**. New grant leaves are appended to **that** log’s authority MMR (Subplan 03 / ranger). **`logId`** is the **target** of the grant (e.g. data log or child auth log UUID); **`ownerLogId`** is where the **grant leaf** lives.                                                                                                      |
| Checkpoint signer **K(L)**                           | For authority log **L**, the key material Univocity uses to validate **checkpoints** for **L** (root case: **ES256** key in bootstrap **`grantData`**). **Register-grant** MUST verify the **transparent statement** is signed by **K(L)** or a **delegate** (§4), where **L** is **`bytesToUuid(ownerLogId)`** for the inner grant.                                                                     |
| Grant $G_i^{(n)}$                                    | **`PublishGrant`** commitment + Forestrie-Grant wire **v0** (keys **1–6**; **`GrantAssembly` = `Grant`**) (Plan 0007 (private, cited by name)). **Issuance** of $G$ is the signed transparent statement; **membership** of the leaf is §5. For **register-statement**, **`isStatementRegistrationGrant`** (**`GF_*`**) and **`grantData`** vs **`kid`** apply (**§6**). |
| $\operatorname{range}$, $\operatorname{granularity}$ | On-chain **`maxHeight`**, **`minGrowth`**; contract-enforced at checkpoint publish.                                                                                                                                                                                                                                                                                                                      |
| Receipt $C_j$                                        | Unprotected header **396**; §5.                                                                                                                                                                                                                                                                                                                                                                          |
| $G \vdash \operatorname{publish}(C, S)$              | Canopy does not call the contract; **issuance** of $G$ is still gated by §4 + §5 as below.                                                                                                                                                                                                                                                                                                               |

**Bootstrap** (Subplan 08): log not yet initialised — **K(L)** is not yet on-chain; the **Custodian** (via per-log delegation API) acts as an **operational delegate** to sign the **root** transparent statement (current `verifyBootstrapCoseSign1`). After sequencing, **grantData** establishes **K(L)** for future §4 checks on grants whose **`ownerLogId`** is **L**.

---

## 1. When verification applies

### 1.1 register-grant

**Normative (target behaviour):** Every **`POST /register/grants`** request that enqueues a grant MUST:

1. **§4 — Grant statement signature:** Verify the **`Authorization: Forestrie-Grant`** COSE Sign1 (transparent statement) using **§4** (signer is **K(L)** or delegate, **L** = authority log the grant appends under = inner **`ownerLogId`**).
2. **§5 — Receipt / bootstrap branch:** Either
   - **Bootstrap:** log not initialised; satisfy Subplan 08 bootstrap checks (including existing bootstrap signature verification), **or**
   - **Non-bootstrap:** completed grant with **idtimestamp** + receipt; **§5** inclusion holds.

**Ordering:** §4 should run on every path that accepts the artifact (before or after §5 per efficiency); both must pass where applicable.

**Current Canopy:** §4 is **missing** on the non-bootstrap receipt branch; bootstrap satisfies a **special case** of §4 (platform delegation-signer as delegate). See **§7**.

### 1.2 register-signed-statement

Register-signed-statement is **`POST /register/entries`**; target transparency log is **`grant.logId`** only. When inclusion is required: **§5** then **§6** (statement **`kid`** vs **`statementSignerBindingBytes(grant)`**).

**GET registration-status / resolve-receipt** still use **`GET /logs/{logId}/entries/{id}`** so clients know which queue shard to poll: after **register-grant**, **`logId`** in that path is the **authority log** (**`ownerLogId`** / **O**); after **register-signed-statement**, it is the **target data log** (**`grant.logId`** / **T**).

---

## 2. Why §4 does not create irreconcilable circularity

**Worry:** To verify a new grant, we need **K(L)**; to know **K(L)** we might need grants already in **L**; that sounds circular.

**Resolution:** **K(L)** is always resolved from **already-committed** facts **strictly prior** to accepting the **new** issuance:

- **Root log L, first grant:** **K(L)** is not derived from a prior leaf in **L**; the **bootstrap** path uses a **configured** delegation key (operational **delegate**). After the bootstrap leaf is committed, **K(L)** for Univocity is read from that leaf’s **`grantData`** (and/or contract) for **subsequent** grants whose **`ownerLogId`** is **L**.

- **Subsequent grants in L:** **K(L)** comes from the **bootstrap grant** (or latest checkpoint-signer policy on-chain / indexer), **not** from the inner payload of the grant currently being registered.

- **Child AUTH_LOG L′:** Grants that **create** L′ are leaves in **parent** **P**’s MMR; their **statement** is signed by **K(P)**. Once L′ is bootstrapped, **K(L′)** comes from **L′**’s own bootstrap **`grantData`**. **No** definition of **K** refers to the **new** grant’s signature input.

Thus: **verify signature** uses **K** fixed from **past** state; **receipt** (when required) ties the **inner** grant to **past** MMR position. There is **no** self-referential dependence of **K** on the request under verification.

---

## 3. Checkpoint signer, delegation, and subtree control (normative summary)

Let **L** be the authority log identified by **`ownerLogId`** of the **inner** grant (the log whose MMR will contain this grant leaf).

- **K(L)** — **checkpoint signer** for **L**: the signing identity Univocity associates with checkpoints for **L** (typically **ES256** public key bytes committed in the **bootstrap** **`grantData`** for **L**, or successor policy).

- **Delegate** — any signing identity **explicitly** authorised to act for **K(L)** on grant issuance (SCITT delegation wire format **TBD**: e.g. COSE **x5c**, short-lived CWT, operator-configured allow-list of keys certified by **K(L)**).

- **Control story:** Only **K(L)** (or delegate) can produce valid **transparent statements** for **register-grant** on grants under **L**. Therefore only that party can **issue** grants that extend **L**’s subtree—**data logs** (targets under **L**), **child AUTH_LOG** grants (leaves in **L** that mint new authority), and recursively the same pattern for children once **K(child)** is fixed.

---

## 4. Grant statement signature (register-grant) — specification

### 4.1 Inputs

- Raw bytes of the **transparent statement** (base64-decoded from `Authorization: Forestrie-Grant`).
- Decoded **`Grant`** from the payload (for **`ownerLogId`**, and for downstream §5).

### 4.2 Steps

1. **Parse** COSE Sign1: `protected`, `unprotected`, `payload` (grant CBOR), `signature`.
2. **Resolve L** = authority log id from **`ownerLogId`** (UUID string from wire bytes).
3. **Resolve verifying key set** $\mathcal{K}(L) = \{ K(L) \} \cup \mathrm{Delegates}(L)$:
   - Prefer **on-chain / indexer / univocity REST** when available; else **bootstrap grant** for **L** stored in operator pipeline; else **configured** keys for **L** (see §7).
4. **Verify** COSE Sign1 per RFC 9053: `Sig_structure` over `protected || payload` (and algorithm from protected header), **signature** against some key in $\mathcal{K}(L)$.
5. If verification fails → **403** (or **401**) — do not enqueue.

### 4.3 Bootstrap branch

When **L** is **uninitialised**, **$\mathcal{K}(L)$** is the **Custodian** / platform bootstrap key (current behaviour: `verifyBootstrapCoseSign1`). This is a **delegate** of the **root governance** model, not **K(L)** from **grantData** (which does not exist yet).

### 4.4 Relationship to §5

- **§5** proves the **inner** grant already sits in the MMR (non-bootstrap) or skips for bootstrap.
- **§4** proves **who** issued the **envelope**. Both are required for the full security story; neither replaces the other.

---

## 5. Receipt-based inclusion verification

This section realises the **receipt** side of §0: we treat the supplied artifact as carrying a checkpoint-style **$C_j$** (root + proof) and verify that the grant’s leaf is consistent with that MMR view.

### 5.1 Prerequisites

- The grant must be **completed** for the non-bootstrap path: **idtimestamp** (8 bytes) in header **-65537**. **Callers supply** **`Authorization: Forestrie-Grant <base64>`** with payload = grant CBOR, receipt in **396**.
- **Leaf commitment** uses header **idtimestamp** + **grant commitment hash** (`PublishGrant` preimage; Plan 0007).

### 5.2 Receipt format ($C_j$ wire shape)

- **Envelope:** COSE Sign1 (CBOR tag 18 optional).
- **Payload:** 32-byte **peak hash**.
- **Unprotected 396:** MMRIVER inclusion proof (`-1` → `[ { 1: mmrIndex, 2: path } ]`).

Optional: verify receipt COSE signature (policy).

### 5.3 Leaf commitment (grant leaf in $A_n$)

- `leafHash = SHA-256(idTimestampBE || inner)`
- `inner` = **grant commitment hash** (no **request**, no idtimestamp in preimage).

### 5.4 Verification pseudocode

```text
FUNCTION verify_grant_receipt(grant_assembly, idtimestamp, receipt_bytes [, options]):
    IF idtimestamp is missing OR length(idtimestamp) < 8 THEN RETURN false
    (root, proof, coseSign1) := parse_receipt(receipt_bytes)
    inner := grant_commitment_hash(grant_assembly)
    leaf_hash := univocity_leaf_hash(idtimestamp, inner)
    computed_root := calculate_root_async(leaf_hash, proof, SHA256)
    IF computed_root != root THEN RETURN false
    IF options.verify_signature AND NOT verify_cose_sign1_signature(coseSign1) THEN RETURN false
    RETURN true
```

### 5.5 Obtaining the receipt

Per Plan 0005 (private, cited by name), receipt is embedded in the grant artifact; no `X-Grant-Receipt-Location` in this phase.

---

## 6. Signer binding (register-signed-statement only)

### 6.0 Forestrie-Grant wire **v0** and **`PublishGrant.request` (`GC_*`)** vs **`grant` (`GF_*`)**

**Transparent-statement payload (current):** CBOR map keys **1–6** only — `logId`, `ownerLogId`, `grant` (8-byte bitmap), `maxHeight`, `minGrowth`, `grantData`. **No** keys **7** or **8** (obsolete **`signer`** / **`kind`**); **no** `version`, `exp`, or `nbf` on the map (implicit schema **v0**). **Issuer attestation** for who may sign registered statements is only **`grantData`**, which **is** in the commitment preimage. Parsers **reject** keys **7** and **8**. Storage path: **`grant/{sha256}.cbor`** (content-addressed).

**Solidity `PublishGrant`** also has optional **`request`** (**`GC_*`**) — not in the commitment preimage; may appear in TypeScript **`Grant.request`** when hydrated from chain, not required on the Forestrie v0 wire map.

| Axis                              | Where                           | Role                                                                                                                                                                                                                                                              |
| --------------------------------- | ------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **`GC_AUTH_LOG` / `GC_DATA_LOG`** | **`PublishGrant.request`**      | **Checkpoint publish** intent for **log creation** (auth vs data) at **`publishCheckpoint`** time; **not** in the leaf commitment preimage.                                                                                                                       |
| **`GF_*`**                        | **`PublishGrant.grant`** bitmap | **Create vs extend**, **auth log vs data log** target, etc.—**in** the commitment preimage. **`isStatementRegistrationGrant`** uses **`GF_DATA_LOG` + extend** for data-log `/entries`, and **`GF_AUTH_LOG` + `GF_CREATE\|GF_EXTEND`** for root bootstrap grants. |

After **§5** (when required):

1. **Bitmap:** **`isStatementRegistrationGrant(grant)`** MUST be true (`statement-signer-binding.ts`).
2. **`grantData`:** MUST be **non-empty**. The COSE **`kid`** (or, for **64-byte** ES256 **x||y**, the **first 32 bytes / x**) must match **`statementSignerBindingBytes(grant)`**.

**Skim — data log + univocity flags:** For **POST `/register/entries`** on a **data** log — i.e. the grant’s **`logId`** is that data log — **`PublishGrant.grant`** SHOULD carry **`GF_DATA_LOG`** and **`GF_EXTEND`**; **the first grant for that log SHOULD also set `GF_CREATE`**. Root **AUTH** bootstrap grants use **`GF_AUTH_LOG`** + **`GF_CREATE|GF_EXTEND`** with checkpoint key material in **`grantData`**. Full rationale: **§6.1**.

### 6.1 Intent, univocity flags, and “who signed the grant”

**Plain language (data log, POST `/register/entries`):** The owning **AUTH** log (via **§4** + **§5**) has placed a grant leaf that says, in effect: **checkpoints we publish for this data log may carry transparency statements signed by the key named in `grantData`.** The API enforces **`isStatementRegistrationGrant`** plus **`kid` ↔ `grantData`** (**§6.0**, §6 items 1–2).

**`GF_*` vs `GC_*` (univocity `constants.sol`, summarized in brainstorm-0001 §3.4 (private, cited by name)):** **`PublishGrant.grant`** is an 8-byte wire bitmap of **`GF_*`** flags (create/extend, auth vs data log, …). **`PublishGrant.request`** holds high-level **`GC_*`** codes used at **`publishCheckpoint`** time (e.g. log kind at **creation**); it is **not** in the leaf commitment preimage. For **register-signed-statement** alignment with the contract, the relevant discriminator is **`GF_DATA_LOG`** in **`grant`**, not **`GC_DATA_LOG`** in **`request`**.

**Suggested flag rule for this endpoint (normative target once bit tests exist in Canopy):** For grants authorizing **statement registration on a data log**, **`grant`** SHOULD include **`GF_EXTEND`** and **`GF_DATA_LOG`**. **In practice, `GF_CREATE` is also set** on the **first** grant for that log (first checkpoint): expect **`GF_CREATE \| GF_EXTEND`** together with **`GF_DATA_LOG`**. **Later** grants for the same log may omit **`GF_CREATE`** and carry **`GF_EXTEND`** (and **`GF_DATA_LOG`**) only, if policy allows extend-only follow-up grants. Grants meant for **AUTH** log checkpoint keys (bootstrap, new auth log) use **`GF_AUTH_LOG`** (and typically **GF_CREATE \| GF_EXTEND** for root bootstrap)—those are **register-grant** / checkpoint flows, not a substitute shape for arbitrary **data-log** **register-statement** grants.

**Authorizing log signer:** The party that **issues** the grant (proves the leaf is legitimate) MUST be the **checkpoint signer** for **`ownerLogId`** per **§4** (verify the **transparent statement** COSE signature). **§4** is the sole issuance check; inner CBOR convenience fields that are **not** in the **`PublishGrant`** commitment do not replace it.

**Model consistency:** Wire **v0** drops **`kind`** / **`signer`**; **`GF_*`** / **`GC_*`** remain **on-chain `PublishGrant`** fields. **`grantData` vs `kid`** is the **statement-signer** binding. Tighter **`request`/`GF_*`** matrix checks remain **P3** (**§9.8**) when univocity constants are in-repo.

See arc-grant-statement-signer-binding (private, cited by name).

### 6.3 Issuance signer vs endorsed statement signer (**implemented** — the split is live)

> **Revised 2026-08-09.** This subsection previously described the
> issuance-signer / endorsed-statement-signer split as *planned evolution*. That
> is **stale**: the split is **implemented and enforced** in canopy today, and
> the specific coupling this section used to assert (old §6.3.2, "envelope
> signer ≡ grantData identity on child first-grant paths") is **false against
> current code**. The text below is corrected against the implementation (canopy
> `main`, verified 2026-08-09 by file:line). Consumers that were sequenced
> "behind" this split — notably ARC-0028
> §3.3 and §9 Phase 0 — are unblocked on the platform-capability axis.

**Intent (unchanged):** `register-signed-statement` allows any child auth or
data log (except the bootstrap root) to receive a statement when a
**parent-issued** grant authorizes it, with the statement **`kid`** bound to an
**endorsed** key that **may differ** from the party that signed the transparent
Forestrie-Grant envelope.

#### 6.3.1 Verdict: implemented, by convention rather than by a new wire field

The two identities are **already distinct keys in practice**, carried without a
new structured field:

- **Issuer / authority** — never `grantData`. Grant authenticity is established
  by **§4** against the authority keyed off **`ownerLogId`**, via one of three
  branches (§6.3.2) — *not* by verifying the envelope against `grantData`.
- **Endorsed statement signer** — `grantData`. The statement `kid` and the
  statement COSE **signature** are both checked against the `grantData` key
  (**§6**; `register-signed-statement.ts:208-269`).

So `grantData` = *subject / statement signer*; envelope + receipt = *authority*.
The split the old text called "planned" is exactly this separation, and it is
the shipped default — `ietf-126-demo` slide 6 exercises it end-to-end: a
data-log grant signed by the parent (`David`) with `grantData` = `Alice`, after
which `Alice` signs statements with her own key.

#### 6.3.2 What the code actually does (the authority is never `grantData`)

**`register-grant.ts`** contains **no** call to
`verifyCustodianEs256GrantSign1WithGrantDataXy` /
`verifyGrantCoseSign1WithGrantDataXy` (the latter helper is misnamed — all live
callers pass an **authority** key, not the grant's own `grantData` — and the
former is deprecated with no live source callers). Issuance is verified by one
of three branches, selected by target-log MMRS state and grant flags
(`register-grant.ts:169-263`):

| Branch | Grant | Envelope / authenticity verified against | Where |
| --- | --- | --- | --- |
| **Creation** (uninitialized target) | `GF_CREATE` child auth/data | **owner authority key** (parent `K(L)` / genesis bootstrap), delegated to univocity `creationGrantValidator.validate(...)` | `register-grant.ts:190-254`; envelope-vs-parent-key in `prepare-child-log.ts:125-195` |
| **Derived endorsement** (`GF_DERIVED\|GF_EXTEND`, no `GF_CREATE`) | endorsement leaf | **endorser forest bootstrap authority key** (`genesis.bootstrapKey`) | `register-grant.ts:315-380` → `verify-derived-endorsement-envelope.ts:12-47` |
| **Steady-state** (initialized target) | extend | **receipt inclusion** against the `ownerLogId` receipt authority (checkpoint signer) | `register-grant.ts:256-263`; `grantAuthorize` in `auth-grant.ts:260-403` |

In every branch the verifying key is the **parent/owner or genesis authority**,
a **different key** from the child's `grantData` (which is the child owner /
endorsed signer — `prepare-child-log.ts:264-274`).

**`register-signed-statement`** does not re-verify the grant envelope in-handler,
and this is **intentional, not a gap**: grant authenticity comes from **receipt
inclusion** via `grantAuthorize` (`register-signed-statement.ts:154`) against the
`ownerLogId` authority. The handler then enforces **§6** — `kid` binding
(`:208-218`) and statement-signature verification against the `grantData` key
(`:221-269`) — and, for data-log statement grants, requires
**`ownerLogId != logId`** (`:195-202`), i.e. a *distinct governing AUTH log*.
The file comment states the design directly: *"The grant itself is NOT verified
against `grantData` because delegated grants are signed by the authority key (of
`ownerLogId`), not the key embedded in `grantData`. The grant's authenticity is
established via receipt inclusion in `grantAuthorize`."*

#### 6.3.3 Status of the former delta list (D1–D6)

The old "planned deltas" table is retired. Against current code:

| # | Former delta | Status |
| --- | --- | --- |
| **D1** | versioned/structured field for the endorsed signer, distinct from issuer, in the commitment | **Not built — and not required.** The distinction is carried by convention (`grantData` = subject; `ownerLogId` / receipt = authority), which is sufficient and shipped. A structured field remains an *optional* cleanup, not an enabler. |
| **D2** | per-branch matrix of which key verifies the transparent Sign1 | **Superseded / done differently.** A branch matrix exists (§6.3.2) but it is "which *authority* verifies issuance" (univocity / receipt / endorsement) — none verify against `grantData`. The imagined `verifyCustodian…WithGrantDataXy`-per-branch design is gone. |
| **D3** | keep `kid`↔`grantData`; add independent §4 envelope verify in the statement handler | **`kid` binding: done.** In-handler §4 envelope verify: **deliberately not done** — issuance authenticity is established by receipt inclusion against the `ownerLogId` authority instead. |
| **D4 / D5** | doc normative text (this ARC; the signer-binding ARC) | **This revision** addresses D4. §6.0 / §6.1 wording that reads as if `grantData` is *both* issuer and endorsed signer should be interpreted through this section. |
| **D6** | tests for parent-signed envelope ≠ `grantData` | **Partial — coverage is thin on exactly this path.** `register-grant-derived-endorsement.test.ts` exercises envelope-vs-bootstrap-key with empty `grantData`; but the `ownerLogId != logId` 403 branch and `prepare-child-log.ts`'s parent-authority verify have **no direct canopy-side test**. Recommended follow-up. |

**Bootstrap root** remains the **only** case where **§4.3** permits a **platform delegate** without prior **K(L)** from **`grantData`** for **that** log (**§0.3**, **§2**).

#### 6.3.4 Non-goals (no silent loosening)

- Do **not** accept **`kid`** merely because “some key validly signed the transparent statement” without a **committed** endorsement in the **grant preimage** aligned with **§6**.
- Do **not** drop **`isStatementRegistrationGrant`** / bitmap rules; **data vs auth** class for the **target** log must remain explicit.

### 6.2 Should Canopy treat **`Grant`** as contract-shaped and check consistency with the preimage inputs?

**Committed fields (in the preimage):** After decode, **`logId`**, **`grant`** (bitmap), **`maxHeight`**, **`minGrowth`**, **`ownerLogId`**, and **`grantData`** are **one** value set. The commitment preimage is **derived** from that set (`grant-commitment.ts`); there is no second on-wire copy of those fields to reconcile. Inconsistency would mean a broken codec or corrupted bytes, not “payload vs preimage drift.”

**`request` (`GC_*`):** Optional on TypeScript **`Grant`** when hydrated from chain; **not** required on Forestrie wire **v0**. The chain can still enforce relationships between **`request`**, **`grant`** (**`GF_*`**), and checkpoint calls. Therefore:

- **Yes (recommended):** Once univocity documents **compatibility rules** (e.g. which **`GC_*`** values may accompany which **`GF_*`** patterns, auth vs data log, create vs extend), Canopy **should** validate **`grant.request`** (when present) against **`grant.grant`** the same way a careful **`publishCheckpoint`** caller would—so off-chain auth does not accept artifacts the contract would treat as ill-formed or misleading.
- **Wire v0:** Maps that include obsolete keys **7**/**8** or unknown extensions **must** be **rejected** at decode. There is **no** parallel **`signer`** field on the wire; **`grantData`** is the only issuer attestation for statement-signer binding (**§6**).

**Summary:** The preimage discussion **does not** mean “re-validate `logId` twice.” It **does** imply that **`Grant.request`** (when hydrated) **should** be checked for **contract-consistent** combinations with the **`grant`** bitmap (and with HTTP context such as path **`logId`**) when those rules are codified—**§9.8** (bitmap) plus a future **`request`/`GF_*` matrix** sourced from univocity.

---

## 7. Summary flow (target)

**register-grant (non-bootstrap, normative):**

```text
bytes := base64_decode(Authorization: Forestrie-Grant)
assembly := decode_grant_payload_from_transparent_statement(bytes)
IF NOT verify_grant_statement_signature(bytes, assembly.ownerLogId) THEN RETURN 403   // §4
IF NOT grant_completed(idtimestamp) THEN RETURN 403
IF NOT verify_grant_receipt(assembly, idtimestamp, receipt) THEN RETURN 403         // §5
enqueue(…)
RETURN 303
```

**register-grant (bootstrap):**

```text
bytes := …
assembly := …
IF NOT verify_bootstrap_delegate_signature(bytes) THEN RETURN 403   // §4.3 — current verifyBootstrapCoseSign1
… bootstrap shape checks …
enqueue(…)
```

**register-signed-statement:**

```text
… grant_result …
IF inclusion required AND NOT verify_grant_receipt(…) THEN RETURN 403
IF NOT isStatementRegistrationGrant(grant) THEN RETURN 403   // bitmap + data-log or bootstrap auth shape
IF statement.kid != statementSignerBindingBytes(grant) THEN RETURN 403   // grantData only (v0 wire)
enqueue_statement(…)
```

---
