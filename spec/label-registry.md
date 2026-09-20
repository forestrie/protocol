# Codepoint and flag registry

**Status:** LIVE
**Date:** 2026-09-20
**Audience:** anyone implementing or reviewing a Forestrie encoder or
verifier. This is the lookup table; the reasoning lives in the documents it
links to.
**Related:**
[delegation-and-webauthn-envelopes.md](./delegation-and-webauthn-envelopes.md),
[leaf-admission-and-session-endorsement.md](./leaf-admission-and-session-endorsement.md),
[log-authority-and-grants.md](./log-authority-and-grants.md),
[checkpoints-and-receipts.md](./checkpoints-and-receipts.md),
[glossary.md](../glossary.md).

## Summary

Every codepoint Forestrie uses, what defines it, and **who is authoritative and
who copies** — the distinction that governs drift. Values
in the COSE private-use space (below `-65535`) are unregistered by definition;
they are conventions this system agrees on, and the agreement is only as good
as the table below.

## 1. COSE algorithms

| Name | Value | Registry status | Used for |
|---|---|---|---|
| `ES256` | `-7` | RFC 9053 | Checkpoint signing, leaf signing, certificates |
| `KS256` | `-65799` | Private use | secp256k1 + Keccak + Ethereum address; checkpoints and certificates |
| `ALG_ES256_WEBAUTHN` | `-65800` | Private use | **Delegation proofs and certificates only** — never a checkpoint-signing algorithm |

## 2. COSE header parameters

### 2.1 Standard and draft

| Label | Name | Header | Meaning |
|---|---|---|---|
| `1` | `alg` | Protected | Algorithm |
| `3` | `cty` | Protected | Content type |
| `4` | `kid` | Protected | Key id |
| `395` | `vds` | Protected | Verifiable data structure. Value `3` = the MMR consistency profile |
| `396` | `vdp` | Unprotected | Verifiable proofs map. Key `-2` inside it carries the consistency proof |

### 2.2 Private use

| Name in these docs | Current value | Arithmetic | Header | Meaning |
|---|---|---|---|---|
| `COSEPrivateStart` | `-65535` | — | — | Start of the private-use space; allocation below this must be coordinated Forestrie-wide |
| **`TBD1`** — WebAuthn assertion envelope | `-65800` | — | Unprotected | `[authenticatorData, clientDataJSON]`. **Reuses the algorithm's number — see §4** |
| **`TBD2`** — session-key endorsement | `-65801` | — | Unprotected | The endorsement COSE Sign1, embedded as a bstr |
| `SealPeakReceiptsLabel` | `-65931` | `-65535 - 396` | Unprotected | Pre-signed per-peak inclusion receipts on a checkpoint |
| `tree-size-2` (profile draft `TBD_2`) | `-65933` | `-65535 - 398` | **Protected** | The signed size a checkpoint's consistency is proven **to** — the size whose accumulator is the payload and the size the contract anchors. CBOR unsigned integer (major type 0). MUST equal the last consistency proof's `tree-size-2`. Interim private-use pending IANA via the profile draft — [ADR-0066](https://github.com/forestrie/devdocs/blob/main/adr/adr-0066-sec-signed-checkpoint-size.md) |
| ~~`tree-size-1`~~ | ~~`-65932`~~ | `-65535 - 397` | — | **Withdrawn 2026-09-20** before any deployment used it (ADR-0066 amendment 1: `tree-size-1` is unsigned prover context in the consistency proof). Not to be reassigned |
| `SealDelegationProofLabel` | `-66535` | `-65535 - 1000` | Unprotected | The on-chain delegation proof carried in a checkpoint |
| `delegationCertUnprotectedLabel` | `1000` | — | Unprotected | The delegation certificate bytes, as a CBOR bstr. Predates the private-use convention and is **not** in that space |

Note `1000` and `-66535` coexist in the same checkpoint and mean different
things — the certificate bytes and the on-chain proof respectively. The offset
in `SealDelegationProofLabel` mirrors the older label's number; it does not
replace it.

**Derivation convention.** A derived label is `COSEPrivateStart - <related
registered label>`. When no registered label is related, the derivation uses
the *next conceptual slot* in the registered sequence: `tree-size-2` takes
398, the slot after `vds` (395), `vdp` (396) and the withdrawn `tree-size-1`
(397), because it is the next protected-header parameter the MMR profile adds.
The `-658xx` band is not extended, since an algorithm and a header parameter
already share `-65800` there (§4).

`tree-size-2` is the **only protected-header label in the private-use
space**. The profile draft names it `TBD_2` (its `TBD_1` is `vds`); that name
is the draft's, and is unrelated to this registry's `TBD1`/`TBD2`, which are
unprotected envelope labels. It MUST be present on a checkpoint receipt, and
every verifier compares it with the last proof's declared `tree-size-2`
before it trusts the fold — see
[checkpoints-and-receipts.md](./checkpoints-and-receipts.md) §1.3. The
protected header itself MUST be deterministic CBOR (ADR-0066 D9).

## 3. Payload and map keys

### 3.1 Inner grant CBOR

Verified against the codec, not the ADRs — an earlier catalogue pass had this
mapping wrong.

| Key | Field | Wire type |
|---|---|---|
| `0` | `idtimestamp` | bstr, 8 bytes — **response format only**, never in the signed payload |
| `1` | `logId` | bstr, 32-byte padded wire (16-byte UUID in the low bytes) |
| `2` | `ownerLogId` | bstr, 32-byte padded wire |
| `3` | `grant` (flags) | bstr, left-padded to 8 bytes |
| `4` | `maxHeight` | uint |
| `5` | `minGrowth` | uint |
| `6` | `grantData` | bstr |

Keys `7` (legacy `signer`) and `8` (legacy `kind`) are **rejected on sight**,
in both the response and payload decoders. `grantData` is the sole
statement-signer binding.

### 3.2 Delegation certificate payload

| Label | Field | Notes |
|---|---|---|
| `1` | `log_id` | tstr hex; omitted when empty |
| `3` | `mmr_start` | omitted when `log_id` is empty |
| `4` | `mmr_end` | omitted when `log_id` is empty |
| `5` | `delegated_key` | COSE_Key `{1: 2, -1: 1, -2: x, -3: y}` |
| `6` | `constraints` | always present, `{}` when none |
| `7` | `schema_ver` | always `1` |
| `8` | `issued_at` | omitted when zero |
| `9` | `expires_at` | omitted when zero |
| `10` | `delegation_id` | bstr |

**Label `2` is unassigned** and must not be used without a decision.

### 3.3 Session-key endorsement payload

Three text-string keys, exactly — any other count is a decode failure.

| Key | Type |
|---|---|
| `"sessionKey"` | bstr, exactly 64 bytes (x‖y) |
| `"notBefore"` | uint, unix milliseconds |
| `"notAfter"` | uint, unix milliseconds |

## 4. The `-65800` collision

**`-65800` currently means two things**: a COSE *algorithm* and a COSE *header
parameter*. These live in different IANA registries and never occupy the same
parse position — the algorithm appears as a value under protected label `1`,
the envelope as a key in the unprotected map — so it is not a wire ambiguity.

It is still a bug, and this registry is where the cost shows:

- The header-parameter constant is defined as a literal **alias** of the
  algorithm constant, so the two cannot diverge even when they should.
- The envelope's legality is conditional on the algorithm, which makes the
  "is this label allowed here?" question answerable only with context.
- Every definition of the endorsement label has to carry a "this is **not** the
  envelope" disclaimer to stop implementers conflating them.

**`TBD1` is the envelope**; the algorithm keeps `-65800`. Until `TBD1` is
assigned, code shipping against Forestrie must use `-65800` for both. `TBD2`
(the endorsement) is a separate, single-purpose label with no collision — it is
given a TBD name for consistency, not because anything is wrong with it.

## 5. Grant flag bands

The `grant` field is a `uint256` on-chain and an 8-byte big-endian array on the
canopy wire. Bit *n* on-chain maps to the wire array as byte `7 - (n div 8)`,
mask `1 << (n mod 8)` — so bit 40 is **wire byte 2, mask `0x01`**.

| Bits | Band | Enforced by | Notes |
|---|---|---|---|
| 0–1 | Log kind — `GF_AUTH_LOG` (0), `GF_DATA_LOG` (1) | Chain | |
| 32–34 | `GF_CREATE` (32), `GF_EXTEND` (33), `GF_DERIVED` (34) | Chain | |
| 35–39 | Canopy-assignable derived band | **Nothing on-chain** | Reserved by convention only — see below |
| 40–47 | `GF_ALG_MASK` — algorithm policy | Chain, fail-closed | Bit 40 is `GF_REQUIRES_USER_VERIFICATION`; bits 41–47 are unallocated and **always revert** |
| 224–255 | `GF_GC_MASK` — request codes `GC_*` | Not committed | Excluded from the leaf commitment |

**Bits 35–39 have no on-chain constant.** The contract's promise not to read
them holds today only because no code does — there is no mask, and no test
asserts that `GF_ALG_MASK` stays clear of the band. A future widening of the
algorithm band downward would break the promise silently.

**The algorithm-policy band is fail-closed.** If a grant sets a band bit the
supplied delegation algorithm does not consume, the publish reverts. Only
`ALG_ES256_WEBAUTHN` consumes bit 40. A stated policy can therefore never be
silently dropped — which is the property that makes it safe to put policy in
the grant.

## 6. Who is authoritative

"Definition" means the value is written once; "literal" means the number is
typed again somewhere it could have been imported.

| Value | Authoritative | Declaration sites | Agree? | Weakest link |
|---|---|---|---|---|
| `-7` | RFC 9053 | many | Yes | — |
| `-65799` | Solidity constants (chain) + the TypeScript encoding package | 13 named, 4 bare | **Yes** | Two browser-client call sites put a **bare `-65799`** in a request body with no named constant at all |
| `-65800` | Solidity constants (chain) + the TypeScript encoding package | 3 named | **Yes** | One canopy library re-types the literal instead of importing it; **arbor has no name for it at all** — it exists there only as test hex |
| `-65801` (`TBD2`) | The TypeScript encoding package | **1** | **Yes** | None. This is the only codepoint with clean single-definition hygiene |
| `-65933` (signed `tree-size-2`) | Solidity constant (chain, univocity #43) + go-merklelog (#11, merged) + the TypeScript encoding package (canopy #255) | 3 named | pending the slice 06 cross-language KAT | New; the Go, Solidity and TypeScript declarations are pinned to one KAT before any deploys. The canonical ES256 header for size 8 is `a3012619018b033a0001018c08` |
| Bit 40 / UV | Solidity constants (chain) | 1 chain, 3 hand-derived TypeScript, 2 test literals | **Yes** | The bit-40 → byte-2/`0x01` translation is hand-derived in four independent places; a text-comparison test covers two of them, and only one assertion anywhere ties the wire encoding back to the on-chain bit |

Two related constants deserve the same treatment and do not currently get it:

- **The endorsement not-before skew** (5 minutes) is declared independently in
  canopy admission and in the browser client's session component, with only a comment
  asserting they must match.
- **The browser's not-before backdate** (60 seconds) is sized against that
  5-minute skew with no code linkage at all.

All values agree today. Nothing mechanically enforces that they keep agreeing,
except the one fork-sync test and the one bit-40 equivalence assertion.

## Open questions

- **`TBD1` needs a real assignment** distinct from the algorithm's number, and
  the aliased constants need to be separated (§4).
- **Bits 35–39 are reserved by comment only** (§5) — no mask, no test.
- **The duplicated constants have no shared source.** Every TypeScript site
  listed in §6 can already import from the encoding package; most do not.
  arbor has no Go name for `-65800` despite handling it on the publish path.
- **Should the skew and backdate constants become part of the wire contract?**
  They are currently deployment-local numbers that must agree across two
  repositories for the system to behave correctly.

## References

- [delegation-and-webauthn-envelopes.md](./delegation-and-webauthn-envelopes.md)
  — what `ALG_ES256_WEBAUTHN` and `TBD1` are for, and the fail-closed rules.
- [leaf-admission-and-session-endorsement.md](./leaf-admission-and-session-endorsement.md)
  — `TBD2` and the endorsement payload.
- [log-authority-and-grants.md](./log-authority-and-grants.md) — the grant
  wire format and what the flags mean.
- [checkpoints-and-receipts.md](./checkpoints-and-receipts.md) — the checkpoint
  labels, and what the checkpoint signature covers.
- [ADR-0066](https://github.com/forestrie/devdocs/blob/main/adr/adr-0066-sec-signed-checkpoint-size.md)
  — why the tree sizes are signed, and the verification MUSTs.
- [vectors/](../vectors/) — the conformance vectors these codepoints appear in.
