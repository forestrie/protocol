# Codepoint and flag registry

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

Every codepoint Forestrie uses, what defines it, where it is declared, and
the one **display name** a tool prints for it. Values in the COSE private-use
space — IANA reserves labels **less than −65536** for private use; `−65535`
and `−65536` themselves are Specification Required — are unregistered by
definition; they are conventions this system agrees on, and the agreement is
only as good as the table below.

The **Display name** column is normative for rendered output: a decoder that
prints a name for a codepoint prints this string, so that two tools describing
the same bytes agree. Changing a display name changes what tools print, so the
order of adoption is: settle the wording here, land it in the command-line
client, then adopt it in the MCP verification server.

"Declared in" names one public module per codepoint where the value is
written as a named constant. It is where a copy should be imported from, and
where a reviewer checks the value.

## 1. COSE algorithms

| Value | Name | Display name | Registry status | Used for | Declared in |
|---|---|---|---|---|---|
| `-7` | `ES256` | `ES256 (ECDSA P-256 + SHA-256)` | RFC 9053 | Checkpoint signing, leaf signing, certificates | RFC 9053 |
| `-65799` | `KS256` | `KS256 (secp256k1 + Keccak-256, forestrie private-use)` | Private use | secp256k1 + Keccak + Ethereum address; checkpoints and certificates | univocity `src/cosecbor/constants.sol`; canopy `packages/shared/encoding/src/verify-cose-sign1.ts` |
| `-65800` | `ALG_ES256_WEBAUTHN` | `ES256-WebAuthn (forestrie private-use; delegation proofs, certificates and session-key endorsements, never checkpoint-signing)` | Private use | An ES256 key whose signature is a WebAuthn assertion: **delegation proofs, delegation certificates and session-key endorsements** — never a checkpoint-signing algorithm | univocity `src/cosecbor/constants.sol`; canopy `packages/shared/encoding/src/verify-cose-sign1.ts`; arbor `services/pkgs/delegationcert/build_certificate.go` (`CoseAlgES256WebAuthn`) |

## 2. COSE header parameters

### 2.1 Registered

| Label | Name | Display name | Header | Meaning | Registry |
|---|---|---|---|---|---|
| `1` | `alg` | `alg` | Protected | Algorithm | RFC 9052 |
| `3` | `cty` | `content type` | Protected | Content type | RFC 9052 |
| `4` | `kid` | `kid` | Protected | Key id | RFC 9052 |
| `15` | CWT claims | `CWT claims` | Protected | CWT claims set, on a signed statement | RFC 9597 |
| `395` | `vds` | `verifiable data structure` | Protected | Verifiable data structure. Value `3` denotes the MMR profile: **requested by the MMR profile draft, not registered** — IANA's registry holds only `1` (`RFC9162_SHA256`). The Go sealer emits `395: 3` on every checkpoint and peak receipt; the TypeScript exporters do not, and no vector in this repository carries it. A verifier must not require it and must not present it as registry fact | RFC 9942 |
| `396` | `vdp` | `verifiable proofs` | Unprotected | Verifiable proofs map. Key `-1` holds the array of inclusion proofs a receipt carries (`{1: mmrIndex, 2: path}` each; the first element is read). Key `-2` holds the consistency proof a checkpoint carries, as a byte string wrapping `[tree-size-1, tree-size-2, paths, right-peaks]` | RFC 9942 |

Display names for the value of `395`: `1` → `RFC9162_SHA256 (Certificate
Transparency)`, `2` → `CCF_LEDGER_SHA256`, `3` → `MMR profile (draft-bryce,
codepoint TBD)`.

### 2.2 Private use — receipts, grants and checkpoints

| Label | Name in these docs | Display name | Arithmetic | Header | Meaning | Declared in |
|---|---|---|---|---|---|---|
| `-65535` | `COSEPrivateStart` | — | — | — | **A Forestrie arithmetic base, not the IANA boundary.** Derived labels are allocated by subtracting a registered label from it (`−65535 − 396 = −65931`, `−65535 − 1000 = −66535`). The private-use space itself begins below `−65536` | go-merklelog `massifs/checkpointreceipt.go` |
| `-65537` | idtimestamp | `idtimestamp` | — | Unprotected | The assigned idtimestamp, an 8-byte big-endian byte string, on a sealed grant's transparent statement | canopy `packages/libs/receipt-verify/src/forest-genesis-labels.ts` (`HEADER_IDTIMESTAMP`); arbor `services/univocity/src/grant.go` |
| `-65538` | embedded grant | `forestrie grant v0` | — | Unprotected | The full inner grant bytes (keys 1–6), on a sealed grant's transparent statement | canopy `packages/libs/receipt-verify/src/forest-genesis-labels.ts` (`HEADER_FORESTRIE_GRANT_V0`); arbor `services/univocity/src/grant.go` |
| `-65800` | **`TBD1`** — WebAuthn assertion envelope | `WebAuthn assertion envelope` | — | Unprotected | `[authenticatorData, clientDataJSON]`. **Reuses the algorithm's number — see §4** | canopy `packages/shared/encoding/src/verify-cose-sign1.ts` (`WEBAUTHN_ENVELOPE_LABEL`); arbor `services/pkgs/delegationcert/build_certificate.go` (`CoseHeaderWebAuthnEnvelope`) |
| `-65801` | **`TBD2`** — session-key endorsement | `session key endorsement` | — | Unprotected | The endorsement COSE Sign1, embedded as a byte string, on every endorsed entry | canopy `packages/shared/encoding/src/verify-cose-sign1.ts` (`COSE_LABEL_SESSION_KEY_ENDORSEMENT`) |
| `-65931` | `SealPeakReceiptsLabel` | `pre-signed peak receipts` | `-65535 - 396` | Unprotected | Pre-signed per-peak inclusion receipts on a checkpoint: an array of byte strings, one tagged COSE Sign1 per peak | go-merklelog `massifs/checkpointreceipt.go` |
| `-66535` | `SealDelegationProofLabel` | `on-chain delegation proof` | `-65535 - 1000` | Unprotected | The on-chain delegation proof carried in a checkpoint | go-merklelog `massifs/checkpointreceipt.go` |
| `1000` | `delegationCertUnprotectedLabel` | `delegation certificate` | — | Unprotected | The delegation certificate, as a **byte string wrapping its COSE Sign1**. Predates the private-use convention and is **not** in that space | arbor `services/sealer/src/sealer.go`; canopy `packages/apps/canopy-api/src/grant/delegation-verify.ts` |

Note `1000` and `-66535` coexist in the same checkpoint and mean different
things — the certificate bytes and the on-chain proof respectively. The offset
in `SealDelegationProofLabel` mirrors the older label's number; it does not
replace it.

### 2.3 Private use — the forest genesis document

The forest genesis document is a CBOR map with these integer labels. Its
wire format is specified in [log-authority-and-grants.md](./log-authority-and-grants.md)
§1; this table is the lookup.

| Label | Name | Display name | Type | Meaning | Declared in |
|---|---|---|---|---|---|
| `-68009` | genesis version | `forest genesis version` | uint | Schema version; `2` is the only version written | canopy `packages/libs/receipt-verify/src/forest-genesis-labels.ts`; arbor `services/univocity/src/genesis_labels.go` |
| `-68010` | bootstrap log id | `bootstrap log id` | bstr, 32 bytes | The id of the forest's root authority log, in the padded 32-byte wire form (the 16-byte UUID in the low bytes) | same |
| `-68011` | univocity address | `univocity address` | bstr, 20 bytes | The anchoring contract's address | same |
| `-68012` | legacy chain ids | `legacy chain ids` | array of uint | **Retired.** A version-2 document must not carry it; a decoder rejects it | canopy `packages/apps/canopy-api/src/forest/forest-genesis-labels.ts`; arbor `services/univocity/src/genesis_labels.go` |
| `-68013` | chain id | `chain id` | tstr | The EIP-155 chain id as a **decimal text string** | canopy `packages/libs/receipt-verify/src/forest-genesis-labels.ts`; arbor `services/univocity/src/genesis_labels.go` |
| `-68014` | bootstrap key algorithm | `forest genesis alg` | int | The COSE algorithm of the bootstrap key: `-7` or `-65799` | same |
| `-68015` | bootstrap public key | `bootstrap key` | bstr | The bootstrap key: **64-byte `x‖y`** under ES256, **20-byte address** under KS256 | same |
| `-68016` | univocity variant | `univocity variant` | tstr | The contract variant when it is not the immutable one; the only value written is `uups-counterfactual` | canopy `packages/apps/canopy-api/src/forest/forest-genesis-labels.ts` |
| `-68017` | univocity deployer | `univocity deployer` | bstr, 20 bytes | The deterministic-deployment factory address; required exactly when the variant is `uups-counterfactual` | same |

## 3. Payload and map keys

Each payload's map keys are specified once, in the document that owns the
artifact; this section only says where.

### 3.1 Inner grant CBOR

Keys `0`–`6`: [log-authority-and-grants.md](./log-authority-and-grants.md)
§2.1. Keys `7` (legacy `signer`) and `8` (legacy `kind`) are **rejected on
sight**, in both the response and payload decoders; `grantData` is the sole
statement-signer binding, and
[`vectors/fixtures/grant_vectors_negative.json`](../vectors/fixtures/grant_vectors_negative.json)
carries maps with those keys that every decoder must refuse.

### 3.2 Delegation certificate payload

Labels `1` and `3`–`10`:
[delegation-and-webauthn-envelopes.md](./delegation-and-webauthn-envelopes.md)
§5.1, including which labels an encoder may omit. **Label `2` is unassigned**
and must not be used without a decision.

### 3.3 Session-key endorsement payload

The three text-string keys:
[leaf-admission-and-session-endorsement.md](./leaf-admission-and-session-endorsement.md)
§3.

## 4. The `-65800` collision

**`-65800` means two things**: a COSE *algorithm* and a COSE *header
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
| 35 | `GF_CHILD_PAYMENT_REQUIRED` | The operator's registration API | Assigned off-chain: wire byte 3, mask `0x08`. Set on a parent grant, it makes the operator require payment before registering a child grant. Committed in the parent's leaf, so provable from its receipt; invisible to the contract and never an input to verification |
| 36–39 | Operator-assignable band | **Nothing on-chain** | Reserved by convention only — see below |
| 40–47 | `GF_ALG_MASK` — algorithm policy | Chain, fail-closed | Bit 40 is `GF_REQUIRES_USER_VERIFICATION`; bits 41–47 are unallocated and **always revert** |
| 224–255 | `GF_GC_MASK` — request codes `GC_*` | Not committed | Excluded from the leaf commitment |

**Bits 35–39 have no on-chain constant.** The contract's promise not to read
them holds only because no code does — there is no mask, and no test asserts
that `GF_ALG_MASK` stays clear of the band. A future widening of the algorithm
band downward would break the promise silently. Bit 35's meaning is defined by
the operator's registration API, not by this registry or the contract.

**The algorithm-policy band is fail-closed.** If a grant sets a band bit the
supplied delegation algorithm does not consume, the publish reverts. Only
`ALG_ES256_WEBAUTHN` consumes bit 40. A stated policy can therefore never be
silently dropped — which is the property that makes it safe to put policy in
the grant.

## 6. Where the consumers diverge

Two tools render these codepoints. Against the display names above:

- the command-line client's table names every codepoint in §§1–2 that a
  receipt or checkpoint carries; its algorithm string for `-65800` omits
  session-key endorsements, and its notes for `395`/`396` still say "draft";
- the MCP verification server's table omits the `-65800` header entry and
  `-66535`, and carries the same "draft" notes.

Those are implementation differences to be closed in the order stated in the
summary, not registry facts.

## Open questions

- **`TBD1` needs a real assignment** distinct from the algorithm's number, and
  the aliased constants need to be separated (§4).
- **Bits 35–39 are reserved by comment only** (§5) — no mask, no test.
- **Should the timing constants become part of the wire contract?** The
  endorsement not-before skew and the browser's not-before backdate are
  deployment-local numbers that must agree across two repositories for the
  system to behave correctly; see
  [leaf-admission-and-session-endorsement.md](./leaf-admission-and-session-endorsement.md)
  §7.

## References

- [delegation-and-webauthn-envelopes.md](./delegation-and-webauthn-envelopes.md)
  — what `ALG_ES256_WEBAUTHN` and `TBD1` are for, and the fail-closed rules.
- [leaf-admission-and-session-endorsement.md](./leaf-admission-and-session-endorsement.md)
  — `TBD2` and the endorsement payload.
- [log-authority-and-grants.md](./log-authority-and-grants.md) — the grant
  wire format and what the flags mean.
- [checkpoints-and-receipts.md](./checkpoints-and-receipts.md) — the checkpoint
  labels.
- [vectors/](../vectors/) — the conformance vectors these codepoints appear in.
