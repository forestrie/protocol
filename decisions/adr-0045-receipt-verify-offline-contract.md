# ADR-0045: Offline receipt verify contract (`@forestrie/receipt-verify`)

**Status:** ACCEPTED  
Accepted 2026-09-12 on promotion to forestrie/protocol; the contract had been treated as normative by every implementation since it was written.  
**Date:** 2026-07-04  
**Related:** [ARC-0019](./arc-0019-grant-verification-model.md),
ARC-0025 (private, cited by name),
ADR-0030 (private, cited by name),
plan-0030 (private, cited by name),
[canopy grant verification implementation](https://github.com/forestrie/canopy/blob/main/docs/arc/canopy-grant-verification-implementation.md),
FOR-279

## Context

Forestrie promotion gates today prove that SCRAPI **returns** SCITT receipts on
live lanes. They do not prove that a relying party can **verify** those receipts
offline against the forest genesis trust anchor — the headline product claim in
the decentralised brief.

Server-side grant receipt verification already exists in
[receipt-verify.ts](https://github.com/forestrie/canopy/blob/main/packages/apps/canopy-api/src/grant/receipt-verify.ts).
This ADR defines the **public contract** for a shared
`@forestrie/receipt-verify` package (canopy monorepo workspace) consumed by
`@canopy/api`, `@forestrie/canopy-e2e-kit`, CLI tooling, and T3 system tests.
Implementation is tracked separately (Grant receipt offline verify).

## Decision

### 1. Package and scope

- **Package name:** `@forestrie/receipt-verify` (canopy workspace package;
  publish policy TBD — kit re-export may suffice for the estate's
  integration test suite).
- **In scope:** verify layers **A–C** (see below) over captured bytes only.
- **Out of scope (layer D):** on-chain accumulator / burial / tip
  canonicality — separate “on-chain loop” initiative; not mixed into offline
  verify.

### 2. Verify layers A–C

| Layer | Name | What is checked | Trust source |
|-------|------|-----------------|--------------|
| **A** | Receipt signature | COSE Sign1 over MMR peak (detached or embedded 32-byte peak) | ES256 key from **genesis COSE trust root only** (offline path) |
| **B** | MMR inclusion | Header **396** inclusion proof against signed peak | Pure crypto over receipt bytes |
| **C** | Leaf binding | Leaf hash matches receipt subject (grant commitment or statement content hash + idtimestamp) | Caller-supplied grant / statement context |

Layer **D** (on-chain canonicality) is **explicitly deferred**. Offline verify
may succeed while the tip is not yet buried on-chain; product FAQ treats A–C
vs D separately.

### 3. Offline boundary

Verify functions are **pure over bytes**. During verify they **must not**:

- call SCRAPI or any HTTP client;
- call the delegation coordinator;
- call univocity HTTP or `TrustRootClient` network paths;
- read Workers bindings, Doppler, or live lane secrets.

**Allowed before verify (trust bootstrap, not part of verify):**

- one-time `GET /api/forest/{R}/genesis` (or genesis from provision / test
  fixture);
- loading `genesis.cbor` from disk in CLI or T3 artefact capture.

Trust keys for layer A come from **genesis COSE trust root only**, mirroring
[decode-trust-root-cbor.ts](https://github.com/forestrie/canopy/blob/main/packages/apps/canopy-api/src/env/decode-trust-root-cbor.ts)
(`decodeTrustRootFromGenesis(genesisCbor)` export). KS256 genesis roots are used
for delegation-cert paths (BYOK extension); ES256 roots verify receipt Sign1.

**Distinction:** server **register-grant** receipt verify resolves live trust
roots and delegation chains; **offline verify** uses genesis-only keys and
caller-supplied delegation material when BYOK extensions land.

### 4. Public API

#### 4.1 Shared types

```typescript
/** Failure stage for falsifiable tests and CLI exit messaging. */
type ReceiptVerifyStage = "parse" | "signature" | "inclusion" | "binding";

type ReceiptVerifyResult = {
  ok: boolean;
  stage: ReceiptVerifyStage;
  /** Present when ok === false; stable snake_case token for tests. */
  reason?: string;
};

type ParsedReceipt = {
  explicitPeak: Uint8Array | null;
  proof: Proof; // @canopy/merklelog Proof { path, mmrIndex, leafIndex? }
  receiptCbor: Uint8Array;
};
```

#### 4.2 Core exports

| Function | Purpose |
|----------|---------|
| `parseReceipt(receiptCbor)` | Parse COSE Sign1 (+ optional CBOR tag 18); extract header **396** MMRIVER proof; throw or return `stage: "parse"` on failure |
| `decodeTrustRootFromGenesis(genesisCbor)` | Decode forest genesis document to ES256 / KS256 verify keys (genesis-only) |
| `verifyGrantReceiptOffline(input)` | Layers A–C for grant receipts |
| `verifyStatementReceiptOffline(input)` | Layers A–C for statement entry receipts (**phase 3** — contract defined here; implementation follows grant package) |

#### 4.3 Grant verify input

```typescript
type VerifyGrantReceiptOfflineInput = {
  /** Forest genesis document CBOR (forests/…/genesis.cbor shape). */
  genesisCbor: Uint8Array;
  /** Full receipt COSE Sign1 CBOR bytes. */
  receiptCbor: Uint8Array;
  /** Parsed Forestrie-Grant (register-grant body). */
  grant: Grant;
  /** 8-byte big-endian Snowflake idtimestamp for the grant leaf. */
  idtimestampBe8: Uint8Array;
  /** Optional BYOK: delegation cert COSE in receipt unprotected header 1000. */
  delegationCertCbor?: Uint8Array;
};
```

**Leaf binding (layer C):**

```text
inner = grantCommitmentHash(grant)
leaf  = SHA-256(idtimestampBe8 || inner)
```

Matches [leaf-commitment.ts](https://github.com/forestrie/canopy/blob/main/packages/apps/canopy-api/src/grant/leaf-commitment.ts)
and ADR-0030.

#### 4.4 Statement verify input (phase 3)

```typescript
type VerifyStatementReceiptOfflineInput = {
  genesisCbor: Uint8Array;
  receiptCbor: Uint8Array;
  /** Raw register-entry COSE Sign1 bytes (statement). */
  statementSign1: Uint8Array;
  /** 8-byte big-endian idtimestamp assigned at sequencing. */
  idtimestampBe8: Uint8Array;
  /** Optional: SCRAPI entry id hex (content hash) for cross-check only. */
  entryIdHex?: string;
};
```

**Leaf binding (layer C) — intended rule:**

```text
contentHash = SHA-256(statementSign1)
leaf        = SHA-256(idtimestampBe8 || contentHash)
```

Enqueue path in
[register-signed-statement.ts](https://github.com/forestrie/canopy/blob/main/packages/apps/canopy-api/src/scrapi/register-signed-statement.ts)
uses `contentHash = SHA-256(statementData)` where `statementData` is the COSE
Sign1 bytes. **Open question (flag before phase 3 coding):** confirm the ranger
commit / sealer path uses the same `contentHash` and idtimestamp assignment as
canopy enqueue (sign-off from arbor owner or linked issue).

#### 4.5 Verify algorithm (grant)

Order of stages (stop at first failure):

1. **parse** — `parseReceipt(receiptCbor)`; valid COSE Sign1, header 396, path
   elements 32 bytes.
2. **binding** — compute grant leaf hash; derive peak from proof when payload
   detached (nil COSE payload).
3. **signature** — verify COSE Sign1 with `detachedPayload = peak` first; if
   receipt carries explicit 32-byte payload, fall back to embedded peak verify.
   Keys: ES256 from `decodeTrustRootFromGenesis` (+ delegated ES256 from cert
   when BYOK extension supplies header 1000).
4. **inclusion** — `@canopy/merklelog` `verifyInclusion(leaf, proof, peak)`.

**Detached-peak regression (required behaviour):** when COSE payload is nil and
signature fails, verify **must not** report tautological inclusion-ok (peak was
derived from leaf + proof). Preserve
[receipt-verify.ts L304–318](https://github.com/forestrie/canopy/blob/main/packages/apps/canopy-api/src/grant/receipt-verify.ts)
semantics: return `stage: "signature"`, not `"inclusion"` with `ok: true`.

On success: `{ ok: true, stage: "binding" }` (final stage reached).

### 5. Negative-control requirements

Each control **must** fail with an identifiable `stage` and stable `reason`:

| Control | Expected stage | Example `reason` | Future test name (T0) |
|---------|------------------|------------------|------------------------|
| Tampered receipt byte | `parse` or `signature` | `receipt_malformed` / `signature_invalid` | `rejects_tampered_receipt` |
| Wrong genesis trust key | `signature` | `signature_invalid` | `rejects_wrong_genesis_key` |
| Wrong idtimestamp | `inclusion` or `binding` | `inclusion_failed` | `rejects_wrong_idtimestamp` |
| Truncated / missing header 396 | `parse` | `missing_inclusion_proof` | `rejects_truncated_proof_396` |
| Wrong grant commitment | `binding` or `inclusion` | `inclusion_failed` | `rejects_wrong_grant_commitment` |
| Detached peak + bad signature | `signature` (not inclusion-ok) | `signature_invalid` | `detached_peak_sig_failure_not_inclusion_ok` |

### 6. Consumer semver: `@forestrie/canopy-e2e-kit` 0.4.0

**0.4.0** is the **offline verify slice**:

- depends on workspace `@forestrie/receipt-verify`;
- re-exports `verifyGrantReceiptOffline` (and later `verifyStatementReceiptOffline`);
- the estate's integration test suite lane manifests pin **exact**
  `canopy-e2e-kit-v0.4.0` (or later)
  when offline grant T3 specs are enabled (ADR-0041 (private, cited by name)).

Prior kit versions do not guarantee offline verify exports.

### 7. CLI contract (tracer)

`canopy/scripts/verify-grant-receipt` (implementation in Grant receipt project):

```text
verify-grant-receipt --genesis PATH --receipt PATH \
  (--grant-b64 B64 | --grant PATH) --idtimestamp-be8 PATH
```

Exit **0** on `{ ok: true }`, **1** otherwise; stderr prints `stage` and
`reason`. No network.

## Consequences

- One implementation per artifact ([canopy plan-0003](https://github.com/forestrie/canopy/blob/main/docs/plans/plan-0003-encoding-redux.md)):
  extract from api → package → kit + CLI.
- T3 lane B promotion will require at least one offline grant receipt spec
  (ARC-0025,
  ops-0015 (private, cited by name)).
- Statement and BYOK surfaces implement against this contract without changing
  layer A–C definitions.

## References

- [COSE receipts MMR profile](https://robinbryce.github.io/draft-bryce-cose-receipts-mmr-profile/draft-bryce-cose-receipts-mmr-profile.html)
- [scitt-hackathon step 7](https://github.com/forestrie/canopy/blob/main/docs/demo/scitt-hackathon.md)
- the decentralised FAQ (layers A–C vs D)
