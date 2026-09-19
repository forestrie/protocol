# Grant and leaf format

A worked guide to the **leaf commitment** and the **grant** wire format, with
code in Go, TypeScript and Python that reproduces the fixtures under
[`fixtures/`](README.md). The normative definitions are in
[log authority and grants](../spec/log-authority-and-grants.md): §2.1 for the
wire map and §4 for the commitment. Where this guide and that document
differ, that document is right.

**Implementations**: univocity `LibLogState.sol` (`_leafCommitment`), `LibLeafEncoding.sol` (`innerPreimage`, `leafCommitment`), `src/interfaces/types.sol` (`PublishGrant`); canopy [grant codec](https://github.com/forestrie/canopy/blob/main/packages/shared/encoding/src/grant-codec.ts); go-univocity [`grant/cborcodec.go`](https://github.com/forestrie/go-univocity/blob/main/grant/cborcodec.go).

---

## 1. Leaf commitment (hashing)

The authority log leaf is the 32-byte SHA-256 output of:

```
leafCommitment = sha256( grantIDTimestampBe || sha256( inner ) )
inner          = logId(32) || grant(32) || maxHeight_be(8) || minGrowth_be(8) || ownerLogId(32) || grantData
```

Fixed-length fields match Solidity `PublishGrant` and `abi.encodePacked`: **logId** and **ownerLogId** are 32 bytes (bytes32); **grant** is 32 bytes (uint256). Off-chain we typically have 16-byte log IDs and 8-byte grant flags; they are **padded** for the inner preimage:

- **grantIDTimestampBe**: 8 bytes, big-endian uint64 (unique grant timestamp / idtimestamp).
- **logId**: 32 bytes in inner preimage. 16-byte UUID is **left-padded** to 32 (leading zeros; value in least-significant bytes).
- **grant**: 32 bytes in inner preimage. 8-byte grant flags go in the **low 8 bytes** (big-endian); high 24 bytes zero.
- **maxHeight**: 8 bytes, big-endian uint64 (0 = no limit).
- **minGrowth**: 8 bytes, big-endian uint64.
- **ownerLogId**: 32 bytes in inner preimage. 16-byte UUID is **left-padded** to 32.
- **grantData**: variable length (opaque; e.g. signer key for first checkpoint).

Concatenation is **without length prefixes** (Solidity `abi.encodePacked` style). Left-padding is used so that the original bytes occupy the least-significant (right) positions, consistent with big-endian layout for fixed-size fields. The **request** (GC_AUTH_LOG / GC_DATA_LOG) is **not** in the leaf; it is supplied at `publishCheckpoint` time.

**Grant sequencing.** When enqueueing a grant for sequencing, the value used as **ContentHash** (fed to the DO and to ranger) is the **inner hash** = `sha256(inner preimage)`. Idtimestamp is **not** included; ranger assigns it and computes `leafHash = H(idTimestampBE || ContentHash)`. So implementations must expose or compute the 32-byte inner hash for the grant-sequencing path (e.g. go-univocity `InnerHash` / `InnerHashFromGrant`).

---

## 2. Grant fields

Stored grant fields (canopy and arbor use 16-byte log IDs and 8-byte grant flags). For the **leaf inner preimage**, they are encoded with fixed sizes to match Solidity (see §1):

| Field          | Stored / API  | In inner preimage     | Notes                          |
|----------------|---------------|------------------------|---------------------------------|
| idtimestamp    | 8 bytes, BE   | (outer only)           | Unique grant timestamp         |
| logId          | 16 bytes      | 32 bytes (left-pad)   | Target log                      |
| grantFlags     | 8 bytes       | 32 bytes (low 8)       | GF_* bitmap                     |
| maxHeight      | 8 bytes, BE   | 8 bytes, BE            | Optional bound (0 = none)       |
| minGrowth      | 8 bytes, BE   | 8 bytes, BE            | Min growth per checkpoint       |
| ownerLogId     | 16 bytes      | 32 bytes (left-pad)   | Owner (authority) log           |
| grantData      | variable      | variable                | Opaque (e.g. signer key)        |

These seven fields are the whole grant. `grantData` is the sole statement-signer binding; there is no separate signer or kind field on the wire or in the commitment.

---

## 3. Encoding / decoding examples

### 3.1 Go

```go
package main

import (
	"encoding/hex"
	"fmt"
	"github.com/forestrie/go-univocity/grant"
)

func main() {
	idTs := [8]byte{0, 0, 0, 0, 0, 0, 0, 1}
	logId, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	flags, _ := hex.DecodeString("0000000000000001")
	ownerLogId, _ := hex.DecodeString("101112131415161718191a1b1c1d1e1f")
	grantData, _ := hex.DecodeString("abcd")

	leaf := grant.LeafCommitment(idTs, logId, flags, 1000, 1, ownerLogId, grantData)
	fmt.Println(hex.EncodeToString(leaf[:]))
	// 0bc4a0d26f57d59ca4dc604865be4c49a6221f1cbe65840e95e9905d02b30ea0
}
```

Decode from hex and compute leaf (same formula):

```go
	idTsHex := "0000000000000001"
	logIdHex := "000102030405060708090a0b0c0d0e0f"
	// ... decode each with hex.DecodeString, then:
	var idTsArr [8]byte
	copy(idTsArr[:], idTs)
	leaf := grant.LeafCommitment(idTsArr, logId, flags, maxHeight, minGrowth, ownerLogId, grantData)
```

### 3.2 TypeScript

```typescript
import { createHash } from "crypto";

const INNER_LOG_ID_BYTES = 32;
const INNER_GRANT_BYTES = 32;

function u64Be(n: number): Buffer {
  const b = Buffer.alloc(8);
  b.writeBigUInt64BE(BigInt(n));
  return b;
}

function padLeft(b: Buffer, limit: number): Buffer {
  if (b.length >= limit) return b.length === limit ? b : b.subarray(0, limit);
  const out = Buffer.alloc(limit);
  b.copy(out, limit - b.length);
  return out;
}

function padGrant32(flags: Buffer): Buffer {
  const out = Buffer.alloc(32);
  if (flags.length >= 8) flags.subarray(-8).copy(out, 24);
  else if (flags.length > 0) flags.copy(out, 32 - flags.length);
  return out;
}

function leafCommitment(
  grantIDTimestampBe: Buffer,
  logId: Buffer,
  grantFlags: Buffer,
  maxHeight: number,
  minGrowth: number,
  ownerLogId: Buffer,
  grantData: Buffer
): Buffer {
  const inner = Buffer.concat([
    padLeft(logId, 32),
    padGrant32(grantFlags),
    u64Be(maxHeight),
    u64Be(minGrowth),
    padLeft(ownerLogId, 32),
    grantData,
  ]);
  const innerHash = createHash("sha256").update(inner).digest();
  return createHash("sha256")
    .update(Buffer.concat([grantIDTimestampBe, innerHash]))
    .digest();
}

const idTs = Buffer.from("0000000000000001", "hex");
const logId = Buffer.from("000102030405060708090a0b0c0d0e0f", "hex");
const flags = Buffer.from("0000000000000001", "hex");
const ownerLogId = Buffer.from("101112131415161718191a1b1c1d1e1f", "hex");
const grantData = Buffer.from("abcd", "hex");
const leaf = leafCommitment(idTs, logId, flags, 1000, 1, ownerLogId, grantData);
console.log(leaf.toString("hex"));
// 0bc4a0d26f57d59ca4dc604865be4c49a6221f1cbe65840e95e9905d02b30ea0
```

### 3.3 Python

```python
import hashlib

INNER_LOG_ID_BYTES = 32
INNER_GRANT_BYTES = 32

def u64_be(n: int) -> bytes:
    return n.to_bytes(8, "big")

def pad_left(b: bytes, limit: int) -> bytes:
    if len(b) >= limit:
        return b[:limit] if len(b) > limit else b
    return b"\x00" * (limit - len(b)) + b

def pad_grant32(flags: bytes) -> bytes:
    out = bytearray(32)
    if len(flags) >= 8:
        out[24:32] = flags[-8:]
    elif len(flags) > 0:
        out[32 - len(flags) : 32] = flags
    return bytes(out)

def leaf_commitment(
    grant_id_timestamp_be: bytes,
    log_id: bytes,
    grant_flags: bytes,
    max_height: int,
    min_growth: int,
    owner_log_id: bytes,
    grant_data: bytes,
) -> bytes:
    inner = (
        pad_left(log_id, 32)
        + pad_grant32(grant_flags)
        + u64_be(max_height)
        + u64_be(min_growth)
        + pad_left(owner_log_id, 32)
        + grant_data
    )
    inner_hash = hashlib.sha256(inner).digest()
    return hashlib.sha256(grant_id_timestamp_be + inner_hash).digest()

id_ts = bytes.fromhex("0000000000000001")
log_id = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
flags = bytes.fromhex("0000000000000001")
owner_log_id = bytes.fromhex("101112131415161718191a1b1c1d1e1f")
grant_data = bytes.fromhex("abcd")
leaf = leaf_commitment(id_ts, log_id, flags, 1000, 1, owner_log_id, grant_data)
print(leaf.hex())
# 0bc4a0d26f57d59ca4dc604865be4c49a6221f1cbe65840e95e9905d02b30ea0
```

---

## 4. Test vectors

The fixtures live in [`fixtures/`](fixtures/) and are described in [README.md](README.md). Each entry of `leaf_vectors.json` has hex-encoded inputs, **expected_inner_hex** (the content hash for grant sequencing), and **expected_leaf_hex**. All three languages must match these vectors; `scripts/check-vectors.py` recomputes them.

Example (vector 1):

- idtimestamp_hex: `0000000000000001`
- log_id_hex: `000102030405060708090a0b0c0d0e0f`
- grant_flags_hex: `0000000000000001`
- max_height: 1000, min_growth: 1
- owner_log_id_hex: `101112131415161718191a1b1c1d1e1f`
- grant_data_hex: `abcd`
- expected_inner_hex: `37ba4d6d92cfac9b673379005bc24f5fd2acf08e8920782ed37c782d69aea553` (the content hash for grant sequencing)
- expected_leaf_hex: `0bc4a0d26f57d59ca4dc604865be4c49a6221f1cbe65840e95e9905d02b30ea0`

---

## 5. Alignment (canopy vs univocity)

| Canopy              | Univocity (Solidity) | In leaf inner preimage |
|--------------------|----------------------|-------------------------|
| idtimestamp (8)    | grantIDTimestampBe   | Outer only              |
| logId (16)         | logId bytes32       | Left-pad to 32          |
| grantFlags (8)     | grant uint256       | Low 8 bytes of 32       |
| maxHeight, minGrowth | maxHeight, minGrowth (uint64) | 8-byte BE each |
| ownerLogId (16)    | ownerLogId bytes32  | Left-pad to 32          |
| grantData          | grantData bytes     | Variable, no prefix     |

The Solidity `request` code (GC_AUTH_LOG / GC_DATA_LOG) is supplied at `publishCheckpoint` time and is neither on the wire nor in the leaf. Univocity exposes the same encoding via `LibLeafEncoding.sol` (`innerPreimage`, `leafCommitment`); padding is documented in that library.

---

## 6. CBOR wire format

Grants are serialized for storage and wire as a single CBOR (RFC 8949) map with **integer keys 0–6**, in Core Deterministic Encoding (keys ascending; preferred serialization for lengths and integers), so the same grant always produces the same bytes. The normative table is [log authority and grants §2.1](../spec/log-authority-and-grants.md#21-the-inner-grant); it is reproduced here so the examples are self-contained.

| Key | Field        | CBOR type | Wire length | Notes                          |
|-----|--------------|-----------|-------------|---------------------------------|
| 0   | IDTimestamp  | bstr      | 8           | Big-endian idtimestamp; **response form only**, absent from the signed payload |
| 1   | LogId        | bstr      | 32          | Fixed; left-padded on encode    |
| 2   | OwnerLogId   | bstr      | 32          | Fixed; left-padded on encode    |
| 3   | GrantFlags   | bstr      | 8           | Fixed; left-padded on encode    |
| 4   | MaxHeight    | unsigned  | —           | uint64                         |
| 5   | MinGrowth    | unsigned  | —           | uint64                         |
| 6   | GrantData    | bstr      | variable    | Opaque (e.g. signer key)       |

Two forms share these keys. The **payload form** (keys 1–6) is what the owner signs and what the commitment covers. The **response form** (keys 0–6) is the payload form with the assigned idtimestamp at key 0, returned once the grant is sealed; `fixtures/grant_vectors.json` carries this form.

**Keys 7 and 8 are rejected.** They once carried a `signer` and a `kind`; `grantData` is the sole signer binding, and a decoder that accepted the removed keys would reintroduce the ambiguity their removal eliminated. `fixtures/grant_vectors_negative.json` carries maps with those keys that every decoder must refuse.

Fixed lengths (32, 32, 8) guarantee that decode→LeafCommitment pad paths are no-ops and size checks always pass for wire-decoded grants.

**Go**: hand-written encoder/decoder in go-univocity `grant/cborcodec.go`, `MarshalGrant` / `UnmarshalGrant`. **TypeScript**: `encodeGrantPayload` / `decodeGrantPayload` and `encodeGrantForResponse` / `decodeGrantResponse` in `@forestrie/encoding`. Other languages should use the same key assignments and Core Deterministic Encoding so that encoded bytes are interchangeable.
