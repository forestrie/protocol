# Checkpoint receipt vectors (KAT-39)

**File:** [`fixtures/checkpoint-receipt-kat39.json`](./fixtures/checkpoint-receipt-kat39.json),
pinned in [`SHA256SUMS`](./SHA256SUMS).
**Generator:** `scripts/gen_checkpoint_receipt_kat39.py` in the Python
reference, [robinbryce/merkle-mountain-range-proofs](https://github.com/robinbryce/merkle-mountain-range-proofs)
(the reference is the arbiter; the generator asserts its tree equals
go-merklelog's literal KAT tables before emitting).
**Decision:** [ADR-0066](../decisions/adr-0066-sec-signed-checkpoint-size.md)
(signed `tree-size-2`, verification MUSTs D5, receipt encoding conformance
D9); [checkpoints-and-receipts.md](../spec/checkpoints-and-receipts.md)
§1.3.

Every implementation of checkpoint verification (Go, Solidity, TypeScript)
consumes this file unchanged and must agree with every row. A row an
implementation cannot pass is a defect in that implementation or a defect in
the rule, never a reason to edit the row locally.

## The tree

The canonical 39-node MMR: 21 leaves at MMR indices
`0,1,3,4,7,8,10,11,15,16,18,19,22,23,25,26,31,32,34,35,38`, leaf value
`sha256(BE8(mmr_index))`, interior value `sha256(BE8(pos) || left || right)`
with `pos = mmr_index + 1`. `tree.nodes_hex` lists all 39 nodes in index
order; `tree.accumulators` gives the peak indices and values of each of the
21 complete sizes, keyed by **size** (node count). Sizes, not last indices,
are the primary key throughout the file; `complete_mmr_indices` gives the
mapping once.

## Sections

| Section | Rows | What a consumer does |
|---|---|---|
| `consistency_pairs` | 231: every ordered pair of complete sizes (210) plus the 21 pairs from the empty origin | run the size-driven fold on `(tree_size_1, tree_size_2, accumulator_from, paths)`; expect `roots_hex`, `right_peak_count`; `roots + right_peaks` must equal `accumulator_to_hex` and the tree's accumulator for `tree_size_2` |
| `consistency_negatives` | 8 | the fold, or the check around it, must reject; `expect.class` names the reason (below). `base_mismatch` carries `trusted_tree_size_1`, the verifier's own origin, which the proof's `tree_size_1` does not match |
| `protected_headers` | 52 | decode the protected-header map bytes with a D9-conformant decoder and read `tree-size-2`: `accept` with the given size, `absent` (well-formed, label missing), or `reject` with `expect.reason` (below) |
| `keys` | 2 | fixed test keys: ES256 private scalar `c1f1…f1`, KS256 private key = Anvil account 0 (`0xf39F…2266`) |
| `receipts` | 10 | five pairs under both algorithms: rebuild the detached payload from the tree, the `Sig_structure`, the digest; verify `signature_hex` under the key; decode `receipt_cbor_hex` and verify it end to end from the trusted origin `(tree_size_1, accumulator)` |
| `receipt_negatives` | 5 | must reject: signed size ≠ declared, the signed-size replay (genuine 7→8 receipt with the proof re-declared 7→10; the fold accepts either target, only the signed size distinguishes them), signed size absent, payload hashed instead of raw, ES256 high-s |
| `receipt_chains` | 3 | receipts that relay several sealed steps under one signature (ADR-0066 D2): fold `consistency_proofs_hex` in order from `trusted_tree_size_1`; `expect.result: accept` gives the `tree_size_2` the fold and the signed header must both reach, `reject` gives `expect.reason` (below) |

Reason and class enums are strings so every language can map them to its
own error type:

- `consistency_negatives.expect.class`: `size_must_increase`,
  `incomplete_tree_size`, `peak_count_mismatch`, `path_length_mismatch`,
  `root_mismatch`, `right_peak_count_mismatch`, `base_mismatch`.
- `protected_headers.expect.reason`: `shortest_form`, `key_order`,
  `duplicate_key`, `trailing_bytes`, `truncated`, `key_beyond_int64`,
  `non_integer_key`, `excluded_value_type`, `tag`, `invalid_utf8`,
  `size_not_uint`, `indefinite_length`, `malformed`.
- `receipt_negatives.expect.reason`: `signed_size_mismatch`,
  `signed_size_missing`, `signature_invalid`, `signature_malleable`.
- `receipt_chains.expect.reason`: `chain_not_contiguous` (a step's declared
  `tree_size_1` does not equal the previous step's `tree_size_2`, or the
  first step's does not equal `trusted_tree_size_1`), `signed_size_mismatch`
  (the protected header's `tree-size-2` is not the *last* step's; the row
  under this name folds correctly to size 7 but signs the intermediate size
  4).

## `receipt_chains` fields

Each row relays several sealed steps under one signature (ADR-0066 D2): a
receipt whose `vdp` (396) map carries more than one `consistency-proof`
under key `-2`, folded in order from a trusted origin to the size the
protected header signs.

| Field | Meaning |
|---|---|
| `steps` | the chain, in fold order: each entry is `{tree_size_1, tree_size_2}` for one sealed step; consecutive entries share a boundary size |
| `trusted_tree_size_1` | the origin size a verifier is assumed to already trust; MUST equal `steps[0].tree_size_1` for the row to fold |
| `consistency_proofs_hex` | one `consistency_proof` bstr per step, same order as `steps`, exactly as carried under `vdp` key `-2` |
| `protected_header_hex`, `receipt_cbor_hex` | as in `receipts`, but the receipt's `-2` value is the `consistency-proofs` array (below), not a bare bstr |
| `expect` | `{result: "accept", tree_size_2}` — fold every step from `trusted_tree_size_1` and check the result against the tree's accumulator for `tree_size_2`, which the signature also covers — or `{result: "reject", reason}` (above) |

## Byte conventions (all pinned by the `receipts` and `receipt_chains` rows)

| Item | Bytes |
|---|---|
| Protected header | deterministic CBOR map `{1: alg, 395: 3, -65933: tree_size_2}`; keys ordered shorter encoding first, then bytewise: `01`, `19 018b`, `3a 0001018c`. ES256 at size 8: `a3012619018b033a0001018c08`; KS256: `a3013a0001010619018b033a0001018c08` |
| Detached payload | the accumulator peaks of `tree_size_2`, descending height, concatenated raw; no CBOR, no length prefixes, not hashed |
| `Sig_structure` | CBOR `["Signature1", bstr(protected), bstr(h''), bstr(payload)]` = `84 6a "Signature1" 58xx… 40 58xx…` |
| ES256 | P-256 ECDSA over `sha256(Sig_structure)`; signature `r ‖ s`, 64 bytes, `s ≤ n/2` (high-s rejected) |
| KS256 | secp256k1 ECDSA over `keccak256(Sig_structure)`; signature `r ‖ s ‖ v`, 65 bytes, `v ∈ {27, 28}`; the verifier recovers the address and compares (`signer_kind: eoa`; a contract signer goes through ERC-1271 instead) |
| Consistency proof | `bstr(CBOR [tree_size_1, tree_size_2, [[bstr node…]…], [bstr right peak…]])`; an origin peak's empty path is the empty array `80`, never CBOR `null` (`f6`) — ADR-0066 D9 |
| `vdp` (396) value under key `-2` | `consistency-proofs = [ + consistency-proof ]`: an array of one or more proof bstrs, one per relayed step, in fold order, the signed `tree-size-2` (label `-65933`) being the last proof's. A producer now always writes this array, even for a single step; the `receipts` and `receipt_negatives` rows still pin the bare `bstr(consistency_proof)` form (no array wrapper) that every checkpoint sealed before the array form carries, and every verifier still decodes it, as the one-step case |
| Receipt | CBOR tag 18 `[bstr(protected), {396: {-2: consistency_proofs}}, null, bstr(signature)]`, where `consistency_proofs` is either wire form above |

## Header-class notes

Rows are named `class/detail` and the names are stable across languages.
The two `two-unread-labels-*` rows pin the key-order rule that every
verifier already shares: shorter encoding first, then bytewise. Keys `-1`
(`20`, one byte) and `24` (`18 18`, two bytes) sort `-1` first under that
rule and `24` first under plain bytewise comparison; the length-first row is
accepted, the bytewise row rejected.

The `skip/*` rows are the value types an unread label may carry under D9
(integer, byte string, valid UTF-8 text, `false`, `true`, `null`,
shortest-form float). `reject/mt7-simple-40`, `reject/mt7-undefined`, the
wider-than-needed floats, containers, tags, invalid UTF-8 and text-string
keys are the types D9 excludes so that the three verifiers agree.

## Regenerating

```
python3 scripts/gen_checkpoint_receipt_kat39.py \
  --go-kat ../go-merklelog/mmr/draft_kat39_test.go \
  > vectors/fixtures/checkpoint-receipt-kat39.json
sha256sum vectors/fixtures/checkpoint-receipt-kat39.json vectors/checkpoint-receipt-format.md
```

Then update `SHA256SUMS` and every vendored copy (go-merklelog
`massifs/testdata/`, canopy `packages/shared/encoding/src/testdata/`,
univocity `test/fixtures/`, forestrie-cli `test/fixtures/golden/`), each of
which checks its copy's sum against this file's entry.
