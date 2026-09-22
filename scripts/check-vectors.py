#!/usr/bin/env python3
"""Recompute every cross-language fixture under vectors/fixtures/ from its input fields.

Standard library only, so the check does not depend on any Forestrie implementation:

- leaf_vectors.json: recompute expected_inner_hex and expected_leaf_hex from the
  grant fields (spec/log-authority-and-grants.md section 4).
- grant_vectors.json: re-encode the response-form CBOR map (keys 0-6) from the
  fields and require byte identity with expected_cbor_hex
  (spec/log-authority-and-grants.md section 2.1). Any entry carrying the
  retired fields signer_hex or kind, or any encoded map with a key outside
  0-6, fails.
- grant_vectors_negative.json: every entry must decode to a map containing at
  least one of the keys it names as obsolete, so a conforming decoder rejects it.
"""
import hashlib
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURES = os.path.join(ROOT, "vectors", "fixtures")

WIRE_KEYS = (0, 1, 2, 3, 4, 5, 6)
RETIRED_FIELDS = ("signer_hex", "kind")


def u64_be(n: int) -> bytes:
    return n.to_bytes(8, "big")


def pad_left(b: bytes, size: int) -> bytes:
    if len(b) > size:
        raise ValueError(f"field of {len(b)} bytes exceeds {size}")
    return b"\x00" * (size - len(b)) + b


def pad_grant32(flags: bytes) -> bytes:
    out = bytearray(32)
    if len(flags) >= 8:
        out[24:32] = flags[-8:]
    elif flags:
        out[32 - len(flags):] = flags
    return bytes(out)


def inner_preimage(v: dict) -> bytes:
    return (
        pad_left(bytes.fromhex(v["log_id_hex"]), 32)
        + pad_grant32(bytes.fromhex(v["grant_flags_hex"]))
        + u64_be(v["max_height"])
        + u64_be(v["min_growth"])
        + pad_left(bytes.fromhex(v["owner_log_id_hex"]), 32)
        + bytes.fromhex(v["grant_data_hex"])
    )


def cbor_uint(v: int) -> bytes:
    if v < 24:
        return bytes([v])
    if v <= 0xFF:
        return bytes([0x18, v])
    if v <= 0xFFFF:
        return b"\x19" + v.to_bytes(2, "big")
    if v <= 0xFFFFFFFF:
        return b"\x1a" + v.to_bytes(4, "big")
    return b"\x1b" + v.to_bytes(8, "big")


def cbor_bstr(s: bytes) -> bytes:
    n = len(s)
    if n < 24:
        head = bytes([0x40 | n])
    elif n <= 0xFF:
        head = bytes([0x58, n])
    elif n <= 0xFFFF:
        head = b"\x59" + n.to_bytes(2, "big")
    else:
        head = b"\x5a" + n.to_bytes(4, "big")
    return head + s


def encode_grant_response(v: dict) -> bytes:
    """The response-form grant map: keys 0-6, Core Deterministic Encoding."""
    items = [
        (0, cbor_bstr(pad_left(bytes.fromhex(v["idtimestamp_hex"]), 8))),
        (1, cbor_bstr(pad_left(bytes.fromhex(v["log_id_hex"]), 32))),
        (2, cbor_bstr(pad_left(bytes.fromhex(v["owner_log_id_hex"]), 32))),
        (3, cbor_bstr(pad_left(bytes.fromhex(v["grant_flags_hex"]), 8))),
        (4, cbor_uint(v["max_height"])),
        (5, cbor_uint(v["min_growth"])),
        (6, cbor_bstr(bytes.fromhex(v["grant_data_hex"]))),
    ]
    out = bytearray([0xA0 | len(items)])
    for k, enc in items:
        out += cbor_uint(k) + enc
    return bytes(out)


class Cbor:
    """Just enough CBOR to walk a map of (uint -> uint | bstr)."""

    def __init__(self, data: bytes):
        self.data, self.off = data, 0

    def head(self):
        b = self.data[self.off]
        self.off += 1
        major, aux = b >> 5, b & 0x1F
        if aux < 24:
            return major, aux
        width = {24: 1, 25: 2, 26: 4, 27: 8}[aux]
        val = int.from_bytes(self.data[self.off:self.off + width], "big")
        self.off += width
        return major, val

    def map_keys(self):
        major, count = self.head()
        if major != 5:
            raise ValueError(f"expected a map, got major type {major}")
        keys = []
        for _ in range(count):
            kmajor, key = self.head()
            if kmajor != 0:
                raise ValueError("map keys must be unsigned integers")
            keys.append(key)
            vmajor, val = self.head()
            if vmajor == 2:
                self.off += val
            elif vmajor != 0:
                raise ValueError(f"unsupported value major type {vmajor}")
        if self.off != len(self.data):
            raise ValueError("trailing bytes")
        return keys


def load(name):
    with open(os.path.join(FIXTURES, name), encoding="utf-8") as f:
        return json.load(f)


def check_leaf_vectors() -> int:
    bad = 0
    for v in load("leaf_vectors.json"):
        inner = hashlib.sha256(inner_preimage(v)).digest()
        leaf = hashlib.sha256(pad_left(bytes.fromhex(v["idtimestamp_hex"]), 8) + inner).digest()
        for field, got in (("expected_inner_hex", inner.hex()), ("expected_leaf_hex", leaf.hex())):
            if v[field] != got:
                print(f"leaf_vectors.json: {v['description']!r}: {field} is {v[field]}, recomputed {got}")
                bad += 1
    return bad


def check_grant_vectors() -> int:
    bad = 0
    for v in load("grant_vectors.json"):
        for field in RETIRED_FIELDS:
            if field in v:
                print(f"grant_vectors.json: {v['description']!r}: retired field {field!r} present")
                bad += 1
        expected = bytes.fromhex(v["expected_cbor_hex"])
        try:
            keys = Cbor(expected).map_keys()
        except (ValueError, KeyError, IndexError) as e:
            print(f"grant_vectors.json: {v['description']!r}: expected_cbor_hex is not a grant map: {e}")
            bad += 1
            continue
        if tuple(keys) != WIRE_KEYS:
            print(f"grant_vectors.json: {v['description']!r}: map keys {keys}, want {list(WIRE_KEYS)}")
            bad += 1
        recomputed = encode_grant_response(v)
        if recomputed != expected:
            print(f"grant_vectors.json: {v['description']!r}: re-encoding differs\n  got  {recomputed.hex()}\n  want {expected.hex()}")
            bad += 1
    return bad


def check_negative_vectors() -> int:
    bad = 0
    for v in load("grant_vectors_negative.json"):
        if v.get("must_reject") is not True:
            print(f"grant_vectors_negative.json: {v['description']!r}: must_reject is not true")
            bad += 1
        obsolete = set(v.get("obsolete_keys", []))
        try:
            keys = set(Cbor(bytes.fromhex(v["cbor_hex"])).map_keys())
        except (ValueError, KeyError, IndexError) as e:
            print(f"grant_vectors_negative.json: {v['description']!r}: cbor_hex is not a map: {e}")
            bad += 1
            continue
        if not (keys & obsolete):
            print(f"grant_vectors_negative.json: {v['description']!r}: none of the obsolete keys {sorted(obsolete)} present in {sorted(keys)}")
            bad += 1
        if keys <= set(WIRE_KEYS):
            print(f"grant_vectors_negative.json: {v['description']!r}: keys {sorted(keys)} are all valid; a conforming decoder would accept it")
            bad += 1
    return bad


def main() -> int:
    bad = check_leaf_vectors() + check_grant_vectors()
    if os.path.exists(os.path.join(FIXTURES, "grant_vectors_negative.json")):
        bad += check_negative_vectors()
    else:
        print("grant_vectors_negative.json: missing")
        bad += 1
    print(f"{'FAIL' if bad else 'OK'}: {bad} problem(s) in vectors/fixtures")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
