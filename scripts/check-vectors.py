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
- delegate-key-voucher.json: for each voucher (claim 4 set, absent, and an
  explicit 0), re-encode the claims map and require byte identity with
  payload_hex and with the voucher's payload, verify the ES256 signature
  against the registrar key (and the key against its test scalar), and check
  each case: claim 4 present means expired when now >= not_after, absent
  means not_after_missing only when required.
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


def cbor_tstr(s: str) -> bytes:
    b = s.encode("utf-8")
    return bytes([0x60 | len(b)]) + b if len(b) < 24 else bytes([0x78, len(b)]) + b


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


# NIST P-256, for the voucher's ES256 signature (stdlib only, verify only).
P256_P = 2**256 - 2**224 + 2**192 + 2**96 - 1
P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
P256_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
P256_G = (
    0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
)


def p256_add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and (a[1] + b[1]) % P256_P == 0:
        return None
    if a == b:
        m = (3 * a[0] * a[0] - 3) * pow(2 * a[1], -1, P256_P)
    else:
        m = (b[1] - a[1]) * pow(b[0] - a[0], -1, P256_P)
    x = (m * m - a[0] - b[0]) % P256_P
    return x, (m * (a[0] - x) - a[1]) % P256_P


def p256_mul(k: int, pt):
    out = None
    while k:
        if k & 1:
            out = p256_add(out, pt)
        pt = p256_add(pt, pt)
        k >>= 1
    return out


def es256_verify(pub, msg: bytes, sig: bytes) -> bool:
    if len(sig) != 64:
        return False
    r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
    if not (0 < r < P256_N and 0 < s < P256_N):
        return False
    if (pub[1] ** 2 - pub[0] ** 3 + 3 * pub[0] - P256_B) % P256_P:
        return False
    e = int.from_bytes(hashlib.sha256(msg).digest(), "big")
    w = pow(s, -1, P256_N)
    pt = p256_add(p256_mul(e * w % P256_N, P256_G), p256_mul(r * w % P256_N, pub))
    return pt is not None and pt[0] % P256_N == r


def cose_sign1_parts(data: bytes):
    """Split an untagged COSE_Sign1 into (protected, payload, signature)."""
    c = Cbor(data)
    major, count = c.head()
    if major != 4 or count != 4:
        raise ValueError("not a 4-element array")
    parts = []
    for i in range(4):
        major, n = c.head()
        if i == 1:
            if major != 5:
                raise ValueError("unprotected header is not a map")
            if n:
                raise ValueError("unprotected header must be empty")
            continue
        if major != 2:
            raise ValueError(f"element {i} is not a bstr")
        parts.append(c.data[c.off:c.off + n])
        c.off += n
    if c.off != len(data):
        raise ValueError("trailing bytes")
    return parts


def check_voucher_vector() -> int:
    name = "delegate-key-voucher.json"
    v = load(name)
    bad = 0
    xy = bytes.fromhex(v["registrar"]["public_key_xy_hex"])
    pub = (int.from_bytes(xy[:32], "big"), int.from_bytes(xy[32:], "big"))
    if p256_mul(int(v["registrar"]["private_key_d_hex"], 16), P256_G) != pub:
        print(f"{name}: registrar public key is not d*G")
        bad += 1
    shapes = set()
    for entry in v["vouchers"]:
        where = f"{name}: {entry['name']!r}"
        claims = entry["claims"]
        not_after = claims.get("not_after")
        shapes.add("absent" if not_after is None else "zero" if not_after == 0 else "set")
        fields = [
            cbor_uint(1) + cbor_tstr(claims["sealer_id"]),
            cbor_uint(2) + cbor_uint(claims["epoch"]),
            cbor_uint(3) + cbor_bstr(bytes.fromhex(claims["public_key_cose_hex"])),
        ]
        if not_after is not None:
            fields.append(cbor_uint(4) + cbor_uint(not_after))
        payload = bytes([0xA0 | len(fields)]) + b"".join(fields)
        if payload.hex() != entry["payload_hex"]:
            print(f"{where}: claims re-encode to {payload.hex()}, payload_hex is {entry['payload_hex']}")
            bad += 1
        try:
            protected, signed_payload, sig = cose_sign1_parts(bytes.fromhex(entry["voucher_hex"]))
        except (ValueError, IndexError) as e:
            print(f"{where}: voucher_hex is not an untagged COSE_Sign1: {e}")
            bad += 1
            continue
        if signed_payload != payload:
            print(f"{where}: the voucher does not sign payload_hex")
            bad += 1
        sig_structure = (
            bytes([0x84]) + cbor_tstr("Signature1") + cbor_bstr(protected) + cbor_bstr(b"") + cbor_bstr(signed_payload)
        )
        if not es256_verify(pub, sig_structure, sig):
            print(f"{where}: ES256 signature does not verify against the registrar key")
            bad += 1
        for case in entry["cases"]:
            # Claim 4, when present (even 0), is checked against now; its
            # absence fails only when it is required.
            if not_after is None:
                want = "not_after_missing" if case["require_not_after"] else "ok"
            else:
                want = "expired" if case["now"] >= not_after else "ok"
            if case["result"] != want:
                print(f"{where}: case {case['name']!r}: result {case['result']!r}, expected {want!r}")
                bad += 1
    if shapes != {"set", "absent", "zero"}:
        print(f"{name}: needs a voucher with claim 4 set, one without it and one with 4: 0; has {sorted(shapes)}")
        bad += 1
    return bad


def main() -> int:
    bad = check_leaf_vectors() + check_grant_vectors() + check_voucher_vector()
    if os.path.exists(os.path.join(FIXTURES, "grant_vectors_negative.json")):
        bad += check_negative_vectors()
    else:
        print("grant_vectors_negative.json: missing")
        bad += 1
    print(f"{'FAIL' if bad else 'OK'}: {bad} problem(s) in vectors/fixtures")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
