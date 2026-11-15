#!/usr/bin/env python3
"""Recompute every cross-language fixture under vectors/fixtures/ from its input fields.

Standard library only, so the check does not depend on any Forestrie implementation.
With --self-test it instead checks mutated copies of the delegated-spend
fixtures, and fails unless every mutation is caught. Without it:

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
- ks256-low-s.json: re-encode the Sig_structure and its Keccak-256 digest
  from the header and payload, recover every signature to its stated
  signer (recovery does not bound s, so a high-s twin recovers too), and
  require accept exactly when s <= (n-1)/2. Each reject case must be the
  twin (r, n-s, v^1) of an accept case, and one pair must straddle the
  bound itself (spec/checkpoints-and-receipts.md).
- erc7710-statements.json: recompute each delegation's struct hash, EIP-712
  domain and signed digest, and recover its signer; re-encode each
  statement's payload and protected header from its fields, decode it
  strictly and recover its KS256 signer; for a delegation statement check
  that key 2 is DELEGATION_TAG || the struct hash of key 5 and rebuild the
  leaf from prefix, tag, hash and suffix; for a revocation or spend
  statement require the tag absent, and for a spend paid with a payment
  nonce require the nonce over its purpose and root to be its leaf's salt;
  and run the auditor's scan and the route check on each audit case
  (spec/delegated-spend-statements.md).
- payment-nonce.json: recompute each purpose digest, canonical preimage and
  nonce from the purpose's fields and payer, require the grant purpose to be
  the payload form of its grant vector and every nonce distinct, and require
  each not_canonical preimage to be non-canonical and to hash to its salt
  (spec/payment-nonce-and-binding.md section 2).
- erc7710-leaf-salt-v1.json: decode each receipt's logs, rebuild its chains,
  find each chain's binding delegation, pair across the receipt, and require
  the expected payments, unbound transfers and request bindings, and the
  re-pay identities (spec/payment-nonce-and-binding.md section 3).
"""
import hashlib
import json
import os
import re
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


def encode_grant_payload(v: dict) -> bytes:
    """The payload form: the response form without key 0, as the grant carries at -65538."""
    response = encode_grant_response(v)
    key0 = cbor_uint(0) + cbor_bstr(pad_left(bytes.fromhex(v["idtimestamp_hex"]), 8))
    if response[1:1 + len(key0)] != key0:
        raise ValueError("the response form does not open with key 0")
    return bytes([0xA6]) + response[1 + len(key0):]


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


_MUTATED = {}  # name -> fixture; --self-test checks mutated copies, never the files


def load(name):
    if name in _MUTATED:
        return _MUTATED[name]
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


# Keccak-256 and secp256k1 recovery, for the KS256 vector (stdlib only,
# verify only). Keccak-256 pads with domain byte 0x01, so hashlib.sha3_256,
# which pads with 0x06, gives different digests.
_KECCAK_RC = (
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
)
_KECCAK_ROT = (
    (0, 36, 3, 41, 18),
    (1, 44, 10, 45, 2),
    (62, 6, 43, 15, 61),
    (28, 55, 25, 21, 56),
    (27, 20, 39, 8, 14),
)
_M64 = (1 << 64) - 1


def _rol64(v: int, n: int) -> int:
    return ((v << n) | (v >> (64 - n))) & _M64 if n else v


def _keccak_f(a):
    for rc in _KECCAK_RC:
        c = [a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rol64(c[(x + 1) % 5], 1) for x in range(5)]
        a = [[a[x][y] ^ d[x] for y in range(5)] for x in range(5)]
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = _rol64(a[x][y], _KECCAK_ROT[x][y])
        a = [[b[x][y] ^ (~b[(x + 1) % 5][y] & b[(x + 2) % 5][y]) for y in range(5)] for x in range(5)]
        a[0][0] ^= rc
    return a


def keccak256(data: bytes) -> bytes:
    rate = 136
    p = bytearray(data)
    p.append(0x01)
    while len(p) % rate:
        p.append(0)
    p[-1] |= 0x80
    a = [[0] * 5 for _ in range(5)]
    for off in range(0, len(p), rate):
        for i in range(rate // 8):
            a[i % 5][i // 5] ^= int.from_bytes(p[off + 8 * i:off + 8 * i + 8], "little")
        a = _keccak_f(a)
    return b"".join(a[i % 5][i // 5].to_bytes(8, "little") for i in range(4))


K1_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
K1_HALF_N = K1_N // 2  # (n-1)/2: the largest s a verifier accepts
K1_G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)


def k1_add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and (a[1] + b[1]) % K1_P == 0:
        return None
    if a == b:
        m = 3 * a[0] * a[0] * pow(2 * a[1], -1, K1_P)
    else:
        m = (b[1] - a[1]) * pow(b[0] - a[0], -1, K1_P)
    x = (m * m - a[0] - b[0]) % K1_P
    return x, (m * (a[0] - x) - a[1]) % K1_P


def k1_mul(k: int, pt):
    out = None
    while k:
        if k & 1:
            out = k1_add(out, pt)
        pt = k1_add(pt, pt)
        k >>= 1
    return out


def k1_address(pub) -> bytes:
    return keccak256(pub[0].to_bytes(32, "big") + pub[1].to_bytes(32, "big"))[12:]


def k1_recover_address(digest: bytes, r: int, s: int, recid: int):
    """The address (r, s, recid) is a valid signature by, or None. s is not bounded."""
    if not (0 < r < K1_N and 0 < s < K1_N and recid in (0, 1)):
        return None
    y2 = (pow(r, 3, K1_P) + 7) % K1_P
    y = pow(y2, (K1_P + 1) // 4, K1_P)
    if y * y % K1_P != y2:
        return None
    if y & 1 != recid:
        y = K1_P - y
    z = int.from_bytes(digest, "big") % K1_N
    rinv = pow(r, -1, K1_N)
    pub = k1_add(k1_mul(s * rinv % K1_N, (r, y)), k1_mul(-z * rinv % K1_N, K1_G))
    return None if pub is None else k1_address(pub)


KS256_ALG = -65799


def check_ks256_low_s_vector() -> int:
    name = "ks256-low-s.json"
    v = load(name)
    bad = 0
    protected = bytes.fromhex(v["protected_header_hex"])
    payload = bytes.fromhex(v["payload_hex"])
    if v["alg"] != KS256_ALG or protected != bytes([0xA1, 0x01, 0x3A]) + (-1 - KS256_ALG).to_bytes(4, "big"):
        print(f"{name}: protected header must be {{1: {KS256_ALG}}}")
        bad += 1
    # A verifier that decodes the payload before the signature (arbor's
    # delegation certificate check requires a canonical integer-keyed map)
    # must still reach the s check, or its reject cases pass vacuously.
    try:
        keys = Cbor(payload).map_keys()
    except (ValueError, IndexError, KeyError) as e:
        print(f"{name}: payload is not a CBOR map with unsigned integer keys: {e}")
        bad += 1
    else:
        if not keys or keys != sorted(set(keys)):
            print(f"{name}: payload map keys must be non-empty and ascending, got {keys}")
            bad += 1
    sig_structure = (
        bytes([0x84]) + cbor_tstr("Signature1") + cbor_bstr(protected) + cbor_bstr(b"") + cbor_bstr(payload)
    )
    if sig_structure.hex() != v["sig_structure_hex"]:
        print(f"{name}: Sig_structure re-encodes to {sig_structure.hex()}, sig_structure_hex is {v['sig_structure_hex']}")
        bad += 1
    digest = keccak256(sig_structure)
    if digest.hex() != v["digest_hex"]:
        print(f"{name}: keccak256(Sig_structure) is {digest.hex()}, digest_hex is {v['digest_hex']}")
        bad += 1
    if v["conventions"]["low_s_bound"] != f"{K1_HALF_N:064x}":
        print(f"{name}: conventions.low_s_bound is not (n-1)/2")
        bad += 1
    key = v["test_key"]
    d = int(key["private_key_d_hex"], 16)
    if d != int.from_bytes(keccak256(key["label"].encode()), "big") % K1_N:
        print(f"{name}: test_key scalar is not keccak256(label) mod n")
        bad += 1
    if k1_address(k1_mul(d, K1_G)).hex() != key["address_hex"]:
        print(f"{name}: test_key address is not the address of its scalar")
        bad += 1

    cases = {c["name"]: c for c in v["cases"]}
    parsed = {}
    for c in v["cases"]:
        where = f"{name}: {c['name']!r}"
        sig = bytes.fromhex(c["signature_hex"])
        if len(sig) != 65 or sig[64] not in (0, 1):
            print(f"{where}: signature must be 65 bytes r || s || v with v 0 or 1")
            bad += 1
            continue
        r, s, recid = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:64], "big"), sig[64]
        parsed[c["name"]] = (r, s, recid)
        got = k1_recover_address(digest, r, s, recid)
        if got is None or got.hex() != c["signer_address_hex"]:
            print(f"{where}: signature recovers to {got.hex() if got else None}, not {c['signer_address_hex']}")
            bad += 1
        try:
            parts = cose_sign1_parts(bytes.fromhex(c["cose_sign1_hex"]))
        except (ValueError, IndexError) as e:
            print(f"{where}: cose_sign1_hex is not an untagged COSE_Sign1: {e}")
            bad += 1
        else:
            if parts != [protected, payload, sig]:
                print(f"{where}: cose_sign1_hex does not carry the vector's header, payload and signature")
                bad += 1
        want = {"result": "accept"} if s <= K1_HALF_N else {"result": "reject", "reason": "signature_malleable"}
        if c["expect"] != want:
            print(f"{where}: expect is {c['expect']}, s {'<=' if s <= K1_HALF_N else '>'} (n-1)/2 means {want}")
            bad += 1
    if cases.get("accept/low-s", {}).get("signer_address_hex") != key["address_hex"]:
        print(f"{name}: 'accept/low-s' must be signed by test_key")
        bad += 1
    for c in v["cases"]:
        if c["expect"].get("result") != "reject":
            continue
        twin = c.get("twin_of")
        if twin not in cases or cases[twin]["expect"].get("result") != "accept":
            print(f"{name}: {c['name']!r}: twin_of must name an accept case")
            bad += 1
            continue
        if c["name"] in parsed and twin in parsed:
            (r, s, recid), (tr, ts, trecid) = parsed[c["name"]], parsed[twin]
            if (r, s, recid) != (tr, K1_N - ts, trecid ^ 1) or c["signer_address_hex"] != cases[twin]["signer_address_hex"]:
                print(f"{name}: {c['name']!r} is not (r, n-s, v^1) of {twin!r}")
                bad += 1
    twinned = {c.get("twin_of") for c in v["cases"] if c["expect"].get("result") == "reject"}
    for c in v["cases"]:
        if c["expect"].get("result") == "accept" and c["name"] not in twinned:
            print(f"{name}: {c['name']!r} has no reject case that is its high-s twin")
            bad += 1
    s_values = {s for (_, s, _) in parsed.values()}
    if not {K1_HALF_N, K1_HALF_N + 1} <= s_values:
        print(f"{name}: needs a case with s = (n-1)/2 and its twin with s = (n+1)/2")
        bad += 1
    return bad


# ERC-7710 delegated spend (spec/delegated-spend-statements.md and
# spec/delegated-payment-binding.md). The delegation hash is the
# delegation framework's EIP-712 struct hash; the signed digest wraps it
# in the delegation manager's domain.
DELEGATION_TYPEHASH = keccak256(
    b"Delegation(address delegate,address delegator,bytes32 authority,"
    b"Caveat[] caveats,uint256 salt)Caveat(address enforcer,bytes terms)"
)
CAVEAT_TYPEHASH = keccak256(b"Caveat(address enforcer,bytes terms)")
EIP712_DOMAIN_TYPEHASH = keccak256(
    b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
)
ROOT_AUTHORITY = b"\xff" * 32
ANY_DELEGATE = bytes.fromhex("0000000000000000000000000000000000000a11")
DELEGATION_TAG_LABEL = "univocity/erc7710-delegation/v1"
DELEGATION_TAG = hashlib.sha256(DELEGATION_TAG_LABEL.encode()).digest()
CONTENT_TYPES = {
    "delegation": "application/univocity.erc7710-delegation+cbor",
    "revocation": "application/univocity.erc7710-revocation+cbor",
    "spend": "application/univocity.erc7710-spend+cbor",
}


def u256(n: int) -> bytes:
    return n.to_bytes(32, "big")


def addr_word(a: bytes) -> bytes:
    if len(a) != 20:
        raise ValueError(f"an address is 20 bytes, got {len(a)}")
    return b"\x00" * 12 + a


def delegation_struct_hash(delegate, delegator, authority, caveats, salt) -> bytes:
    """EncoderLib._getDelegationHash: the struct hash, never the signed digest."""
    packets = b"".join(keccak256(CAVEAT_TYPEHASH + addr_word(e) + keccak256(t)) for e, t in caveats)
    return keccak256(
        DELEGATION_TYPEHASH + addr_word(delegate) + addr_word(delegator) + authority + keccak256(packets) + salt
    )


def eip712_domain_separator(chain_id: int, manager: bytes) -> bytes:
    return keccak256(
        EIP712_DOMAIN_TYPEHASH + keccak256(b"DelegationManager") + keccak256(b"1") + u256(chain_id) + addr_word(manager)
    )


class Span(bytes):
    """A decoded byte string that remembers where its content starts in the decoded buffer."""


def cbor_head_bytes(major: int, n: int) -> bytes:
    if n < 24:
        return bytes([major << 5 | n])
    for aux, width in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if n < 1 << (8 * width):
            return bytes([major << 5 | aux]) + n.to_bytes(width, "big")
    raise ValueError("integer too large for CBOR")


def cbor_sort_key(order: str):
    if order == "bytewise":
        return lambda enc: enc
    if order == "length-first":
        return lambda enc: (len(enc), enc)
    raise ValueError(f"unknown map key order {order!r}")


def cbor_encode(v, order: str = "bytewise") -> bytes:
    """Deterministic CBOR for ints, byte and text strings, arrays and maps."""
    if isinstance(v, bool):
        raise TypeError("booleans are not used")
    if isinstance(v, int):
        return cbor_head_bytes(0, v) if v >= 0 else cbor_head_bytes(1, -1 - v)
    if isinstance(v, (bytes, bytearray)):
        return cbor_head_bytes(2, len(v)) + bytes(v)
    if isinstance(v, str):
        b = v.encode("utf-8")
        return cbor_head_bytes(3, len(b)) + b
    if isinstance(v, list):
        return cbor_head_bytes(4, len(v)) + b"".join(cbor_encode(x, order) for x in v)
    if isinstance(v, dict):
        key = cbor_sort_key(order)
        items = sorted(((cbor_encode(k, order), cbor_encode(x, order)) for k, x in v.items()), key=lambda kv: key(kv[0]))
        return cbor_head_bytes(5, len(items)) + b"".join(k + x for k, x in items)
    raise TypeError(f"cannot encode {type(v).__name__}")


def cbor_decode(data: bytes, order: str = "bytewise"):
    """Decode one item, refusing what deterministic encoding forbids: a head longer
    than it needs, indefinite lengths, tags, floats and simple values, and map keys
    that repeat or are out of `order`. Byte strings come back as Span."""
    value, off = _cbor_item(data, 0, cbor_sort_key(order), order)
    if off != len(data):
        raise ValueError("trailing bytes")
    return value


def _cbor_item(data: bytes, off: int, key, order: str):
    if off >= len(data):
        raise ValueError("truncated")
    major, aux = data[off] >> 5, data[off] & 0x1F
    off += 1
    if aux < 24:
        n = aux
    elif aux in (24, 25, 26, 27):
        width = 1 << (aux - 24)
        if off + width > len(data):
            raise ValueError("truncated head")
        n = int.from_bytes(data[off:off + width], "big")
        off += width
        if n < (24 if width == 1 else 1 << (4 * width)):
            raise ValueError("head not in shortest form")
    else:
        raise ValueError("indefinite length or reserved head")
    if major == 0:
        return n, off
    if major == 1:
        return -1 - n, off
    if major in (2, 3):
        if off + n > len(data):
            raise ValueError("truncated string")
        raw = data[off:off + n]
        if major == 3:
            return raw.decode("utf-8"), off + n
        s = Span(raw)
        s.offset = off
        return s, off + n
    if major == 4:
        items = []
        for _ in range(n):
            item, off = _cbor_item(data, off, key, order)
            items.append(item)
        return items, off
    if major == 5:
        out, prev = {}, None
        for _ in range(n):
            start = off
            k, off = _cbor_item(data, off, key, order)
            if isinstance(k, (list, dict)):
                raise ValueError("map keys must be integers or strings")
            rank = key(data[start:off])
            if prev is not None and rank <= prev:
                raise ValueError(f"map keys repeat or are out of {order} order")
            prev = rank
            out[bytes(k) if isinstance(k, Span) else k], off = _cbor_item(data, off, key, order)
        return out, off
    raise ValueError(f"major type {major} is not used")


def is_bstr(v, size=None) -> bool:
    return isinstance(v, bytes) and (size is None or len(v) == size)


def is_uint(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and v >= 0


def parse_hop(hop):
    """The published hop: [delegate, delegator, authority, [[enforcer, terms], ...], salt, signature]."""
    if not (isinstance(hop, list) and len(hop) == 6):
        raise ValueError("the hop is a 6-element array")
    delegate, delegator, authority, caveats, salt, signature = hop
    if not (is_bstr(delegate, 20) and is_bstr(delegator, 20) and is_bstr(authority, 32) and is_bstr(salt, 32)):
        raise ValueError("hop field of the wrong type or size")
    if not (isinstance(caveats, list) and all(isinstance(c, list) and len(c) == 2 and is_bstr(c[0], 20) and is_bstr(c[1]) for c in caveats)):
        raise ValueError("caveats are [enforcer bstr .size 20, terms bstr] pairs")
    if not is_bstr(signature):
        raise ValueError("the signature is a byte string")
    return {
        "delegate": bytes(delegate), "delegator": bytes(delegator), "authority": bytes(authority),
        "caveats": [(bytes(e), bytes(t)) for e, t in caveats], "salt": bytes(salt), "signature": bytes(signature),
    }


def hop_struct_hash(h) -> bytes:
    """The delegation hash; a caveat's args, where a redeemed delegation carries them, are not covered."""
    caveats = [(c[0], c[1]) for c in h["caveats"]]
    return delegation_struct_hash(h["delegate"], h["delegator"], h["authority"], caveats, h["salt"])


def parse_purpose(p, statement_type: str):
    """Purpose map: 1 kind and 2 digest together (a spend's), 3 description (a delegation's), 4 intent digest."""
    if not isinstance(p, dict) or not p or not set(p) <= {1, 2, 3, 4}:
        raise ValueError("purpose keys are 1 to 4")
    if (1 in p) != (2 in p):
        raise ValueError("purpose kind (1) and digest (2) appear together")
    if 1 in p and not (isinstance(p[1], int) and not isinstance(p[1], bool) and p[1] >= 0 and is_bstr(p[2], 32)):
        raise ValueError("purpose kind is an unsigned integer (an open registry, Q78) and its digest 32 bytes")
    if 3 in p and not (isinstance(p[3], str) and p[3]):
        raise ValueError("purpose description is a non-empty text string")
    if 4 in p and not is_bstr(p[4], 32):
        raise ValueError("intent digest is 32 bytes")
    if statement_type == "delegation" and (3 not in p or 1 in p):
        raise ValueError("a delegation's purpose has a description and no payment kind")
    if statement_type == "spend" and 1 not in p:
        raise ValueError("a spend's purpose has a kind and a digest")


def parse_statement_payload(statement_type: str, payload: dict) -> dict:
    """Check a payload against its type's CDDL and return it; raise ValueError if it does not conform."""
    required = {
        "delegation": {1, 2, 3, 4, 5, 6, 7, 10},
        "revocation": {1, 3, 4, 8, 11},
        "spend": {1, 3, 4, 8, 9, 10},
    }[statement_type]
    optional = {"delegation": set(), "revocation": {9}, "spend": set()}[statement_type]
    if not isinstance(payload, dict) or not required <= set(payload) <= required | optional:
        raise ValueError(f"{statement_type} payload keys {sorted(payload) if isinstance(payload, dict) else payload}")
    if payload[1] != 1 or not is_uint(payload[3]) or not is_bstr(payload[4], 20):
        raise ValueError("version, chain id or delegation manager malformed")
    if statement_type == "delegation":
        if not is_bstr(payload[2], 64) or not is_bstr(payload[6], 32) or not is_uint(payload[7]):
            raise ValueError("delegation key 2, 6 or 7 malformed")
        parse_hop(payload[5])
    else:
        if not is_bstr(payload[8], 32):
            raise ValueError("key 8 is a bare 32-byte delegation hash")
        for k in (9,):
            if k in payload and not is_bstr(payload[k], 32):
                raise ValueError("key 9 is a 32-byte transaction hash")
        if statement_type == "revocation" and not (isinstance(payload[11], str) and payload[11]):
            raise ValueError("key 11 is a non-empty reason")
    if 10 in payload:
        parse_purpose(payload[10], statement_type)
    return payload


COSE_SIGN1_TAG = 0xD2  # CBOR tag 18, one byte


def strip_tag18(data: bytes):
    """Drop a single leading tag 18 (spec/delegated-spend-statements.md section 3) and say how many
    bytes that shifted every offset: (the bytes after it, 1), or (the same bytes, 0)."""
    return (data[1:], 1) if data[:1] == bytes([COSE_SIGN1_TAG]) else (data, 0)


def parse_cose_sign1(data: bytes):
    """Split a COSE_Sign1, tagged 18 or not, and decode its protected header. `shift` is the
    length of the tag, so an offset in a decoded byte string plus `shift` is an offset in `data`."""
    data, shift = strip_tag18(data)
    item = cbor_decode(data)
    if not (isinstance(item, list) and len(item) == 4):
        raise ValueError("not a 4-element COSE_Sign1")
    protected_bytes, unprotected, payload, signature = item
    if not (is_bstr(protected_bytes) and isinstance(unprotected, dict) and is_bstr(payload) and is_bstr(signature)):
        raise ValueError("COSE_Sign1 element of the wrong type")
    return {
        "protected_bytes": protected_bytes, "protected": cbor_decode(protected_bytes),
        "unprotected": unprotected, "payload": payload, "signature": signature, "shift": shift,
    }


def _lenient_head(data: bytes, off: int):
    """(major, argument or None for indefinite, offset after the head), accepting a head longer than it needs."""
    if off >= len(data):
        raise ValueError("truncated")
    major, aux = data[off] >> 5, data[off] & 0x1F
    off += 1
    if aux < 24:
        return major, aux, off
    if aux in (24, 25, 26, 27):
        width = 1 << (aux - 24)
        if off + width > len(data):
            raise ValueError("truncated head")
        return major, int.from_bytes(data[off:off + width], "big"), off + width
    if aux == 31:
        return major, None, off
    raise ValueError("reserved head")


def _lenient_item(data: bytes, off: int):
    """Decode one item without the deterministic rules: heads longer than they need, indefinite
    lengths, tags and any map key order. Definite byte strings come back as Span; the content of an
    indefinite one is not located, so it raises."""
    major, n, off = _lenient_head(data, off)
    if major in (0, 1) and n is not None:
        return (n if major == 0 else -1 - n), off
    if major in (2, 3) and n is not None:
        if off + n > len(data):
            raise ValueError("truncated string")
        if major == 3:
            return data[off:off + n].decode("utf-8"), off + n
        s = Span(data[off:off + n])
        s.offset = off
        return s, off + n
    if major == 6 and n is not None:
        return _lenient_item(data, off)
    if major in (4, 5):
        items = []
        while True:
            if n is None and data[off:off + 1] == b"\xff":
                off += 1
                break
            if n is not None and len(items) == n * (2 if major == 5 else 1):
                break
            item, off = _lenient_item(data, off)
            items.append(item)
        if major == 4:
            return items, off
        return {(bytes(k) if isinstance(k, Span) else k): v for k, v in zip(items[::2], items[1::2])
                if not isinstance(k, (list, dict))}, off
    raise ValueError("an item the lenient decoder does not read")


def lenient_cose_sign1(data: bytes):
    """Locate the four elements of a COSE_Sign1 as found, however the signer or a relayer encoded
    the heads: non-shortest array and byte-string heads, tag 18 as 0xd2 or as 0xd8 0x12. Offsets
    are into `data`. Only byte-string elements the signature covers matter here; it raises if
    the bytes are not a four-element array of the right types."""
    major, n, off = _lenient_head(data, 0)
    if major == 6:
        if n != 18:
            raise ValueError("a tag other than 18")
        major, n, off = _lenient_head(data, off)
    if major != 4 or n != 4:
        raise ValueError("not a 4-element COSE_Sign1")
    protected_bytes, off = _lenient_item(data, off)
    unprotected, off = _lenient_item(data, off)
    payload, off = _lenient_item(data, off)
    signature, off = _lenient_item(data, off)
    if not (is_bstr(protected_bytes) and isinstance(unprotected, dict) and is_bstr(payload) and is_bstr(signature)):
        raise ValueError("COSE_Sign1 element of the wrong type")
    return {"protected_bytes": protected_bytes, "protected": _lenient_item(protected_bytes, 0)[0],
            "unprotected": unprotected, "payload": payload, "signature": signature}


def ks256_statement_signer(sign1):
    """The address a KS256 statement signature recovers to, or None (low-s required)."""
    if sign1["protected"].get(1) != KS256_ALG or len(sign1["signature"]) != 65:
        return None
    sig = sign1["signature"]
    r, s, recid = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:64], "big"), sig[64]
    if s > K1_HALF_N:
        return None
    sig_structure = cbor_encode(["Signature1", bytes(sign1["protected_bytes"]), b"", bytes(sign1["payload"])])
    return k1_recover_address(keccak256(sig_structure), r, s, recid)


def statement_type_of(sign1):
    cty = sign1["protected"].get(3)
    return next((t for t, c in CONTENT_TYPES.items() if c == cty), None)


def audit_publications(statement: bytes):
    """Every TAG ‖ H in the bytes publishes H. Only TAG ‖ H at key 2 of a delegation
    statement whose hop hashes to H is well formed; anything else is flagged."""
    found, i = [], statement.find(DELEGATION_TAG)
    while i != -1:
        if i + 64 <= len(statement):
            found.append((i, statement[i + 32:i + 64]))
        i = statement.find(DELEGATION_TAG, i + 1)
    anchor_offset, struct_hash, signer, signed = None, None, None, []
    try:
        # The signer and the signed ranges come from a lenient read: the outer array's head and
        # the byte-string heads are not covered by the signature, so whoever holds the statement, or
        # the signer, can choose them, and no tag in signed bytes may escape its signer that way.
        lenient = lenient_cose_sign1(statement)
        signer = ks256_statement_signer(lenient)
        # The signature covers the protected header and the payload, not the unprotected header.
        signed = [(lenient[k].offset, lenient[k].offset + len(lenient[k])) for k in ("protected_bytes", "payload")]
    except (ValueError, KeyError, IndexError, UnicodeDecodeError):
        pass
    try:
        sign1 = parse_cose_sign1(statement)
        if statement_type_of(sign1) == "delegation":
            payload = parse_statement_payload("delegation", cbor_decode(sign1["payload"]))
            anchor_offset = sign1["shift"] + sign1["payload"].offset + payload[2].offset
            struct_hash = hop_struct_hash(parse_hop(payload[5]))
    except (ValueError, KeyError, IndexError, UnicodeDecodeError):
        pass
    out = []
    for off, h in found:
        if off != anchor_offset:
            verdict = "flag:outside-key-2"
        elif h != struct_hash:
            verdict = "flag:hash-mismatch"
        else:
            verdict = "well-formed"
        attributed = signer if any(a <= off and off + 64 <= b for a, b in signed) else None
        out.append({"offset": off, "hash_hex": h.hex(), "verdict": verdict,
                    "signer_hex": attributed.hex() if attributed else None})
    return out


def route_check(statement: bytes) -> str:
    """What a registration service does with a statement of these types: it strips tag 18, then
    refuses a revocation or spend statement whose bytes, headers included, hold the delegation tag.
    Bytes that hold the tag and do not decode strictly cannot be classified, so it refuses those too."""
    try:
        statement_type = statement_type_of(parse_cose_sign1(statement))
    except (ValueError, KeyError, IndexError, UnicodeDecodeError):
        return "refused:tag-present" if DELEGATION_TAG in statement else "not-a-statement"
    if statement_type in ("revocation", "spend") and DELEGATION_TAG in statement:
        return "refused:tag-present"
    return "accepted"


def check_test_keys(name: str, v) -> int:
    bad = 0
    for k in v.get("keys", []):
        d = int(k["private_key_d_hex"], 16)
        if d != int.from_bytes(keccak256(k["label"].encode()), "big") % K1_N:
            print(f"{name}: key {k['label']!r}: scalar is not keccak256(label) mod n")
            bad += 1
        if k1_address(k1_mul(d, K1_G)).hex() != k["address_hex"]:
            print(f"{name}: key {k['label']!r}: address is not the address of its scalar")
            bad += 1
    for a in v.get("accounts", []):
        if keccak256(a["label"].encode())[12:].hex() != a["address_hex"]:
            print(f"{name}: account {a['label']!r}: address is not the low 20 bytes of keccak256(label)")
            bad += 1
    return bad


def hop_from_fields(d) -> dict:
    return {
        "delegate": bytes.fromhex(d["delegate_hex"]), "delegator": bytes.fromhex(d["delegator_hex"]),
        "authority": bytes.fromhex(d["authority_hex"]),
        "caveats": [(bytes.fromhex(c["enforcer_hex"]), bytes.fromhex(c["terms_hex"])) for c in d["caveats"]],
        "salt": bytes.fromhex(d["salt_hex"]), "signature": bytes.fromhex(d["signature_hex"]),
    }


def check_delegations(name: str, v) -> int:
    """Struct hash, domain, signed digest and signer of each delegation."""
    bad = 0
    keys = {k["label"]: bytes.fromhex(k["address_hex"]) for k in v.get("keys", [])}
    for d in v["delegations"]:
        where = f"{name}: delegation {d['name']!r}"
        h = hop_from_fields(d)
        struct_hash = hop_struct_hash(h)
        domain = eip712_domain_separator(d["chain_id"], bytes.fromhex(d["delegation_manager_hex"]))
        digest = keccak256(b"\x19\x01" + domain + struct_hash)
        for field, got in (("struct_hash_hex", struct_hash), ("domain_separator_hex", domain), ("typed_data_digest_hex", digest)):
            if d[field] != got.hex():
                print(f"{where}: {field} is {d[field]}, recomputed {got.hex()}")
                bad += 1
        sig = h["signature"]
        if len(sig) != 65 or sig[64] not in (27, 28):
            print(f"{where}: signature must be 65 bytes r || s || v with v 27 or 28")
            bad += 1
            continue
        r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:64], "big")
        signer = k1_recover_address(digest, r, s, sig[64] - 27)
        if s > K1_HALF_N or signer is None or signer != keys.get(d["signer"]):
            print(f"{where}: signature does not recover, low-s, to {d['signer']!r}")
            bad += 1
        if d["delegator_kind"] == "eoa" and signer != h["delegator"]:
            print(f"{where}: an EOA delegator's signature must recover to the delegator")
            bad += 1
    return bad


def statement_protected(statement_type: str, kid: bytes, iss: str, sub: str) -> bytes:
    return cbor_encode({1: KS256_ALG, 3: CONTENT_TYPES[statement_type], 4: kid, 15: {1: iss, 2: sub}})


def hop_array(h) -> list:
    return [h["delegate"], h["delegator"], h["authority"], [[e, t] for e, t in h["caveats"]], h["salt"], h["signature"]]


def purpose_map(p) -> dict:
    out = {}
    if "kind" in p:
        out[1], out[2] = p["kind"], bytes.fromhex(p["digest_hex"])
    if "description" in p:
        out[3] = p["description"]
    if "intent_digest_hex" in p:
        out[4] = bytes.fromhex(p["intent_digest_hex"])
    return out


def statement_payload_from_fields(st, hops) -> dict:
    f = st["fields"]
    payload = {1: 1, 3: f["chain_id"], 4: bytes.fromhex(f["delegation_manager_hex"])}
    if st["type"] == "delegation":
        h = hops[f["delegation"]]
        payload.update({2: DELEGATION_TAG + hop_struct_hash(h), 5: hop_array(h),
                        6: bytes.fromhex(f["delegate_log_id_hex"]), 7: f["depth"], 10: purpose_map(f["purpose"])})
    else:
        payload[8] = bytes.fromhex(f["delegation_hash_hex"])
        if "transaction_hash_hex" in f:
            payload[9] = bytes.fromhex(f["transaction_hash_hex"])
        if st["type"] == "revocation":
            payload[11] = f["reason"]
        else:
            payload[10] = purpose_map(f["purpose"])
    return payload


SESSION_ENDORSEMENT_LABEL = -65801  # spec/leaf-admission-and-session-endorsement.md section 4


def check_statement(name: str, st, hops, keys) -> int:
    where = f"{name}: statement {st['name']!r}"
    bad = 0
    data = bytes.fromhex(st["cose_sign1_hex"])
    try:
        sign1 = parse_cose_sign1(data)
        payload = parse_statement_payload(st["type"], cbor_decode(sign1["payload"]))
    except (ValueError, KeyError, IndexError, UnicodeDecodeError) as e:
        print(f"{where}: does not decode as a {st['type']} statement: {e}")
        return 1
    built = statement_payload_from_fields(st, hops)
    if cbor_encode(built) != bytes(sign1["payload"]):
        print(f"{where}: the fields re-encode to {cbor_encode(built).hex()}, the payload is {bytes(sign1['payload']).hex()}")
        bad += 1
    kid = keys[st["signer"]]
    sub = (bytes(payload[2][32:]) if st["type"] == "delegation" else bytes(payload[8])).hex()
    if statement_protected(st["type"], kid, kid.hex(), sub) != bytes(sign1["protected_bytes"]):
        print(f"{where}: protected header is not {{1: KS256, 3: its content type, 4: kid, 15: {{1: iss, 2: sub}}}}")
        bad += 1
    if set(sign1["unprotected"]) - {SESSION_ENDORSEMENT_LABEL}:
        print(f"{where}: the unprotected header must be empty, or hold only the session endorsement")
        bad += 1
    if ks256_statement_signer(sign1) != kid:
        print(f"{where}: the KS256 signature does not recover, low-s, to its kid")
        bad += 1
    if st["type"] == "delegation":
        h = hop_struct_hash(parse_hop(payload[5]))
        if bytes(payload[2]) != DELEGATION_TAG + h:
            print(f"{where}: key 2 is not TAG ‖ the struct hash of key 5")
            bad += 1
        pub = st["publication"]
        prefix, suffix = bytes.fromhex(pub["prefix_hex"]), bytes.fromhex(pub["suffix_hex"])
        if prefix + DELEGATION_TAG + h + suffix != data or pub["delegation_hash_hex"] != h.hex():
            print(f"{where}: prefix ‖ TAG ‖ delegation hash ‖ suffix is not the statement")
            bad += 1
        leaf = hashlib.sha256(bytes.fromhex(pub["idtimestamp_hex"]) + hashlib.sha256(data).digest()).digest()
        if pub["leaf_hex"] != leaf.hex():
            print(f"{where}: leaf is {pub['leaf_hex']}, recomputed {leaf.hex()}")
            bad += 1
        if [p["verdict"] for p in audit_publications(data)] != ["well-formed"]:
            print(f"{where}: a delegation statement must hold exactly one, well formed, publication")
            bad += 1
    elif DELEGATION_TAG in data:
        print(f"{where}: a {st['type']} statement must never encode the delegation tag")
        bad += 1
    if route_check(data) != "accepted":
        print(f"{where}: the route check refuses it")
        bad += 1
    paid = st.get("paid_by")
    if paid:
        codes = {}
        p = payload[10]
        kind = {v_: k for k, v_ in PAYMENT_KINDS.items()}.get(p[1])
        if "delegation" in paid:
            # An auditor ties a spend of a registration-service purpose back to its
            # leaf: the nonce over the purpose and the chain's root is the leaf's salt.
            leaf = hops[paid["delegation"]]
            by_hash = {hop_struct_hash(h): h for h in hops.values()}
            root_hop = leaf
            for _ in range(len(hops)):  # follow authority links to the hop that names ROOT_AUTHORITY
                if root_hop["authority"] == ROOT_AUTHORITY or root_hop["authority"] not in by_hash:
                    break
                root_hop = by_hash[root_hop["authority"]]
            if root_hop["authority"] != ROOT_AUTHORITY or root_hop["delegator"].hex() != paid["root_hex"]:
                codes["root"] = "paid_by.root_hex is not the delegator at the root of the leaf's authority chain"
            if hop_struct_hash(leaf) != bytes(payload[8]) or kind is None or hashlib.sha256(
                payment_nonce_preimage(kind, bytes(p[2]), bytes.fromhex(paid["root_hex"]))
            ).digest() != leaf["salt"]:
                codes["nonce"] = "the nonce over its purpose and root is not the salt of the leaf it names"
        if paid.get("receipt_checked"):
            refusal = receipt_refusal(payload, kind)
            if refusal:
                codes[refusal[0]] = refusal[1]
        want = {st["refused"]} if "refused" in st else set()
        if set(codes) != want:
            for message in codes.values():
                print(f"{where}: {message}")
            if not codes:
                print(f"{where}: refused for {sorted(want)}, but every spend check passes")
            bad += 1
    return bad


def receipt_refusal(payload: dict, kind):
    """Why key 8 of a kind 1 to 3 spend is no payment of the erc7710-leaf-salt/v1 receipt that
    key 9's transaction stands for, as (code, message), or None when it is one: key 8 is a payment
    of the receipt (`binding`), on the spend's delegation manager (`manager`) and chain (`chain`),
    and the nonce over the spend's kind, purpose digest and that payment's root is its salt (`purpose`)."""
    v = load("erc7710-leaf-salt-v1.json")
    case = next((c for c in v["cases"] if c["transaction_hash_hex"] == bytes(payload[9]).hex()), None)
    if case is None:
        return "binding", "key 9 names no receipt"
    got = leaf_salt_v1(v["config"], case["receipt"]["logs"])
    pay = next((p for p in got["payments"] if p["delegation_hash_hex"] == bytes(payload[8]).hex()), None)
    if pay is None:
        return "binding", "key 8 is not a payment of the receipt's binding rule"
    if pay["delegation_manager_hex"] != bytes(payload[4]).hex():
        return "manager", "the payment is under another delegation manager than the spend names"
    if v["config"]["chain_id"] != payload[3]:
        return "chain", "the payment is on another chain than the spend names"
    if kind is None or hashlib.sha256(
            payment_nonce_preimage(kind, bytes(payload[10][2]), bytes.fromhex(pay["root_hex"]))
    ).hexdigest() != pay["salt_hex"]:
        return "purpose", "the nonce over the spend's kind, purpose digest and the payment's root is not the payment's salt"
    return None


def check_map_key_order(name: str, m) -> int:
    """A map whose labels differ in encoded length: both orders' bytes, each refused under
    the other order, and the vector provisional until the platform settles which is canon."""
    where = f"{name}: map_key_order"
    value = {int(k): bytes.fromhex(x) for k, x in m["map"].items()}
    lengths = {len(cbor_encode(k)) for k in value}
    got = {order: cbor_encode(value, order) for order in ("bytewise", "length-first")}
    bad = 0
    if len(lengths) < 2 or got["bytewise"] == got["length-first"]:
        print(f"{where}: the labels must differ in encoded length and the two orders give different bytes")
        bad += 1
    for order, field in (("bytewise", "bytewise_hex"), ("length-first", "length_first_hex")):
        if m[field] != got[order].hex():
            print(f"{where}: {field} is {m[field]}, recomputed {got[order].hex()}")
            bad += 1
        other = "length-first" if order == "bytewise" else "bytewise"
        try:
            cbor_decode(got[order], other)
            print(f"{where}: {order} bytes decode under {other} order; a strict decoder refuses them")
            bad += 1
        except ValueError:
            pass
    if m.get("status") != "provisional" or m.get("canonical") != "unsettled":
        print(f"{where}: stays provisional, canonical unsettled, until the map key order is decided")
        bad += 1
    return bad


def check_delegated_spend_statements() -> int:
    name = "erc7710-statements.json"
    v = load(name)
    bad = check_test_keys(name, v)
    conv = v["conventions"]
    for field, want in (
        ("delegation_tag_label", DELEGATION_TAG_LABEL), ("delegation_tag_hex", DELEGATION_TAG.hex()),
        ("delegation_typehash_hex", DELEGATION_TYPEHASH.hex()), ("caveat_typehash_hex", CAVEAT_TYPEHASH.hex()),
        ("root_authority_hex", ROOT_AUTHORITY.hex()), ("any_delegate_hex", ANY_DELEGATE.hex()),
        ("content_types", CONTENT_TYPES),
    ):
        if conv.get(field) != want:
            print(f"{name}: conventions.{field} is {conv.get(field)!r}, expected {want!r}")
            bad += 1
    bad += check_delegations(name, v)
    hops = {d["name"]: hop_from_fields(d) for d in v["delegations"]}
    keys = {k["label"]: bytes.fromhex(k["address_hex"]) for k in v["keys"]}
    for st in v["statements"] + v["refused_spends"]:
        bad += check_statement(name, st, hops, keys)
    for neg in v["decode_negatives"]:
        try:
            sign1 = parse_cose_sign1(bytes.fromhex(neg["cose_sign1_hex"]))
            parse_statement_payload(neg["type"], cbor_decode(sign1["payload"]))
            if set(sign1["unprotected"]) - {SESSION_ENDORSEMENT_LABEL}:
                raise ValueError("an unprotected label other than the session endorsement's")
        except (ValueError, KeyError, IndexError, UnicodeDecodeError):
            continue
        print(f"{name}: decode negative {neg['name']!r}: a conforming decoder refuses it, and it decoded")
        bad += 1
    for acc in v["decode_accepts"]:
        try:
            sign1 = parse_cose_sign1(bytes.fromhex(acc["cose_sign1_hex"]))
            parse_statement_payload(acc["type"], cbor_decode(sign1["payload"]))
        except (ValueError, KeyError, IndexError, UnicodeDecodeError) as e:
            print(f"{name}: decode accept {acc['name']!r}: a conforming decoder accepts it, and refused it: {e}")
            bad += 1
    if not any(a["name"] == "purpose-kind-5" for a in v["decode_accepts"]):
        print(f"{name}: needs a spend of a kind no section 7 kind names, which a decoder accepts (Q78)")
        bad += 1
    if not {"binding", "manager", "chain", "purpose", "root"} <= {st["refused"] for st in v["refused_spends"]}:
        print(f"{name}: needs a spend refused for each code: key 8 no payment of its receipt (binding), "
              "another delegation manager, another chain, a purpose the payment's salt does not match, and a root "
              "that is not the root of the leaf's authority chain")
        bad += 1
    if {st["type"] for st in v["statements"]} != set(CONTENT_TYPES):
        print(f"{name}: needs a statement of every type")
        bad += 1
    for case in v["audit_cases"]:
        data = bytes.fromhex(case["cose_sign1_hex"])
        got = audit_publications(data)
        if got != case["expect"]["publications"]:
            print(f"{name}: audit case {case['name']!r}: publications {got}, expected {case['expect']['publications']}")
            bad += 1
        if route_check(data) != case["expect"]["route"]:
            print(f"{name}: audit case {case['name']!r}: route {route_check(data)}, expected {case['expect']['route']}")
            bad += 1
    if not any(c["expect"]["route"] == "refused:tag-present" for c in v["audit_cases"]):
        print(f"{name}: needs a revocation or spend statement that the route check refuses")
        bad += 1
    bad += check_map_key_order(name, v["map_key_order"])
    if not {c["expect"]["publications"][0]["verdict"] for c in v["audit_cases"] if c["expect"]["publications"]} >= {
        "well-formed", "flag:outside-key-2", "flag:hash-mismatch"
    }:
        print(f"{name}: audit cases must cover a well-formed publication and both flags")
        bad += 1
    return bad


# The payment nonce (spec/payment-nonce-and-binding.md section 2).
PAYMENT_NONCE_TAG = b"univocity/payment-nonce/v1"
PAYMENT_KINDS = {"grant": 1, "onboarding": 2, "credits": 3}
CANONICAL_INSTANCE_ID = re.compile(r"^eip155:[1-9][0-9]{0,31}:0x[0-9a-f]{40}$")


def purpose_digest(kind: str, purpose: dict) -> bytes:
    if kind == "grant":
        grant = bytes.fromhex(purpose["grant_hex"])
        if sorted(cbor_decode(grant)) != [1, 2, 3, 4, 5, 6]:
            raise ValueError("a grant purpose is the inner grant, keys 1 to 6")
        return hashlib.sha256(grant).digest()
    if kind == "onboarding":
        if not purpose["request_id"]:
            raise ValueError("an onboarding request id is not empty")
        return hashlib.sha256(purpose["request_id"].encode("utf-8")).digest()
    if kind == "credits":
        instance, credits = purpose["univocity_instance_id"], purpose["credits"]
        if not CANONICAL_INSTANCE_ID.match(instance) or not 0 < credits < 1 << 64 or not purpose["idempotency_key"]:
            raise ValueError("credits need a canonical instance id, a count from 1 and a key")
        purchase_id = hashlib.sha256(purpose["idempotency_key"].encode("utf-8")).digest()
        return hashlib.sha256(instance.encode("utf-8") + b"\x00" + u64_be(credits) + purchase_id).digest()
    raise ValueError(f"unknown purpose kind {kind!r}")


def payment_nonce_preimage(kind: str, digest: bytes, payer: bytes) -> bytes:
    if len(digest) != 32 or len(payer) != 20:
        raise ValueError("the purpose digest is 32 bytes and the payer 20")
    return PAYMENT_NONCE_TAG + bytes([PAYMENT_KINDS[kind]]) + digest + payer


def is_canonical_nonce_preimage(b: bytes) -> bool:
    """The only shape any request derives a nonce from: TAG || kind 1-3 || 32 || 20 bytes."""
    t = len(PAYMENT_NONCE_TAG)
    return len(b) == t + 1 + 32 + 20 and b[:t] == PAYMENT_NONCE_TAG and b[t] in PAYMENT_KINDS.values()


def check_payment_nonce() -> int:
    name = "payment-nonce.json"
    v = load(name)
    bad = 0
    conv = v["conventions"]
    if conv.get("tag_utf8") != PAYMENT_NONCE_TAG.decode() or conv.get("kinds") != PAYMENT_KINDS:
        print(f"{name}: conventions name a different tag or kinds")
        bad += 1
    nonces = {}
    for e in v["vectors"]:
        where = f"{name}: {e['name']!r}"
        try:
            digest = purpose_digest(e["kind"], e["purpose"])
            preimage = payment_nonce_preimage(e["kind"], digest, bytes.fromhex(e["payer_hex"]))
        except (ValueError, KeyError) as err:
            print(f"{where}: {err}")
            bad += 1
            continue
        nonce = hashlib.sha256(preimage).digest()
        for field, got in (("purpose_digest_hex", digest), ("preimage_hex", preimage), ("nonce_hex", nonce)):
            if e[field] != got.hex():
                print(f"{where}: {field} is {e[field]}, recomputed {got.hex()}")
                bad += 1
        if "purchase_id_hex" in e and e["purchase_id_hex"] != hashlib.sha256(e["purpose"]["idempotency_key"].encode()).hexdigest():
            print(f"{where}: purchase_id_hex is not SHA-256 of the Idempotency-Key")
            bad += 1
        if not is_canonical_nonce_preimage(preimage):
            print(f"{where}: the preimage is not canonical")
            bad += 1
        nonces[e["name"]] = nonce
    if len(set(nonces.values())) != len(nonces):
        print(f"{name}: two vectors share a nonce")
        bad += 1
    grant = next(e for e in v["vectors"] if e["name"] == "grant")
    golden = next(g for g in load("grant_vectors.json") if g["description"] == grant["purpose"]["from_grant_vector"])
    if encode_grant_payload(golden) != bytes.fromhex(grant["purpose"]["grant_hex"]):
        print(f"{name}: the grant purpose is not the payload form (keys 1 to 6) of its grant vector")
        bad += 1
    if [e["kind"] for e in v["vectors"]].count("grant") < 2 or not {"onboarding", "credits"} <= {e["kind"] for e in v["vectors"]}:
        print(f"{name}: needs every kind, and one purpose under two payers")
        bad += 1
    for e in v["not_canonical"]:
        b = bytes.fromhex(e["preimage_hex"])
        if is_canonical_nonce_preimage(b) or hashlib.sha256(b).hexdigest() != e["salt_hex"]:
            print(f"{name}: not_canonical {e['name']!r}: is canonical, or salt_hex is not its SHA-256")
            bad += 1
    return bad


# erc7710-leaf-salt/v1 (spec/payment-nonce-and-binding.md section 3): the binding
# of a delegated payment, read from a successful receipt's logs.
REDEEMED_DELEGATION_TOPIC = keccak256(
    b"RedeemedDelegation(address,address,(address,address,bytes32,(address,bytes,bytes)[],uint256,bytes))"
)
TRANSFER_TOPIC = keccak256(b"Transfer(address,address,uint256)")
AUTHORIZATION_USED_TOPIC = keccak256(b"AuthorizationUsed(address,bytes32)")
TRANSFER_SELECTOR = keccak256(b"transfer(address,uint256)")[:4]


def abi_bytes(b: bytes) -> bytes:
    return u256(len(b)) + b + b"\x00" * (-len(b) % 32)


def abi_encode_delegation(h) -> bytes:
    """abi.encode(Delegation), the data of a RedeemedDelegation log; caveats carry args."""
    parts = []
    for enforcer, terms, args in h["caveats"]:
        t = abi_bytes(terms)
        parts.append(addr_word(enforcer) + u256(96) + u256(96 + len(t)) + t + abi_bytes(args))
    offsets, at = [], 32 * len(parts)
    for part in parts:
        offsets.append(at)
        at += len(part)
    caveats = u256(len(parts)) + b"".join(u256(o) for o in offsets) + b"".join(parts)
    head = (addr_word(h["delegate"]) + addr_word(h["delegator"]) + h["authority"] + u256(192) + h["salt"]
            + u256(192 + len(caveats)))
    return u256(32) + head + caveats + abi_bytes(h["signature"])


def abi_decode_delegation(data: bytes) -> dict:
    """Decode a RedeemedDelegation log's data; refuse any encoding but the canonical one."""
    def word(off):
        if off < 0 or off + 32 > len(data):
            raise ValueError("ABI read out of bounds")
        return data[off:off + 32]

    def uint(off):
        return int.from_bytes(word(off), "big")

    def address(off):
        w = word(off)
        if w[:12] != b"\x00" * 12:
            raise ValueError("address word with high bytes set")
        return w[12:]

    def dyn_bytes(off):
        n = uint(off)
        if off + 32 + n > len(data):
            raise ValueError("ABI bytes out of bounds")
        return data[off + 32:off + 32 + n]

    t = uint(0)
    caveats_at = t + uint(t + 96)
    caveats = []
    for i in range(uint(caveats_at)):
        c = caveats_at + 32 + uint(caveats_at + 32 + 32 * i)
        caveats.append((address(c), dyn_bytes(c + uint(c + 32)), dyn_bytes(c + uint(c + 64))))
    h = {"delegate": address(t), "delegator": address(t + 32), "authority": word(t + 64), "caveats": caveats,
         "salt": word(t + 128), "signature": dyn_bytes(t + uint(t + 160))}
    if abi_encode_delegation(h) != data:
        raise ValueError("not the canonical ABI encoding of a Delegation")
    return h


def pinned_transfer(terms: bytes, usdc: bytes, payee: bytes):
    """The amount an ExactExecutionEnforcer pin moves to the payee, or None: the terms are
    exactly USDC || value 0 || transfer(payee, amount)."""
    if len(terms) != 20 + 32 + 4 + 64 or terms[:20] != usdc or terms[20:52] != u256(0):
        return None
    if terms[52:56] != TRANSFER_SELECTOR or terms[56:88] != addr_word(payee):
        return None
    return int.from_bytes(terms[88:120], "big")


def leaf_salt_v1(config: dict, logs: list) -> dict:
    """Bind a successful receipt's logs, as erc7710-leaf-salt/v1 defines."""
    usdc, payee = bytes.fromhex(config["usdc_hex"]), bytes.fromhex(config["payee_hex"])
    managers = {bytes.fromhex(m["delegation_manager_hex"]): m for m in config["delegation_managers"]}
    transfers, eip3009, redeemed = [], [], []
    for pos, log in enumerate(logs):
        address, topics = bytes.fromhex(log["address_hex"]), [bytes.fromhex(t) for t in log["topics_hex"]]
        data = bytes.fromhex(log["data_hex"])
        if address == usdc and len(topics) == 3 and topics[0] == TRANSFER_TOPIC and len(data) == 32:
            if topics[1][:12] != b"\x00" * 12 or topics[2][:12] != b"\x00" * 12:
                continue
            sender, to = topics[1][12:], topics[2][12:]
            if to != payee:
                continue
            prev = logs[pos - 1] if pos else None
            if (prev and bytes.fromhex(prev["address_hex"]) == usdc and len(prev["topics_hex"]) == 3
                    and bytes.fromhex(prev["topics_hex"][0]) == AUTHORIZATION_USED_TOPIC
                    and bytes.fromhex(prev["topics_hex"][1]) == addr_word(sender)):
                eip3009.append(pos)
            else:
                transfers.append({"position": pos, "from": sender, "amount": int.from_bytes(data, "big")})
        elif address in managers and len(topics) == 3 and topics[0] == REDEEMED_DELEGATION_TOPIC:
            if topics[1][:12] != b"\x00" * 12:
                continue
            try:
                h = abi_decode_delegation(data)
            except ValueError:
                continue
            redeemed.append({"position": pos, "manager": address, "root": topics[1][12:], "hop": h,
                             "hash": hop_struct_hash(h)})
    # Chains: per manager, a run of events, each delegation's authority the hash of the
    # next, ending at ROOT_AUTHORITY, every event naming the run's root delegator.
    chains, open_runs = [], {}
    for e in redeemed:
        run = open_runs.get(e["manager"])
        if run and run[-1]["hop"]["authority"] == e["hash"]:
            run.append(e)
        else:
            run = open_runs[e["manager"]] = [e]
        if e["hop"]["authority"] == ROOT_AUTHORITY:
            if all(x["root"] == e["hop"]["delegator"] for x in run):
                chains.append(run)
            open_runs[e["manager"]] = None
    bindings, out_chains = [], []
    for run in chains:
        m = managers[run[0]["manager"]]
        exact = bytes.fromhex(m["exact_execution_enforcer_hex"])
        limited = bytes.fromhex(m["limited_calls_enforcer_hex"])
        binding = None
        for e in reversed(run):  # root first
            amounts = [pinned_transfer(t, usdc, payee) for enf, t, _ in e["hop"]["caveats"] if enf == exact]
            amounts = [a for a in amounts if a is not None]
            if amounts:
                binding = {"position": e["position"], "manager": e["manager"], "hash": e["hash"],
                           "salt": e["hop"]["salt"], "root": run[-1]["hop"]["delegator"], "amount": amounts[0],
                           "call_limit": any(enf == limited and t == u256(1) for enf, t, _ in e["hop"]["caveats"])}
                bindings.append(binding)
                break
        out_chains.append({"root_hex": run[-1]["hop"]["delegator"].hex(),
                           "delegations": [e["hash"].hex() for e in run],
                           "binding": binding["hash"].hex() if binding else None})
    paired, pairs, unpaired = set(), [], []
    for b in sorted(bindings, key=lambda b: b["position"]):
        t = next((t for t in transfers if t["position"] not in paired and t["from"] == b["root"]
                  and t["amount"] == b["amount"]), None)
        if t is None:
            unpaired.append(b["hash"].hex())
            continue
        paired.add(t["position"])
        pairs.append((b, t))
    payments = [{"chain": f"eip155:{config['chain_id']}", "delegation_manager_hex": b["manager"].hex(), "delegation_hash_hex": b["hash"].hex(),
                 "salt_hex": b["salt"].hex(), "root_hex": b["root"].hex(), "amount": b["amount"],
                 "transfer_position": t["position"]} for b, t in pairs if b["call_limit"]]
    held = {p["transfer_position"] for p in payments}
    return {
        "eip3009_transfers": eip3009,
        "chains": out_chains,
        "pairs": [{"binding": b["hash"].hex(), "transfer_position": t["position"]} for b, t in pairs],
        "unpaired_bindings": unpaired,
        "payments": payments,
        "unbound_transfers": [t["position"] for t in transfers if t["position"] not in held],
    }


def request_binds(payments: list, kind: str, digest: bytes):
    """The payment a request binds: the one whose salt is the request's nonce over its root."""
    return next((p for p in payments if hashlib.sha256(
        payment_nonce_preimage(kind, digest, bytes.fromhex(p["root_hex"]))).hexdigest() == p["salt_hex"]), None)


def check_leaf_salt() -> int:
    name = "erc7710-leaf-salt-v1.json"
    v = load(name)
    bad = check_test_keys(name, v)
    nonces = {e["name"]: e for e in load("payment-nonce.json")["vectors"]}
    m = v["config"]["delegation_managers"]
    if [(x["framework"], x["delegation_manager_hex"]) for x in m] != [(LEAF_SALT_FRAMEWORK, LEAF_SALT_MANAGER)]:
        print(f"{name}: the v1 rule lists one framework version and its delegation manager")
        bad += 1
    results = {}
    if len({c["transaction_hash_hex"] for c in v["cases"]}) != len(v["cases"]):
        print(f"{name}: each case's transaction_hash_hex must be its own, for a spend's key 9 to select it")
        bad += 1
    for case in v["cases"]:
        where = f"{name}: case {case['name']!r}"
        got = leaf_salt_v1(v["config"], case["receipt"]["logs"])
        results[case["name"]] = got
        for field, want in case["expect"].items():
            if got[field] != want:
                print(f"{where}: {field} is {got[field]}, expected {want}")
                bad += 1
        for r in case["requests"]:
            n = nonces[r["purpose"]]
            p = request_binds(got["payments"], n["kind"], bytes.fromhex(n["purpose_digest_hex"]))
            if (p["delegation_hash_hex"] if p else None) != r["binds"]:
                print(f"{where}: a {r['purpose']!r} request binds {p and p['delegation_hash_hex']}, expected {r['binds']}")
                bad += 1
    rp = v["repay"]
    first, second = (results[rp[k]]["payments"] for k in ("first_case", "second_case"))
    if len(first) != 1 or len(second) != 1 or first[0]["salt_hex"] != second[0]["salt_hex"] or (
            first[0]["delegation_hash_hex"] == second[0]["delegation_hash_hex"]):
        print(f"{name}: repay: the varied leaf must bind the same nonce under another identity")
        return bad + 1
    a, b = (bytes.fromhex(x) for x in rp["same_leaf_other_args"]["event_data_hex"])
    try:
        ha, hb = hop_struct_hash(abi_decode_delegation(a)), hop_struct_hash(abi_decode_delegation(b))
    except ValueError as e:
        print(f"{name}: repay: event data does not decode: {e}")
        return bad + 1
    if a == b or ha != hb or ha.hex() != first[0]["delegation_hash_hex"]:
        print(f"{name}: repay: other args must leave the first leaf's hash, and so its identity, unchanged")
        bad += 1
    if not {"one-payment", "two-payments-one-root", "salted-hop-above-salted-leaf", "stranger-extends-leaf",
            "no-call-limit", "no-call-limit-takes-part", "two-bindings-one-transfer",
            "eip3009-transfer-beside-binding", "two-roots-pair-by-root",
            "call-limit-two", "call-limit-unlisted", "pin-unlisted-enforcer", "pin-to-another-payee",
            "transfer-from-another-contract", "authorization-used-from-another-contract",
            "authorization-used-for-another-account", "pin-other-target", "pin-approve",
            "agent-pays-itself", "pin-trailing-bytes"} <= set(results):
        print(f"{name}: a case the rule requires is missing")
        bad += 1
    return bad


LEAF_SALT_FRAMEWORK = "MetaMask Delegation Framework v1.3.0"
LEAF_SALT_MANAGER = "db9b1e94b5b69df7e401ddbede43491141047db3"


def _flip(hex_string: str, at: int = -2) -> str:
    """Change one byte of a hex string."""
    i = len(hex_string) + at if at < 0 else at
    return hex_string[:i] + f"{int(hex_string[i:i + 2], 16) ^ 1:02x}" + hex_string[i + 2:]


def _named(items, name):
    return next(x for x in items if x["name"] == name)


def _set(item, **fields):
    item.update(fields)


# Each mutation breaks one rule of a delegated-spend fixture; --self-test requires
# the checker to report at least one problem for every one of them.
SELF_TEST_MUTATIONS = [
    ("erc7710-statements.json", "a delegation signature byte",
     lambda v: _set(_named(v["delegations"], "D_AB"), signature_hex=_flip(_named(v["delegations"], "D_AB")["signature_hex"], 10))),
    ("erc7710-statements.json", "a caveat's terms",
     lambda v: _set(_named(v["delegations"], "D_HA")["caveats"][1],
                    terms_hex=_flip(_named(v["delegations"], "D_HA")["caveats"][1]["terms_hex"]))),
    ("erc7710-statements.json", "the signed digest recorded as the struct hash",
     lambda v: _set(_named(v["delegations"], "D_AB"), struct_hash_hex=_named(v["delegations"], "D_AB")["typed_data_digest_hex"])),
    ("erc7710-statements.json", "a statement byte",
     lambda v: _set(_named(v["statements"], "delegation/D_AB"),
                    cose_sign1_hex=_flip(_named(v["statements"], "delegation/D_AB")["cose_sign1_hex"], 200))),
    ("erc7710-statements.json", "a statement's signer",
     lambda v: _set(_named(v["statements"], "revocation/D_AB"), signer=_named(v["statements"], "spend/credits")["signer"])),
    ("erc7710-statements.json", "a publication's idtimestamp",
     lambda v: _set(_named(v["statements"], "delegation/D_HA")["publication"], idtimestamp_hex="019a8f6e2c000002")),
    ("erc7710-statements.json", "an audit verdict",
     lambda v: _set(_named(v["audit_cases"], "flag/hash-mismatch")["expect"]["publications"][0], verdict="well-formed")),
    ("erc7710-statements.json", "a signer blamed for the unprotected header",
     lambda v: _set(_named(v["audit_cases"], "refuse/spend-with-tag")["expect"]["publications"][0],
                    signer_hex=next(k["address_hex"] for k in v["keys"] if k["label"].endswith("agent B statement key")))),
    ("erc7710-statements.json", "a re-encoded statement's tag left unattributed",
     lambda v: _set(_named(v["audit_cases"], "flag/tag-in-another-statement-type-reencoded")["expect"]["publications"][0],
                    signer_hex=None)),
    ("erc7710-statements.json", "a long tag 18 statement's tag left unattributed",
     lambda v: _set(_named(v["audit_cases"], "flag/tag-in-another-statement-type-tag18-long")["expect"]["publications"][0],
                    signer_hex=None)),
    ("erc7710-leaf-salt-v1.json", "a pin with a trailing byte treated as a pin",
     lambda v: _set(_named(v["cases"], "pin-trailing-bytes")["expect"]["chains"][0],
                    binding=_named(v["cases"], "pin-trailing-bytes")["expect"]["chains"][0]["delegations"][0])),
    ("erc7710-statements.json", "no spend refused for another chain",
     lambda v: v["refused_spends"].remove(_named(v["refused_spends"], "spend/credits-on-another-chain"))),
    ("erc7710-statements.json", "no spend refused for another delegation manager",
     lambda v: v["refused_spends"].remove(_named(v["refused_spends"], "spend/credits-under-another-manager"))),
    ("erc7710-statements.json", "no spend refused for a misstated purpose",
     lambda v: v.update(refused_spends=[st for st in v["refused_spends"] if st["refused"] != "purpose"])),
    ("erc7710-statements.json", "a misstated purpose refused as a binding failure",
     lambda v: _set(_named(v["refused_spends"], "spend/credits-another-purchase"), refused="binding")),
    ("erc7710-statements.json", "a hidden publication left out",
     lambda v: _named(v["audit_cases"], "flag/tag-in-hop-signature")["expect"]["publications"].pop()),
    ("erc7710-statements.json", "a refused revocation's route",
     lambda v: _set(_named(v["audit_cases"], "refuse/revocation-with-tag")["expect"], route="accepted")),
    ("erc7710-statements.json", "a refused statement's route",
     lambda v: _set(_named(v["audit_cases"], "refuse/spend-with-tag")["expect"], route="accepted")),
    ("erc7710-statements.json", "a tag-18 spend statement's route",
     lambda v: _set(_named(v["audit_cases"], "refuse/spend-with-tag-tag18")["expect"], route="accepted")),
    ("erc7710-statements.json", "an unreadable statement holding the tag, route",
     lambda v: _set(_named(v["audit_cases"], "refuse/spend-with-tag-reencoded")["expect"], route="not-a-statement")),
    ("erc7710-statements.json", "a spend naming a receipt without its leaf accepted",
     lambda v: _set(_named(v["refused_spends"], "spend/credits-wrong-receipt"), refused="chain")),
    ("erc7710-statements.json", "the receipt check dropped from a refused spend",
     lambda v: _named(v["refused_spends"], "spend/credits-under-salted-hop")["paid_by"].pop("receipt_checked")),
    ("erc7710-leaf-salt-v1.json", "two receipts under one transaction hash",
     lambda v: _set(v["cases"][1], transaction_hash_hex=v["cases"][0]["transaction_hash_hex"])),
    ("erc7710-leaf-salt-v1.json", "a leaf binding on its own pin, not the verifier's payee",
     lambda v: _set(_named(v["cases"], "agent-pays-itself")["expect"]["chains"][0],
                    binding=_named(v["cases"], "agent-pays-itself")["expect"]["chains"][0]["delegations"][0])),
    ("erc7710-statements.json", "a refused decode swapped for a conforming statement",
     lambda v: _set(_named(v["decode_negatives"], "purpose-kind-text"),
                    cose_sign1_hex=_named(v["statements"], "spend/credits")["cose_sign1_hex"])),
    ("erc7710-statements.json", "an open-registry kind swapped for a refused decode",
     lambda v: _set(_named(v["decode_accepts"], "purpose-kind-5"),
                    cose_sign1_hex=_named(v["decode_negatives"], "purpose-kind-text")["cose_sign1_hex"])),
    ("erc7710-statements.json", "the spend leaf's salt",
     lambda v: _set(_named(v["delegations"], "leaf/credits"), salt_hex="00" * 32)),
    ("erc7710-statements.json", "the provisional vector frozen",
     lambda v: _set(v["map_key_order"], status="frozen", canonical="bytewise")),
    ("erc7710-statements.json", "the map key orders swapped",
     lambda v: _set(v["map_key_order"], bytewise_hex=v["map_key_order"]["length_first_hex"])),
    ("payment-nonce.json", "a nonce byte",
     lambda v: _set(_named(v["vectors"], "onboarding"), nonce_hex=_flip(_named(v["vectors"], "onboarding")["nonce_hex"]))),
    ("payment-nonce.json", "a purpose field",
     lambda v: _set(_named(v["vectors"], "credits")["purpose"], credits=101)),
    ("payment-nonce.json", "the payer",
     lambda v: _set(_named(v["vectors"], "grant"), payer_hex=_named(v["vectors"], "grant/another-payer")["payer_hex"])),
    ("payment-nonce.json", "a canonical preimage among the non-canonical",
     lambda v: _set(v["not_canonical"][0], preimage_hex=_named(v["vectors"], "grant")["preimage_hex"],
                    salt_hex=_named(v["vectors"], "grant")["nonce_hex"])),
    ("erc7710-leaf-salt-v1.json", "a payment's Transfer position",
     lambda v: _set(_named(v["cases"], "one-payment")["expect"]["payments"][0], transfer_position=0)),
    ("erc7710-leaf-salt-v1.json", "the leaf binding beneath a salted hop",
     lambda v: _set(_named(v["cases"], "salted-hop-above-salted-leaf")["requests"][1],
                    binds=_named(v["delegations"], "leaf/under-salted-hop")["struct_hash_hex"])),
    ("erc7710-leaf-salt-v1.json", "both bindings paid by one Transfer",
     lambda v: _set(_named(v["cases"], "two-bindings-one-transfer")["expect"], unpaired_bindings=[])),
    ("erc7710-leaf-salt-v1.json", "an EIP-3009 Transfer counted as unbound",
     lambda v: _set(_named(v["cases"], "eip3009-transfer-beside-binding")["expect"], unbound_transfers=[1])),
    ("erc7710-leaf-salt-v1.json", "a Transfer from another contract paired",
     lambda v: _set(_named(v["cases"], "transfer-from-another-contract")["expect"], unpaired_bindings=[])),
    ("erc7710-leaf-salt-v1.json", "an AuthorizationUsed from another contract making the Transfer EIP-3009",
     lambda v: _set(_named(v["cases"], "authorization-used-from-another-contract")["expect"],
                    eip3009_transfers=[2], pairs=[], payments=[])),
    ("erc7710-leaf-salt-v1.json", "an AuthorizationUsed for another account making the Transfer EIP-3009",
     lambda v: _set(_named(v["cases"], "authorization-used-for-another-account")["expect"],
                    eip3009_transfers=[2], pairs=[], payments=[])),
    ("erc7710-leaf-salt-v1.json", "a pin on another contract binding",
     lambda v: _set(_named(v["cases"], "pin-other-target")["expect"]["chains"][0],
                    binding=_named(v["delegations"], "leaf/pin-other-target")["struct_hash_hex"])),
    ("erc7710-leaf-salt-v1.json", "a pin on approve binding",
     lambda v: _set(_named(v["cases"], "pin-approve")["expect"]["chains"][0],
                    binding=_named(v["delegations"], "leaf/pin-approve")["struct_hash_hex"])),
    ("erc7710-leaf-salt-v1.json", "a payment's chain",
     lambda v: _set(_named(v["cases"], "one-payment")["expect"]["payments"][0], chain="eip155:1")),
    ("erc7710-leaf-salt-v1.json", "a RedeemedDelegation byte",
     lambda v: _set(_named(v["cases"], "one-payment")["receipt"]["logs"][-1],
                    data_hex=_flip(_named(v["cases"], "one-payment")["receipt"]["logs"][-1]["data_hex"], 100))),
    ("erc7710-leaf-salt-v1.json", "the re-pay leaf given the first leaf's identity",
     lambda v: _set(v["repay"], second_case=v["repay"]["first_case"])),
    ("erc7710-leaf-salt-v1.json", "another delegation manager listed",
     lambda v: _set(v["config"]["delegation_managers"][0], delegation_manager_hex="00" * 20)),
]


def self_test() -> int:
    """Run the checks on mutated copies of the delegated-spend fixtures; each must fail."""
    import contextlib
    import copy
    import io

    checks = {"erc7710-statements.json": check_delegated_spend_statements, "payment-nonce.json": check_payment_nonce,
              "erc7710-leaf-salt-v1.json": check_leaf_salt}
    missed = 0
    for name, what, mutate in SELF_TEST_MUTATIONS:
        fixture = copy.deepcopy(load(name))
        mutate(fixture)
        _MUTATED[name] = fixture
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                found = checks[name]()
        except (ValueError, KeyError, IndexError, TypeError, StopIteration):
            found = 1
        finally:
            del _MUTATED[name]
        if not found:
            print(f"self-test: {name}: {what}: the checker reported nothing")
            missed += 1
    print(f"{'FAIL' if missed else 'OK'}: self-test, {len(SELF_TEST_MUTATIONS) - missed} of "
          f"{len(SELF_TEST_MUTATIONS)} mutations caught")
    return 1 if missed else 0


def main() -> int:
    if sys.argv[1:] == ["--self-test"]:
        return self_test()
    bad = check_leaf_vectors() + check_grant_vectors() + check_voucher_vector() + check_ks256_low_s_vector()
    bad += check_delegated_spend_statements() + check_payment_nonce() + check_leaf_salt()
    if os.path.exists(os.path.join(FIXTURES, "grant_vectors_negative.json")):
        bad += check_negative_vectors()
    else:
        print("grant_vectors_negative.json: missing")
        bad += 1
    print(f"{'FAIL' if bad else 'OK'}: {bad} problem(s) in vectors/fixtures")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
