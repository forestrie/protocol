#!/usr/bin/env python3
"""Generate the delegated-spend fixtures under vectors/fixtures/.

    gen-delegated-spend-vectors.py          write the fixtures
    gen-delegated-spend-vectors.py --check  exit 1 if a fixture would change

Standard library only, and deterministic: every key is keccak256 of a label
reduced mod n, every signature is RFC 6979, so rerunning reproduces the bytes.
The encoding primitives come from scripts/check-vectors.py; the expected
results below are written out by hand from the specification, and
check-vectors.py recomputes each one from the bytes independently of this
file.

- erc7710-statements.json: spec/delegated-spend-statements.md
"""
import hashlib
import hmac
import importlib.util
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURES = os.path.join(ROOT, "vectors", "fixtures")

sys.dont_write_bytecode = True  # importing check-vectors.py must leave no __pycache__ behind
_spec = importlib.util.spec_from_file_location("check_vectors", os.path.join(ROOT, "scripts", "check-vectors.py"))
cv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cv)

LABEL_PREFIX = "protocol vectors delegated spend: "

# The payment chain the vectors use: Base Sepolia, its USDC, and the
# MetaMask Delegation Framework v1.3.0 deployments, which share one address
# on every chain the framework is deployed to.
CHAIN_ID = 84532
USDC = bytes.fromhex("036cbd53842c5426634e7929541ec2318f3dcf7e")
MANAGER = bytes.fromhex("db9b1e94b5b69df7e401ddbede43491141047db3")
EXACT_EXECUTION = bytes.fromhex("146713078d39ecc1f5338309c28405ccf85abfbb")
LIMITED_CALLS = bytes.fromhex("04658b29f6b82ed55274221a06fc97d318e25416")
TIMESTAMP = bytes.fromhex("1046bb45c8d673d4ea75321280db34899413c069")
ERC20_TRANSFER_AMOUNT = bytes.fromhex("f100b0819427117ecf76ed94b358b1a5b5c6d2fc")


def rfc6979_sign(d: int, digest: bytes):
    """Deterministic secp256k1 ECDSA (RFC 6979, HMAC-SHA256), normalised to low s."""
    x = d.to_bytes(32, "big")
    h = (int.from_bytes(digest, "big") % cv.K1_N).to_bytes(32, "big")
    v, k_ = b"\x01" * 32, b"\x00" * 32
    k_ = hmac.new(k_, v + b"\x00" + x + h, hashlib.sha256).digest()
    v = hmac.new(k_, v, hashlib.sha256).digest()
    k_ = hmac.new(k_, v + b"\x01" + x + h, hashlib.sha256).digest()
    v = hmac.new(k_, v, hashlib.sha256).digest()
    while True:
        v = hmac.new(k_, v, hashlib.sha256).digest()
        k = int.from_bytes(v, "big")
        if 1 <= k < cv.K1_N:
            pt = cv.k1_mul(k, cv.K1_G)
            r = pt[0] % cv.K1_N
            s = pow(k, -1, cv.K1_N) * (int.from_bytes(digest, "big") + r * d) % cv.K1_N
            if r and s and pt[0] < cv.K1_N:
                recid = pt[1] & 1
                if s > cv.K1_HALF_N:
                    s, recid = cv.K1_N - s, recid ^ 1
                return r, s, recid
        k_ = hmac.new(k_, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k_, v, hashlib.sha256).digest()


class Key:
    def __init__(self, role: str):
        self.label = LABEL_PREFIX + role
        self.d = int.from_bytes(cv.keccak256(self.label.encode()), "big") % cv.K1_N
        self.address = cv.k1_address(cv.k1_mul(self.d, cv.K1_G))

    def sign(self, digest: bytes, v_offset: int) -> bytes:
        r, s, recid = rfc6979_sign(self.d, digest)
        return r.to_bytes(32, "big") + s.to_bytes(32, "big") + bytes([recid + v_offset])

    def json(self):
        return {"label": self.label, "private_key_d_hex": f"{self.d:064x}", "address_hex": self.address.hex()}


class Account:
    """An address nobody holds a key for in these vectors."""

    def __init__(self, role: str):
        self.label = LABEL_PREFIX + role
        self.address = cv.keccak256(self.label.encode())[12:]

    def json(self):
        return {"label": self.label, "address_hex": self.address.hex()}


def log_id(role: str) -> bytes:
    """A log id in the 32-byte wire form: a 16-byte id in the low bytes."""
    return b"\x00" * 16 + hashlib.sha256((LABEL_PREFIX + role).encode()).digest()[:16]


KEYS = {r: Key(r) for r in (
    "human root owner", "human statement key", "agent A spending key", "agent A statement key",
    "agent B spending key", "agent B statement key", "agent B gas account",
    "stranger spending key", "stranger gas account", "stranger statement key",
)}
ACCOUNTS = {r: Account(r) for r in (
    "human root account", "payee", "published enforcer (test deployment)",
    "univocity instance (test deployment)", "unlisted delegation manager", "second root account",
)}
W_H = ACCOUNTS["human root account"].address
PAYEE = ACCOUNTS["payee"].address
PUBLISHED_ENFORCER = ACCOUNTS["published enforcer (test deployment)"].address
INSTANCE = ACCOUNTS["univocity instance (test deployment)"].address
L_H, L_A, L_B = log_id("log L_H"), log_id("log L_A"), log_id("log L_B")


def published_terms(instance: bytes, log: bytes) -> bytes:
    return cv.addr_word(instance) + log


def u128(n: int) -> bytes:
    return n.to_bytes(16, "big")


class Delegation:
    def __init__(self, name, delegate, delegator, authority, caveats, salt, signer: Key, delegator_kind, note):
        self.name, self.delegate, self.delegator, self.authority = name, delegate, delegator, authority
        self.caveats, self.salt, self.signer, self.delegator_kind, self.note = caveats, salt, signer, delegator_kind, note
        self.struct_hash = cv.delegation_struct_hash(delegate, delegator, authority, [(e, t) for e, t, _ in caveats], salt)
        self.domain = cv.eip712_domain_separator(CHAIN_ID, MANAGER)
        self.digest = cv.keccak256(b"\x19\x01" + self.domain + self.struct_hash)
        self.signature = signer.sign(self.digest, 27)

    def hop(self) -> dict:
        return {"delegate": self.delegate, "delegator": self.delegator, "authority": self.authority,
                "caveats": [(e, t) for e, t, _ in self.caveats], "salt": self.salt, "signature": self.signature}

    def json(self):
        return {
            "name": self.name, "note": self.note, "chain_id": CHAIN_ID, "delegation_manager_hex": MANAGER.hex(),
            "delegate_hex": self.delegate.hex(), "delegator_hex": self.delegator.hex(),
            "delegator_kind": self.delegator_kind, "authority_hex": self.authority.hex(),
            "caveats": [{"enforcer_hex": e.hex(), "terms_hex": t.hex(), "note": n} for e, t, n in self.caveats],
            "salt_hex": self.salt.hex(), "signer": self.signer.label, "signature_hex": self.signature.hex(),
            "struct_hash_hex": self.struct_hash.hex(), "domain_separator_hex": self.domain.hex(),
            "typed_data_digest_hex": self.digest.hex(),
        }


D_HA = Delegation(
    "D_HA", KEYS["agent A spending key"].address, W_H, cv.ROOT_AUTHORITY,
    [
        (PUBLISHED_ENFORCER, published_terms(INSTANCE, L_H), "publication caveat: abi.encode(instance, L_H)"),
        (ERC20_TRANSFER_AMOUNT, USDC + cv.u256(5_000_000), "ERC20TransferAmountEnforcer: USDC, at most 5 USDC in all"),
        (TIMESTAMP, u128(0) + u128(1_798_761_600), "TimestampEnforcer: usable until 2027-01-01T00:00:00Z"),
    ],
    cv.u256(1), KEYS["human root owner"], "contract",
    "the root hop, from the human's smart account to agent A's spending key; the account checks its "
    "owner's signature (ERC-1271), so it recovers to the owner, not to the delegator",
)
D_AB = Delegation(
    "D_AB", KEYS["agent B spending key"].address, KEYS["agent A spending key"].address, D_HA.struct_hash,
    [
        (PUBLISHED_ENFORCER, published_terms(INSTANCE, L_A), "publication caveat: abi.encode(instance, L_A)"),
        (ERC20_TRANSFER_AMOUNT, USDC + cv.u256(1_000_000), "ERC20TransferAmountEnforcer: USDC, at most 1 USDC in all"),
        (TIMESTAMP, u128(0) + u128(1_796_083_200), "TimestampEnforcer: usable until 2026-12-01T00:00:00Z"),
    ],
    cv.u256(1), KEYS["agent A spending key"], "eoa",
    "a reusable hop from agent A to agent B, signed by A's spending key, narrower than D_HA",
)
DELEGATIONS = [D_HA, D_AB]

INTENT_DOCUMENT = (
    '{"natural_language_description":"Pay registration fees and buy research for the '
    'household accounts project","intent_expiry":"2027-01-01T00:00:00Z","requires_refundability":true}'
)


def sign_statement(protected: bytes, payload: bytes, key: Key) -> bytes:
    sig_structure = cv.cbor_encode(["Signature1", protected, b"", payload])
    return cv.cbor_encode([protected, {}, payload, key.sign(cv.keccak256(sig_structure), 0)])


def delegation_statement(name, d: Delegation, signer: Key, delegate_log: bytes, depth: int, purpose: dict,
                         idtimestamp: bytes, anchor: bytes = None, note: str = ""):
    """A delegation statement; `anchor` overrides key 2's hash for the malformed audit cases."""
    anchor = d.struct_hash if anchor is None else anchor
    payload = {1: 1, 2: cv.DELEGATION_TAG + anchor, 3: CHAIN_ID, 4: MANAGER, 5: cv.hop_array(d.hop()),
               6: delegate_log, 7: depth, 10: cv.purpose_map(purpose)}
    protected = cv.statement_protected("delegation", signer.address, signer.address.hex(), anchor.hex())
    data = sign_statement(protected, cv.cbor_encode(payload), signer)
    off = data.find(cv.DELEGATION_TAG + anchor)
    entry = {
        "name": name, "type": "delegation", "note": note, "signer": signer.label,
        "fields": {"chain_id": CHAIN_ID, "delegation_manager_hex": MANAGER.hex(), "delegation": d.name,
                   "delegate_log_id_hex": delegate_log.hex(), "depth": depth, "purpose": purpose},
        "cose_sign1_hex": data.hex(),
        "publication": {
            "delegation_hash_hex": anchor.hex(), "prefix_hex": data[:off].hex(), "suffix_hex": data[off + 64:].hex(),
            "idtimestamp_hex": idtimestamp.hex(),
            "leaf_hex": hashlib.sha256(idtimestamp + hashlib.sha256(data).digest()).hexdigest(),
        },
    }
    return entry, data, off


def statements_fixture():
    st_ha, _, _ = delegation_statement(
        "delegation/D_HA", D_HA, KEYS["human statement key"], L_A, 3,
        {"description": "Agent A pays registration fees and buys research, up to 5 USDC",
         "intent_digest_hex": hashlib.sha256(INTENT_DOCUMENT.encode()).hexdigest()},
        bytes.fromhex("019a8f6e2c000001"),
        note="the root hop, published in the human's authority log L_H by the human's statement key",
    )
    st_ab, ab_bytes, ab_off = delegation_statement(
        "delegation/D_AB", D_AB, KEYS["agent A statement key"], L_B, 2,
        {"description": "Agent B pays the registration fees of log L_B"},
        bytes.fromhex("019a8f7a11000003"),
        note="a reusable hop, published in agent A's log L_A by A's statement key, never its spending key",
    )
    a_stmt = KEYS["agent A statement key"]
    _, mismatch, mm_off = delegation_statement(
        "", D_AB, a_stmt, L_B, 2, {"description": "Agent B pays the registration fees of log L_B"},
        b"\x00" * 8, anchor=D_HA.struct_hash,
    )
    _, digest_case, dg_off = delegation_statement(
        "", D_AB, a_stmt, L_B, 2, {"description": "Agent B pays the registration fees of log L_B"},
        b"\x00" * 8, anchor=D_AB.digest,
    )
    stranger = KEYS["stranger statement key"]
    other_payload = b"a statement of another type that quotes " + cv.DELEGATION_TAG + D_AB.struct_hash
    other = sign_statement(
        cv.cbor_encode({1: cv.KS256_ALG, 3: "application/octet-stream", 4: stranger.address}), other_payload, stranger
    )
    other_off = other.find(cv.DELEGATION_TAG)

    def pub(off, h, verdict, key):
        return {"offset": off, "hash_hex": h.hex(), "verdict": verdict, "signer_hex": key.address.hex()}

    audit_cases = [
        {"name": "well-formed/D_AB", "rule": "1b",
         "note": "TAG ‖ H at key 2 of a delegation statement, H the struct hash of the hop at key 5",
         "cose_sign1_hex": ab_bytes.hex(),
         "expect": {"publications": [pub(ab_off, D_AB.struct_hash, "well-formed", a_stmt)]}},
        {"name": "flag/hash-mismatch", "rule": "1b",
         "note": "key 2 publishes D_HA while key 5 shows the terms of D_AB: it publishes D_HA, and auditors flag it",
         "cose_sign1_hex": mismatch.hex(),
         "expect": {"publications": [pub(mm_off, D_HA.struct_hash, "flag:hash-mismatch", a_stmt)]}},
        {"name": "flag/signed-digest-not-struct-hash", "rule": "1b",
         "note": "key 2 carries the EIP-712 digest D_AB's delegator signed instead of its struct hash: it publishes "
                 "a value no delegation manager ever hands an enforcer, so D_AB stays unpublished",
         "cose_sign1_hex": digest_case.hex(),
         "expect": {"publications": [pub(dg_off, D_AB.digest, "flag:hash-mismatch", a_stmt)]}},
        {"name": "flag/tag-in-another-statement-type", "rule": "1b",
         "note": "a statement of another content type, signed by someone else with a grant to the log, quotes "
                 "TAG ‖ H(D_AB): it still publishes D_AB, and auditors flag it and attribute it to its signer",
         "cose_sign1_hex": other.hex(),
         "expect": {"publications": [pub(other_off, D_AB.struct_hash, "flag:outside-key-2", stranger)]}},
    ]
    return {
        "version": 1,
        "description": "ERC-7710 delegation, revocation and spend statements (spec/delegated-spend-statements.md): "
                       "the delegation hash a statement must carry, the statement bytes, the leaf the publication "
                       "enforcer rebuilds from them, and how auditors classify every TAG ‖ H they find.",
        "generator": "scripts/gen-delegated-spend-vectors.py (standard library, RFC 6979). Deterministic: "
                     "rerunning gives these bytes.",
        "conventions": {
            "hex": "unprefixed lowercase",
            "delegation_tag_label": cv.DELEGATION_TAG_LABEL,
            "delegation_tag_hex": cv.DELEGATION_TAG.hex(),
            "delegation_typehash_hex": cv.DELEGATION_TYPEHASH.hex(),
            "caveat_typehash_hex": cv.CAVEAT_TYPEHASH.hex(),
            "root_authority_hex": cv.ROOT_AUTHORITY.hex(),
            "any_delegate_hex": cv.ANY_DELEGATE.hex(),
            "content_types": cv.CONTENT_TYPES,
            "framework": "MetaMask Delegation Framework v1.3.0; EIP-712 domain name DelegationManager, version 1",
            "delegation_signature": "65 bytes r || s || v, v 27 or 28, low s, over the typed-data digest",
            "statement_signature": "KS256: 65 bytes r || s || v, v the recovery id 0 or 1, low s",
            "cose_sign1": "untagged, empty unprotected header, attached payload",
            "test_key": "private_key_d_hex is keccak256 of the label, reduced mod n; a test scalar, never a "
                        "deployed key",
            "account": "address_hex is the low 20 bytes of keccak256 of the label; nobody holds its key",
            "intent_document": INTENT_DOCUMENT,
        },
        "keys": [k.json() for k in KEYS.values()],
        "accounts": [a.json() for a in ACCOUNTS.values()],
        "delegations": [d.json() for d in DELEGATIONS],
        "statements": [st_ha, st_ab],
        "audit_cases": audit_cases,
    }


FIXTURE_BUILDERS = {
    "erc7710-statements.json": statements_fixture,
}


def main() -> int:
    check = "--check" in sys.argv[1:]
    changed = 0
    for name, build in FIXTURE_BUILDERS.items():
        text = json.dumps(build(), indent=2, ensure_ascii=False) + "\n"
        path = os.path.join(FIXTURES, name)
        old = open(path, encoding="utf-8").read() if os.path.exists(path) else None
        if old != text:
            changed += 1
            if check:
                print(f"{name}: would change")
            else:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(text)
                print(f"{name}: written")
    return 1 if check and changed else 0


if __name__ == "__main__":
    sys.exit(main())
