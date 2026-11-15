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
- payment-nonce.json: spec/payment-nonce-and-binding.md section 2
- erc7710-leaf-salt-v1.json: spec/payment-nonce-and-binding.md section 3
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
    "human root account", "payee", "seller", "published enforcer (test deployment)",
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

GOLDEN_GRANT = "golden grant (all fields, fixed-length left-padded)"
ONBOARDING_REQUEST_ID = "0b6e8f62-4d1a-4c8e-9f3b-7a2d5c1e9b40"
INSTANCE_ID = f"eip155:{CHAIN_ID}:0x{INSTANCE.hex()}"
SECOND_ROOT = ACCOUNTS["second root account"].address


def grant_payload() -> bytes:
    return cv.encode_grant_payload(next(g for g in cv.load("grant_vectors.json") if g["description"] == GOLDEN_GRANT))


def nonce_entry(name, kind, purpose, payer, note):
    digest = cv.purpose_digest(kind, purpose)
    preimage = cv.payment_nonce_preimage(kind, digest, payer)
    e = {"name": name, "kind": kind, "note": note, "purpose": purpose, "payer_hex": payer.hex()}
    if kind == "credits":
        e["purchase_id_hex"] = hashlib.sha256(purpose["idempotency_key"].encode()).hexdigest()
    e.update({"purpose_digest_hex": digest.hex(), "preimage_hex": preimage.hex(),
              "nonce_hex": hashlib.sha256(preimage).hexdigest()})
    return e


def nonce(name: str) -> bytes:
    return bytes.fromhex(next(e for e in NONCES if e["name"] == name)["nonce_hex"])


GRANT_PURPOSE = {"from_grant_vector": GOLDEN_GRANT, "grant_hex": grant_payload().hex()}
CREDITS_PURPOSE = {"univocity_instance_id": INSTANCE_ID, "credits": 100,
                   "idempotency_key": "5f1c7a3e-2b9d-4e60-8a4f-c3d2b1e0f987"}
NONCES = [
    nonce_entry("grant", "grant", GRANT_PURPOSE, W_H,
                "the inner grant in payload form, keys 1 to 6, as a Forestrie-Grant carries it at -65538"),
    nonce_entry("grant/another-payer", "grant", GRANT_PURPOSE, SECOND_ROOT,
                "the same grant paid from another root: another nonce, so each payer claims its own"),
    nonce_entry("onboarding", "onboarding", {"request_id": ONBOARDING_REQUEST_ID}, W_H,
                "the onboarding request id, as the registration service issued it"),
    nonce_entry("credits", "credits", CREDITS_PURPOSE, W_H,
                "100 credits for the test instance, purchase id SHA-256 of the Idempotency-Key"),
    nonce_entry("credits/another-purchase", "credits",
                dict(CREDITS_PURPOSE, idempotency_key="a2e4c6f8-1b3d-4f5a-9c7e-0d2f4b6a8c1e"), W_H,
                "the same count for the same instance under another Idempotency-Key: a distinct purchase"),
]




def transfer_pin(recipient: bytes, amount: int) -> bytes:
    """ExactExecutionEnforcer terms: USDC, value 0, transfer(recipient, amount), packed."""
    return USDC + cv.u256(0) + bytes.fromhex("a9059cbb") + cv.addr_word(recipient) + cv.u256(amount)


PRICE = 10_000  # 0.01 USDC, in base units
PIN = (EXACT_EXECUTION, transfer_pin(PAYEE, PRICE), "ExactExecutionEnforcer: USDC, value 0, transfer(payee, 10000)")
CALL_LIMIT = (LIMITED_CALLS, cv.u256(1), "LimitedCallsEnforcer: 1")


def payment_leaf(name, salt_name, authority, caveats=(PIN, CALL_LIMIT), note=""):
    return Delegation(name, cv.ANY_DELEGATE, KEYS["agent B spending key"].address, authority, list(caveats),
                      nonce(salt_name), KEYS["agent B spending key"], "eoa", note)


LEAF_CREDITS = payment_leaf(
    "leaf/credits", "credits", D_AB.struct_hash,
    note="a payment leaf beneath D_AB: open delegate, the exact transfer, one call, the credits nonce as salt",
)
SELLER = ACCOUNTS["seller"].address
LEAF_SELLER = Delegation(
    "leaf/seller", cv.ANY_DELEGATE, KEYS["agent B spending key"].address, D_AB.struct_hash,
    [(EXACT_EXECUTION, transfer_pin(SELLER, 250_000), "ExactExecutionEnforcer: USDC, value 0, transfer(seller, 250000)"),
     CALL_LIMIT],
    hashlib.sha256(b"seller order 7731").digest(), KEYS["agent B spending key"], "eoa",
    "a payment leaf for a seller; a seller's payment carries no payment nonce",
)


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


def plain_statement(name, statement_type, signer: Key, fields: dict, note: str, paid_by=None,
                    unprotected=None):
    """A revocation or spend statement; `unprotected` only for the refused audit case."""
    payload = {1: 1, 3: CHAIN_ID, 4: MANAGER, 8: bytes.fromhex(fields["delegation_hash_hex"])}
    if "transaction_hash_hex" in fields:
        payload[9] = bytes.fromhex(fields["transaction_hash_hex"])
    if statement_type == "revocation":
        payload[11] = fields["reason"]
    else:
        payload[10] = cv.purpose_map(fields["purpose"])
    protected = cv.statement_protected(statement_type, signer.address, signer.address.hex(),
                                       fields["delegation_hash_hex"])
    payload_bytes = cv.cbor_encode(payload)
    sig_structure = cv.cbor_encode(["Signature1", protected, b"", payload_bytes])
    data = cv.cbor_encode([protected, unprotected or {}, payload_bytes, signer.sign(cv.keccak256(sig_structure), 0)])
    entry = {"name": name, "type": statement_type, "note": note, "signer": signer.label,
             "fields": dict({"chain_id": CHAIN_ID, "delegation_manager_hex": MANAGER.hex()}, **fields)}
    if paid_by:
        entry["paid_by"] = paid_by
    entry["cose_sign1_hex"] = data.hex()
    return entry, data


ONE_PAYMENT_TX = cv.keccak256(b"protocol vectors delegated spend: the one-payment transaction")
DISABLE_TX = cv.keccak256(b"protocol vectors delegated spend: the disableDelegation(D_AB) transaction")
SELLER_TX = cv.keccak256(b"protocol vectors delegated spend: the seller payment transaction")
CREDITS_DIGEST = cv.purpose_digest("credits", CREDITS_PURPOSE)


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

    b_stmt = KEYS["agent B statement key"]
    st_revoke, _ = plain_statement(
        "revocation/D_AB", "revocation", a_stmt,
        {"delegation_hash_hex": D_AB.struct_hash.hex(), "transaction_hash_hex": DISABLE_TX.hex(),
         "reason": "Agent B's task is finished"},
        "agent A records, in L_A, that it disabled D_AB on chain; the revoked hash is bare",
    )
    st_spend, _ = plain_statement(
        "spend/credits", "spend", b_stmt,
        {"delegation_hash_hex": LEAF_CREDITS.struct_hash.hex(), "transaction_hash_hex": ONE_PAYMENT_TX.hex(),
         "purpose": {"kind": 3, "digest_hex": CREDITS_DIGEST.hex(), "description": "100 credits for the test instance"}},
        "agent B records, in L_B, the payment leaf/credits made; amount, asset and payee are read from the "
        "transaction, and the purpose digest is the credits nonce's",
        paid_by={"delegation": LEAF_CREDITS.name, "root_hex": W_H.hex()},
    )
    st_seller, _ = plain_statement(
        "spend/seller", "spend", b_stmt,
        {"delegation_hash_hex": LEAF_SELLER.struct_hash.hex(), "transaction_hash_hex": SELLER_TX.hex(),
         "purpose": {"kind": 4, "digest_hex": hashlib.sha256(b"seller order 7731").hexdigest(),
                     "description": "A research report"}},
        "agent B records a purchase from a seller; the purpose digest is the seller's reference for what was bought",
    )
    _, tagged_spend = plain_statement(
        "", "spend", b_stmt,
        {"delegation_hash_hex": LEAF_CREDITS.struct_hash.hex(), "transaction_hash_hex": ONE_PAYMENT_TX.hex(),
         "purpose": {"kind": 3, "digest_hex": CREDITS_DIGEST.hex()}},
        "", unprotected={-70000: cv.DELEGATION_TAG + D_AB.struct_hash},
    )
    ts_off = tagged_spend.find(cv.DELEGATION_TAG)

    def pub(off, h, verdict, key):
        return {"offset": off, "hash_hex": h.hex(), "verdict": verdict, "signer_hex": key.address.hex()}

    audit_cases = [
        {"name": "well-formed/D_AB", "rule": "1b",
         "note": "TAG ‖ H at key 2 of a delegation statement, H the struct hash of the hop at key 5",
         "cose_sign1_hex": ab_bytes.hex(),
         "expect": {"publications": [pub(ab_off, D_AB.struct_hash, "well-formed", a_stmt)], "route": "accepted"}},
        {"name": "flag/hash-mismatch", "rule": "1b",
         "note": "key 2 publishes D_HA while key 5 shows the terms of D_AB: it publishes D_HA, and auditors flag it",
         "cose_sign1_hex": mismatch.hex(),
         "expect": {"publications": [pub(mm_off, D_HA.struct_hash, "flag:hash-mismatch", a_stmt)],
                    "route": "accepted"}},
        {"name": "flag/signed-digest-not-struct-hash", "rule": "1b",
         "note": "key 2 carries the EIP-712 digest D_AB's delegator signed instead of its struct hash: it publishes "
                 "a value no delegation manager ever hands an enforcer, so D_AB stays unpublished",
         "cose_sign1_hex": digest_case.hex(),
         "expect": {"publications": [pub(dg_off, D_AB.digest, "flag:hash-mismatch", a_stmt)], "route": "accepted"}},
        {"name": "flag/tag-in-another-statement-type", "rule": "1b",
         "note": "a statement of another content type, signed by someone else with a grant to the log, quotes "
                 "TAG ‖ H(D_AB): it still publishes D_AB, and auditors flag it and attribute it to its signer",
         "cose_sign1_hex": other.hex(),
         "expect": {"publications": [pub(other_off, D_AB.struct_hash, "flag:outside-key-2", stranger)],
                    "route": "accepted"}},
        {"name": "refuse/spend-with-tag", "rule": "1a",
         "note": "a spend statement whose unprotected header carries TAG ‖ H(D_AB): the registration service "
                 "refuses it on its route; were it anchored anyway, it would publish D_AB and auditors would flag it",
         "cose_sign1_hex": tagged_spend.hex(),
         "expect": {"publications": [pub(ts_off, D_AB.struct_hash, "flag:outside-key-2", b_stmt)],
                    "route": "refused:tag-present"}},
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
            "cose_sign1": "untagged, attached payload, empty unprotected header except in refuse/spend-with-tag",
            "test_key": "private_key_d_hex is keccak256 of the label, reduced mod n; a test scalar, never a "
                        "deployed key",
            "account": "address_hex is the low 20 bytes of keccak256 of the label; nobody holds its key",
            "intent_document": INTENT_DOCUMENT,
        },
        "keys": [k.json() for k in KEYS.values()],
        "accounts": [a.json() for a in ACCOUNTS.values()],
        "delegations": [d.json() for d in DELEGATIONS + [LEAF_CREDITS, LEAF_SELLER]],
        "statements": [st_ha, st_ab, st_revoke, st_spend, st_seller],
        "audit_cases": audit_cases,
    }


def payment_nonce_fixture():
    grant_digest = cv.purpose_digest("grant", GRANT_PURPOSE)
    earlier = b"forestrie/mcp-register x402 grant payment nonce v1" + b"\x00" + grant_digest + W_H
    kind4 = cv.PAYMENT_NONCE_TAG + b"\x04" + grant_digest + W_H
    return {
        "version": 1,
        "description": "The payment nonce (spec/payment-nonce-and-binding.md section 2): SHA-256 over a tag, the "
                       "purpose's kind, its digest and the payer, for each kind, with preimages that no request "
                       "can ever derive.",
        "generator": "scripts/gen-delegated-spend-vectors.py. Deterministic: rerunning gives these bytes.",
        "conventions": {
            "hex": "unprefixed lowercase",
            "tag_utf8": cv.PAYMENT_NONCE_TAG.decode(),
            "kinds": cv.PAYMENT_KINDS,
            "preimage": "tag (26 bytes) || kind (1 byte) || purpose digest (32 bytes) || payer (20 bytes): 79 bytes",
            "payer": "the account the USDC leaves: the root delegator of a delegated payment, from of an EIP-3009 one",
        },
        "vectors": NONCES,
        "not_canonical": [
            {"name": "earlier-grant-nonce", "preimage_hex": earlier.hex(),
             "salt_hex": hashlib.sha256(earlier).hexdigest(),
             "reason": "the tag of an earlier, tool-specific grant nonce: no request derives a nonce from it"},
            {"name": "kind-outside-1-to-3", "preimage_hex": kind4.hex(),
             "salt_hex": hashlib.sha256(kind4).hexdigest(),
             "reason": "the canonical tag with kind 4, which names no purpose"},
        ],
    }


# erc7710-leaf-salt/v1 receipts. Each log is built by name, and each case's
# expectations name the logs and delegations they mean; positions come from
# where each named log lands in its receipt.
LEAF_KEYS = {r: Key(r) for r in ("agent B second spending key", "agent B gas account",
                                 "stranger spending key", "stranger gas account")}
UNLISTED_MANAGER = ACCOUNTS["unlisted delegation manager"].address
GAS_B, GAS_STRANGER = LEAF_KEYS["agent B gas account"].address, LEAF_KEYS["stranger gas account"].address
B_SPEND, B_SPEND_2 = KEYS["agent B spending key"], LEAF_KEYS["agent B second spending key"]
STRANGER = LEAF_KEYS["stranger spending key"]


def leaf(name, salt_name, authority=None, caveats=(PIN, CALL_LIMIT), signer=B_SPEND, note=""):
    return Delegation(name, cv.ANY_DELEGATE, signer.address, D_AB.struct_hash if authority is None else authority,
                      list(caveats), nonce(salt_name), signer, "eoa", note)


def timestamp_until(t: int, label: str):
    return (TIMESTAMP, u128(0) + u128(t), f"TimestampEnforcer: usable until {label}")


H_B = Delegation(
    "hop/B-salted", B_SPEND_2.address, B_SPEND.address, D_AB.struct_hash, [PIN, CALL_LIMIT],
    nonce("grant"), B_SPEND, "eoa",
    "an intermediate hop agent B salts with the grant nonce and pins the transfer, above a salted leaf",
)
LEAVES = {d.name: d for d in (
    leaf("leaf/grant", "grant", note="pins the transfer, one call, the grant nonce as salt"),
    LEAF_CREDITS,
    leaf("leaf/no-call-limit", "grant", caveats=(PIN,), note="pins the transfer and carries no call limit"),
    leaf("leaf/under-salted-hop", "credits", authority=H_B.struct_hash, signer=B_SPEND_2,
         note="a leaf beneath hop/B-salted, the credits nonce as salt"),
    leaf("leaf/repay-1", "onboarding", caveats=(PIN, CALL_LIMIT, timestamp_until(1_795_000_000, "2026-11-18T09:46:40Z")),
         note="a leaf for the onboarding nonce whose payment was refunded"),
    leaf("leaf/repay-2", "onboarding", caveats=(PIN, CALL_LIMIT, timestamp_until(1_795_003_600, "2026-11-18T10:46:40Z")),
         note="the re-pay leaf: the same nonce, another TimestampEnforcer bound, so another delegation hash"),
    H_B,
)}
STRANGER_CHILD = Delegation(
    "child/stranger", GAS_STRANGER, STRANGER.address, LEAF_CREDITS.struct_hash, [PIN, CALL_LIMIT],
    nonce("grant"), STRANGER, "eoa",
    "a stranger's child beneath the open leaf/credits, salted with a nonce of its own choosing",
)
LEAVES[STRANGER_CHILD.name] = STRANGER_CHILD


def topic_address(a: bytes) -> str:
    return cv.addr_word(a).hex()


def event_args(d, args=None):
    h = d.hop()
    h["caveats"] = [(e, t, (args or {}).get(i, b"")) for i, (e, t) in enumerate(h["caveats"])]
    return h


def rd_log(d, root, redeemer, manager=MANAGER, args=None):
    return {"address_hex": manager.hex(),
            "topics_hex": [cv.REDEEMED_DELEGATION_TOPIC.hex(), topic_address(root), topic_address(redeemer)],
            "data_hex": cv.abi_encode_delegation(event_args(d, args)).hex()}


def transfer_log(sender, to, amount):
    return {"address_hex": USDC.hex(), "topics_hex": [cv.TRANSFER_TOPIC.hex(), topic_address(sender), topic_address(to)],
            "data_hex": cv.u256(amount).hex()}


def authorization_used_log(authorizer, auth_nonce):
    return {"address_hex": USDC.hex(),
            "topics_hex": [cv.AUTHORIZATION_USED_TOPIC.hex(), topic_address(authorizer), auth_nonce.hex()],
            "data_hex": ""}


def increased_count_log(d, redeemer):
    topic = cv.keccak256(b"IncreasedCount(address,address,bytes32,uint256,uint256)")
    return {"address_hex": LIMITED_CALLS.hex(),
            "topics_hex": [topic.hex(), topic_address(MANAGER), topic_address(redeemer), d.struct_hash.hex()],
            "data_hex": (cv.u256(1) + cv.u256(1)).hex()}


def chain_logs(prefix, chain, redeemer, manager=MANAGER):
    """The RedeemedDelegation logs of one redeemed chain, leaf first, as the manager emits them."""
    return [(f"{prefix}:{d.name}", rd_log(d, W_H, redeemer, manager)) for d in chain]


def case(name, note, named_logs, expect, requests):
    positions = {n: i for i, (n, _) in enumerate(named_logs)}

    def hashes(names):
        return [LEAVES.get(n, {"D_AB": D_AB, "D_HA": D_HA}.get(n)).struct_hash.hex() for n in names]

    def d(n):
        return LEAVES.get(n) or {"D_AB": D_AB, "D_HA": D_HA}[n]

    out = {
        "eip3009_transfers": [positions[n] for n in expect.get("eip3009", [])],
        "chains": [{"root_hex": W_H.hex(), "delegations": hashes(c), "binding": d(b).struct_hash.hex() if b else None}
                   for c, b in expect.get("chains", [])],
        "pairs": [{"binding": d(b).struct_hash.hex(), "transfer_position": positions[t]}
                  for b, t in expect.get("pairs", [])],
        "unpaired_bindings": hashes(expect.get("unpaired", [])),
        "payments": [{"delegation_manager_hex": MANAGER.hex(), "delegation_hash_hex": d(b).struct_hash.hex(),
                      "salt_hex": d(b).salt.hex(), "root_hex": W_H.hex(), "amount": amount,
                      "transfer_position": positions[t]} for b, t, amount in expect.get("payments", [])],
        "unbound_transfers": [positions[n] for n in expect.get("unbound", [])],
    }
    return {"name": name, "note": note, "receipt": {"status": 1, "logs": [log for _, log in named_logs],
                                                    "log_names": [n for n, _ in named_logs]},
            "expect": out,
            "requests": [{"purpose": p, "binds": d(b).struct_hash.hex() if b else None} for p, b in requests]}


def redemption(prefix, chain, moves, redeemer=GAS_B, manager=MANAGER):
    """One redeemed chain: the call-limit count, the transfers the root's code makes, then the events."""
    logs = [(f"{prefix}:count", increased_count_log(chain[0], redeemer))] if CALL_LIMIT in chain[0].caveats else []
    logs += [(f"{prefix}:transfer{i}", transfer_log(W_H, PAYEE, a)) for i, a in enumerate(moves)]
    return logs, chain_logs(prefix, chain, redeemer, manager)


def leaf_salt_cases():
    L = LEAVES
    above = [D_AB, D_HA]
    c = []
    pre, ev = redemption("r", [L["leaf/credits"]] + above, [PRICE])
    c.append(case("one-payment", "one chain, one Transfer of the pinned amount from the root: one payment",
                  pre + [("other:transfer", transfer_log(SELLER, ACCOUNTS["second root account"].address, 5))] + ev,
                  {"chains": [(["leaf/credits", "D_AB", "D_HA"], "leaf/credits")],
                   "pairs": [("leaf/credits", "r:transfer0")],
                   "payments": [("leaf/credits", "r:transfer0", PRICE)], "unbound": []},
                  [("credits", "leaf/credits"), ("grant", None)]))
    p1, e1 = redemption("a", [L["leaf/grant"]] + above, [PRICE])
    p2, e2 = redemption("b", [L["leaf/credits"]] + above, [PRICE])
    c.append(case("two-payments-one-root",
                  "two chains from one root in one transaction, each moving its pinned amount: two payments, "
                  "each with its own identity and Transfer",
                  p1 + p2 + e1 + e2,
                  {"chains": [(["leaf/grant", "D_AB", "D_HA"], "leaf/grant"),
                              (["leaf/credits", "D_AB", "D_HA"], "leaf/credits")],
                   "pairs": [("leaf/grant", "a:transfer0"), ("leaf/credits", "b:transfer0")],
                   "payments": [("leaf/grant", "a:transfer0", PRICE), ("leaf/credits", "b:transfer0", PRICE)],
                   "unbound": []},
                  [("grant", "leaf/grant"), ("credits", "leaf/credits"), ("onboarding", None)]))
    pre, ev = redemption("r", [L["leaf/under-salted-hop"], H_B] + above, [PRICE], redeemer=GAS_B)
    c.append(case("salted-hop-above-salted-leaf",
                  "agent B salts its own hop and the leaf beneath it: only the hop, nearest the root, can bind",
                  pre + ev,
                  {"chains": [(["leaf/under-salted-hop", "hop/B-salted", "D_AB", "D_HA"], "hop/B-salted")],
                   "pairs": [("hop/B-salted", "r:transfer0")],
                   "payments": [("hop/B-salted", "r:transfer0", PRICE)], "unbound": []},
                  [("grant", "hop/B-salted"), ("credits", None)]))
    pre, ev = redemption("r", [STRANGER_CHILD, L["leaf/credits"]] + above, [PRICE], redeemer=GAS_STRANGER)
    c.append(case("stranger-extends-leaf",
                  "a stranger signs a child under the open leaf and redeems the chain: the leaf still binds",
                  pre + ev,
                  {"chains": [(["child/stranger", "leaf/credits", "D_AB", "D_HA"], "leaf/credits")],
                   "pairs": [("leaf/credits", "r:transfer0")],
                   "payments": [("leaf/credits", "r:transfer0", PRICE)], "unbound": []},
                  [("credits", "leaf/credits"), ("grant", None)]))
    pre, ev = redemption("r", [L["leaf/no-call-limit"]] + above, [PRICE])
    c.append(case("no-call-limit",
                  "a leaf salted with the nonce but without LimitedCallsEnforcer(1): it pairs and binds nothing, "
                  "so its Transfer is money nothing can bind",
                  pre + ev,
                  {"chains": [(["leaf/no-call-limit", "D_AB", "D_HA"], "leaf/no-call-limit")],
                   "pairs": [("leaf/no-call-limit", "r:transfer0")], "payments": [], "unbound": ["r:transfer0"]},
                  [("grant", None)]))
    p1, e1 = redemption("a", [L["leaf/no-call-limit"]] + above, [PRICE])
    p2, e2 = redemption("b", [L["leaf/credits"]] + above, [])
    c.append(case("no-call-limit-takes-part",
                  "a leaf without the call limit comes first in log order and takes the one Transfer, so the "
                  "leaf with the call limit pairs with nothing: the Transfer is counted once",
                  p1 + p2 + e1 + e2,
                  {"chains": [(["leaf/no-call-limit", "D_AB", "D_HA"], "leaf/no-call-limit"),
                              (["leaf/credits", "D_AB", "D_HA"], "leaf/credits")],
                   "pairs": [("leaf/no-call-limit", "a:transfer0")], "unpaired": ["leaf/credits"],
                   "payments": [], "unbound": ["a:transfer0"]},
                  [("credits", None), ("grant", None)]))
    p1, e1 = redemption("a", [L["leaf/grant"]] + above, [PRICE])
    p2, e2 = redemption("b", [L["leaf/credits"]] + above, [])
    c.append(case("two-bindings-one-transfer",
                  "two binding leaves from one root whose code moves the money once: exactly one binds, the first "
                  "in log order, which only pairing across the whole receipt shows",
                  p1 + p2 + e1 + e2,
                  {"chains": [(["leaf/grant", "D_AB", "D_HA"], "leaf/grant"),
                              (["leaf/credits", "D_AB", "D_HA"], "leaf/credits")],
                   "pairs": [("leaf/grant", "a:transfer0")], "unpaired": ["leaf/credits"],
                   "payments": [("leaf/grant", "a:transfer0", PRICE)], "unbound": []},
                  [("grant", "leaf/grant"), ("credits", None)]))
    pre, ev = redemption("r", [L["leaf/credits"]] + above, [])
    auth = [("x402:authorization", authorization_used_log(W_H, cv.keccak256(b"an x402 authorization nonce"))),
            ("x402:transfer", transfer_log(W_H, PAYEE, PRICE))]
    c.append(case("eip3009-transfer-beside-binding",
                  "an EIP-3009 Transfer from the root beside a binding leaf whose root moved nothing: the Transfer "
                  "belongs to x402 and pairs with nothing",
                  auth + pre + ev,
                  {"eip3009": ["x402:transfer"], "chains": [(["leaf/credits", "D_AB", "D_HA"], "leaf/credits")],
                   "unpaired": ["leaf/credits"], "payments": [], "unbound": []},
                  [("credits", None)]))
    pre, ev = redemption("r", [L["leaf/credits"]] + above, [PRICE], manager=UNLISTED_MANAGER)
    c.append(case("unlisted-manager",
                  "the events come from a delegation manager the verifier does not list: no chain, and the "
                  "Transfer is unbound",
                  pre + ev, {"payments": [], "unbound": ["r:transfer0"]}, [("credits", None)]))
    pre, ev = redemption("r", [L["leaf/credits"]] + above, [2 * PRICE])
    c.append(case("transfer-differs-from-pin",
                  "the root's code moves another amount than the leaf pins: the leaf pairs with nothing and the "
                  "Transfer is unbound",
                  pre + ev,
                  {"chains": [(["leaf/credits", "D_AB", "D_HA"], "leaf/credits")], "unpaired": ["leaf/credits"],
                   "payments": [], "unbound": ["r:transfer0"]},
                  [("credits", None)]))
    for n, other in (("repay/first-leaf", "leaf/repay-1"), ("repay/varied-leaf", "leaf/repay-2")):
        pre, ev = redemption("r", [L[other]] + above, [PRICE])
        c.append(case(n, "the first payment for the onboarding nonce" if other.endswith("1") else
                      "the re-pay: a leaf varied by its TimestampEnforcer bound binds the same nonce as a new payment",
                      pre + ev,
                      {"chains": [([other, "D_AB", "D_HA"], other)], "pairs": [(other, "r:transfer0")],
                       "payments": [(other, "r:transfer0", PRICE)], "unbound": []},
                      [("onboarding", other)]))
    return c


def leaf_salt_fixture():
    r1 = LEAVES["leaf/repay-1"]
    return {
        "version": 1,
        "description": "erc7710-leaf-salt/v1 (spec/payment-nonce-and-binding.md section 3): which delegation in a "
                       "successful receipt binds a payment, which Transfer it pairs with, and which request it pays.",
        "generator": "scripts/gen-delegated-spend-vectors.py. Deterministic: rerunning gives these bytes.",
        "conventions": {
            "hex": "unprefixed lowercase",
            "log": "address_hex, topics_hex and data_hex as eth_getTransactionReceipt returns them; log_names are "
                   "labels for readers, not part of the receipt",
            "position": "a log's index among the transaction's own logs, from 0",
            "delegations": "the hops and leaves, with their struct hashes, are in erc7710-statements.json and below",
            "requests": "purpose names a payment-nonce.json vector; binds is the delegation hash of the payment the "
                        "request binds, or null",
        },
        "keys": [k.json() for k in LEAF_KEYS.values()],
        "config": {
            "chain_id": CHAIN_ID, "usdc_hex": USDC.hex(), "payee_hex": PAYEE.hex(),
            "delegation_managers": [{
                "framework": cv.LEAF_SALT_FRAMEWORK, "delegation_manager_hex": MANAGER.hex(),
                "exact_execution_enforcer_hex": EXACT_EXECUTION.hex(),
                "limited_calls_enforcer_hex": LIMITED_CALLS.hex(),
            }],
        },
        "delegations": [d.json() for d in LEAVES.values()],
        "cases": leaf_salt_cases(),
        "repay": {
            "note": "a leaf whose payment was refunded cannot be redeemed again, and other args leave its hash, so "
                    "its identity, unchanged; a payer forms another leaf for the same nonce by another "
                    "TimestampEnforcer bound",
            "first_case": "repay/first-leaf", "second_case": "repay/varied-leaf",
            "same_leaf_other_args": {
                "delegation": r1.name,
                "event_data_hex": [cv.abi_encode_delegation(event_args(r1)).hex(),
                                   cv.abi_encode_delegation(event_args(r1, {2: b"args are not signed"})).hex()],
            },
        },
    }


FIXTURE_BUILDERS = {
    "erc7710-leaf-salt-v1.json": leaf_salt_fixture,
    "erc7710-statements.json": statements_fixture,
    "payment-nonce.json": payment_nonce_fixture,
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
