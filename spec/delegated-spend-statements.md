# Delegated-spend statements

**Audience:** implementers of agent tooling that publishes ERC-7710
delegations, of the on-chain publication check, and of auditors that walk a
payment back to the authority that allowed it.
**Related:** [checkpoints-and-receipts.md](./checkpoints-and-receipts.md)
§4 (the entry leaf),
[leaf-admission-and-session-endorsement.md](./leaf-admission-and-session-endorsement.md)
(who may sign an entry), [label-registry.md](./label-registry.md),
[glossary.md](../glossary.md), and the vectors in
[`vectors/fixtures/erc7710-statements.json`](../vectors/fixtures/erc7710-statements.json).

## Summary

An agent spends its owner's money through a chain of
[ERC-7710](https://eips.ethereum.org/EIPS/eip-7710) delegations, held and
enforced on chain by a delegation manager. Forestrie supplies none of the
money. It supplies transparency: each reusable hop of the chain is published
as a statement in a Forestrie log, and a caveat on the hop makes it
unusable on chain until that statement is anchored.

This document specifies three statements:

- the **delegation statement**, which publishes one hop;
- the **revocation statement**, which records that a delegator disabled a
  hop on chain;
- the **spend statement**, which records a payment that a payment leaf made.

Every statement carries hashes, accounts and terms, never a payload of its
own ([P1](../rules/platform.md#p1--pipe-not-store)). A spend statement
references its settlement and does not contain it: amount, asset and payee
are read from the transaction.

"Delegation" in this document always means an ERC-7710 delegation. The
sealing delegation of a log's root key is a different artifact
([delegation-and-webauthn-envelopes.md](./delegation-and-webauthn-envelopes.md)).

## 1. The delegation framework

The formats below fix one framework: the MetaMask Delegation Framework at
version 1.3.0, whose delegation manager implements ERC-7710. A delegation is
the framework's struct:

```text
Delegation { address delegate; address delegator; bytes32 authority;
             Caveat[] caveats; uint256 salt; bytes signature; }
Caveat     { address enforcer; bytes terms; bytes args; }
```

- `authority` is the delegation hash of the parent hop, or
  `ROOT_AUTHORITY` (32 bytes of `0xff`) for the hop the funds account signs.
- `delegate` may be `ANY_DELEGATE` (`0x0000…0a11`), which lets anyone
  redeem or extend the delegation.
- A caveat's `terms` are signed. Its `args` are supplied by whoever redeems,
  are not signed, and change with each redemption.

A **hop** is a reusable delegation that confers standing authority: caps,
an expiry, and optionally a list of payees. A **payment leaf** is a
single-use delegation that pins one transfer; it is never published. Which
delegation binds a payment, and to which request, is the binding rule's
([payment-nonce-and-binding.md](./payment-nonce-and-binding.md) §3).

## 2. The delegation hash

The **delegation hash** of a delegation is its EIP-712 struct hash, the
value the framework's `EncoderLib._getDelegationHash` returns:

```text
DELEGATION_TYPEHASH = keccak256("Delegation(address delegate,address delegator,"
                        "bytes32 authority,Caveat[] caveats,uint256 salt)"
                        "Caveat(address enforcer,bytes terms)")
CAVEAT_TYPEHASH     = keccak256("Caveat(address enforcer,bytes terms)")

caveatHash(c)   = keccak256(abi.encode(CAVEAT_TYPEHASH, c.enforcer, keccak256(c.terms)))
delegationHash  = keccak256(abi.encode(DELEGATION_TYPEHASH, delegate, delegator,
                    authority, keccak256(caveatHash(c0) ‖ caveatHash(c1) ‖ …), salt))
```

It covers the delegate, the delegator, the authority, each caveat's enforcer
and terms in order, and the salt. It does not cover the caveats' `args` or
the signature.

The delegator signs a different value, the typed-data digest
`keccak256(0x19 ‖ 0x01 ‖ domainSeparator ‖ delegationHash)`, where the
domain is `EIP712Domain(name "DelegationManager", version "1", chainId,
verifyingContract = the delegation manager)`. **A statement carries the
struct hash, never the digest.** The delegation manager hands each caveat
enforcer the struct hash, so a statement that carries the digest publishes
a value nothing on chain ever checks, and leaves its hop unpublished. That is
the easiest mistake for tooling to make, and the vectors test it (§8.2).

## 3. The common envelope

Each statement is a COSE_Sign1 with an attached payload, registered in a log
like any other statement and admitted under the log's usual signer rules
([leaf-admission-and-session-endorsement.md](./leaf-admission-and-session-endorsement.md)
§5). It is signed by the log's **statement-signing key**, which is never the
key that signs delegations: the agent tooling refuses to use one key for
both.

A statement is registered either as the bare COSE_Sign1 array or as a
**tag-18** COSE_Sign1: CBOR tag 18, the byte `0xd2`, then the array. The
entry commits to the bytes as registered, so a tagged statement's bytes
start with `0xd2`, and so does the `prefix` the publication check rebuilds
for a tagged delegation statement (§8). The signature and the protected
header do not cover the tag. Tag 18 is the only tag a statement may hold,
once, outermost; everything this document says of a statement's bytes
applies to the bytes as registered, and everything it says of its
structure applies to the array inside the tag.

```cddl
spend-statement-protected = {
  1 => int,              ; alg: -7 (ES256) or -65799 (KS256)
  3 => tstr,             ; content type, one per statement type (below)
  4 => bstr,             ; kid of the statement-signing key
  15 => {                ; CWT claims (RFC 9597)
    1 => tstr,           ; iss: the signer, as the registration service names it
    2 => tstr,           ; sub: lowercase hex of the delegation hash the statement is about
  },
}
```

| Statement | Content type | Logged by |
|---|---|---|
| Delegation | `application/univocity.erc7710-delegation+cbor` | The hop's delegator, in the log its publication caveat names |
| Revocation | `application/univocity.erc7710-revocation+cbor` | The hop's delegator, in the log that published the hop |
| Spend | `application/univocity.erc7710-spend+cbor` | The spender, the delegator of the payment leaf, in its own log |

`sub` names the hop for a delegation or revocation statement and the
payment leaf for a spend statement. The unprotected header is empty,
except that a log whose signer rules require the session endorsement
([leaf-admission-and-session-endorsement.md](./leaf-admission-and-session-endorsement.md)
§4, §5.1) carries it, and only it, at `-65801`. The §8.1 tag scan covers
the endorsement's bytes like any other.

The payload of every statement type is a map in one key space: a key means
the same thing in every type that uses it.

| Key | Name | Type | In |
|---|---|---|---|
| `1` | `v` | uint, `1` | every type |
| `2` | publication anchor | bstr, 64 bytes: `DELEGATION_TAG ‖ delegation hash` | delegation only |
| `3` | chain id | uint, the EIP-155 chain id of the funds chain | every type |
| `4` | delegation manager | bstr, 20 bytes | every type |
| `5` | hop | the delegation as signed (§4) | delegation |
| `6` | delegate log | bstr, 32 bytes: the delegate's log id in the padded wire form | delegation |
| `7` | depth | uint (§4) | delegation |
| `8` | delegation hash | bstr, 32 bytes, bare | revocation, spend |
| `9` | transaction hash | bstr, 32 bytes | spend; revocation, optional |
| `10` | purpose | map (§7) | delegation, spend |
| `11` | reason | tstr, not empty | revocation |

Keys `2` and `8` both carry a delegation hash. Only key 2, in a delegation
statement, carries it after `DELEGATION_TAG`; key 8 carries it bare, so a
revocation or spend statement never publishes the hop it is about (§8.1).

## 4. The delegation statement

```cddl
delegation-payload = {
  1 => 1,                     ; v
  2 => bstr .size 64,         ; DELEGATION_TAG ‖ delegation hash
  3 => uint,                  ; chain id of the funds chain
  4 => bstr .size 20,         ; delegation manager
  5 => hop,
  6 => bstr .size 32,         ; the delegate's log id
  7 => uint,                  ; depth
  10 => purpose,
}

hop = [
  delegate:  bstr .size 20,
  delegator: bstr .size 20,
  authority: bstr .size 32,   ; the parent's delegation hash, or ROOT_AUTHORITY
  caveats:   [* [enforcer: bstr .size 20, terms: bstr]],
  salt:      bstr .size 32,   ; the uint256 salt, big-endian
  signature: bstr,
]

purpose = {
  ? 1 => uint,                ; payment kind, a spend's only (§7)
  ? 2 => bstr .size 32,       ; purpose digest, with key 1
  ? 3 => tstr,                ; description, in words, not empty
  ? 4 => bstr .size 32,       ; intent digest
}
```

```text
DELEGATION_TAG = SHA-256( UTF-8 "univocity/erc7710-delegation/v1" )
               = b09bc7d90e4fa6b305d213aa3f89a5df627c8bace691cabe3ccbe1bd85251649
```

- **Key 2 is the anchor the chain checks.** It is the 32-byte tag followed
  by the hop's delegation hash, contiguous, so the publication check can
  rebuild the statement bytes around the hash it is given without parsing
  CBOR (§8).
- **Key 5 is the hop as signed**, without the caveats' `args`, which are not
  signed and change with each redemption. Publishing the signature lets
  anyone check the delegator offline. It gives nobody else the power to
  redeem: a hop names its delegate, and the delegation manager lets only
  that delegate redeem it or sign beneath it. The issuing tools never sign
  a hop for `ANY_DELEGATE`; only a payment leaf is open.
- **Caps, period, expiry and payees are the caveats' terms**, and the
  statement does not restate them. A restated cap could disagree with the
  one the chain enforces; the terms are the ones that bind.
- **Key 6 names the delegate's log**, where the delegate publishes its own
  hops and records its spending, so an auditor can walk forward from a hop.
- **Key 7, depth,** is the most delegations a chain may hold beneath this
  hop, the payment leaf included. No caveat enforces depth on chain. The
  issuing tools refuse to sign a hop that declares more depth than its
  parent allows beneath it, and an auditor flags a redeemed chain that holds
  more delegations beneath a hop than the hop declares.
- **Key 10, the purpose,** says what the hop is for: a description, and
  optionally an intent digest (§7). It carries no payment kind.

## 5. Revocation

```cddl
revocation-payload = {
  1 => 1,                     ; v
  3 => uint,                  ; chain id of the funds chain
  4 => bstr .size 20,         ; delegation manager
  8 => bstr .size 32,         ; the revoked hop's delegation hash
  ? 9 => bstr .size 32,       ; the disableDelegation transaction's hash
  11 => tstr,                 ; reason, not empty
}
```

A revocation statement mirrors the framework's `disableDelegation`, which a
delegator calls on the delegation manager to stop a hop being redeemed. The
statement does not revoke anything: the chain does. It records that the
delegator meant to, why, and, once the call has been mined, in which
transaction (key 9), so an auditor reading the log sees the hop's end beside
its start. The delegator signs it in the log that published the hop, with
the same statement-signing key.

## 6. Spend

```cddl
spend-payload = {
  1 => 1,                     ; v
  3 => uint,                  ; chain id of the funds chain
  4 => bstr .size 20,         ; delegation manager
  8 => bstr .size 32,         ; the payment leaf's delegation hash
  9 => bstr .size 32,         ; the redeeming transaction's hash
  10 => purpose,              ; with keys 1 and 2 (§7)
}
```

The spender records each payment in its own log, the delegate log its
parent hop names. Key 8 is the delegation hash of the payment leaf that
made the payment, and key 9 the transaction that redeemed it. The leaf is
never published, but the delegation manager logs every delegation it
redeems, so an auditor finds the leaf in the transaction by its hash, then
walks its authority links up to the published hops. Amount, asset and payee
are read from the transaction, never restated: a restated amount could
disagree with the transfer the chain made.

## 7. The purpose

| Key | Name | Delegation | Spend |
|---|---|---|---|
| `1` | payment kind | absent | required |
| `2` | purpose digest | absent | required |
| `3` | description | required | optional |
| `4` | intent digest | optional | optional |

A spend's kind says whom it paid and for what. The kinds are an open
registry: a decoder accepts any unsigned kind, and a later kind is added
without a new statement version. An auditor reports a kind other than 1 to 3
as an unverified claim, as it does for kind 4, because it has no payment
nonce to check the purpose digest against.

| Kind | Paid for | Purpose digest |
|---|---|---|
| `1` | a grant, to a registration service | the grant's, as the payment nonce defines it |
| `2` | an onboarding, to a registration service | the onboarding request's, likewise |
| `3` | credits, to a registration service | the credit purchase's, likewise |
| `4` | anything else, to a seller | the seller's reference for what was bought |

For kinds 1 to 3 the purpose digest is the one the payment nonce is built
from ([payment-nonce-and-binding.md](./payment-nonce-and-binding.md) §2), so
an auditor checks a spend against its leaf: the nonce over the kind, the
purpose digest and the chain's root delegator is the leaf's salt. That is
not enough on its own: key 8 of a kind 1 to 3 spend must be a **payment** of
key 9's transaction, so the receipt the auditor uses is the one key 9
names, and no other. The auditor runs the binding rule
([payment-nonce-and-binding.md](./payment-nonce-and-binding.md) §3.2) on
that transaction's receipt and requires key 8, under the spend's chain and
delegation manager, to be among its payments, with the nonce over the kind,
the purpose digest and that payment's root equal to the payment's salt. The
auditor runs the rule with the USDC contract and the registration payee from
its own configuration for the spend's chain and manager
([payment-nonce-and-binding.md](./payment-nonce-and-binding.md) §3.1),
never the payee a leaf's pin names; a leaf pinned elsewhere binds nothing,
and the spend is refused. A
leaf salted beneath a salted hop pays nothing, because the hop nearest the
root binds; a spend that names such a leaf is refused, although its leaf's
salt matches. A seller's
payment (kind 4) carries no payment nonce, and its digest is whatever
reference the seller gave.

The intent digest (key 4) is the SHA-256 of an off-log document stating the
owner's intent, for example an AP2 IntentMandate. The document stays with
its owner; the statement holds only its digest.

## 8. Publication

**An anchored entry in log `L` whose statement bytes contain
`DELEGATION_TAG ‖ H` publishes `H` in `L`.** The entry's leaf is the usual
one ([checkpoints-and-receipts.md](./checkpoints-and-receipts.md) §4):

```text
leaf = SHA-256( idtimestamp (8 bytes, big-endian) ‖ SHA-256( statement bytes ) )
```

The on-chain publication check receives `H` from the delegation manager and,
from whoever redeems, the statement bytes before the anchor (`prefix`), the
bytes after it (`suffix`), the idtimestamp and an inclusion path. It rebuilds

```text
statement bytes = prefix ‖ DELEGATION_TAG ‖ H ‖ suffix
```

and the leaf, and checks the leaf's inclusion against the log's anchored
state. The redeemer's inputs are unsigned and untrusted: they can only
reproduce a leaf that is already in the log. Each statement vector gives
`prefix`, `suffix`, the idtimestamp and the leaf.

The check proves **presence, not form**. It is as strong as the log's write
path: anyone with a grant to the log can register a statement that holds
the tag, so a delegator names a log whose grants it controls.

### 8.1 The tag stays out of the other types

A revocation or spend statement carries its delegation hash bare, at key 8,
and never encodes `DELEGATION_TAG`, anywhere in its bytes. A registration
service that accepts these two types strips a single leading tag 18 (§3),
classifies the statement by its content type, and refuses, on its route, a
statement of either type whose bytes hold the tag, headers included. Bytes
that hold the tag and do not decode strictly as a COSE_Sign1 cannot be
classified, and it refuses those too: re-encoding the outer array leaves
the signature valid, so a statement must not pass by being unreadable. That keeps a
revocation from publishing the very hop it revokes, and a spend from
publishing anything, by accident or on purpose.

### 8.2 What an auditor accepts

Nothing stops someone with a grant to a log, or its checkpoint authority,
from putting the tag in some other statement. So:

- every `DELEGATION_TAG ‖ H` in an anchored statement's bytes is a
  publication of `H`, which is what the chain accepts;
- an auditor finds publications by scanning statement bytes, as registered,
  for the tag, and accepts one as **well formed** only when the statement
  (after a single leading tag 18 is stripped, §3) is a delegation
  statement, the tag and `H` are its payload's key 2, and `H` is the
  delegation hash recomputed from key 5;
- it flags anything else, attributed to the statement's signer where the
  bytes are signed, that is, inside the protected header or the payload,
  which the signature covers, and to nobody when the tag sits in the
  unprotected header or elsewhere, which it does not (anyone holding a
  signed statement can add a label there without breaking the signature):
  the tag outside key 2 of a delegation statement
  (`outside-key-2`), or a key 2 hash that is not the hash of the hop at key 5
  (`hash-mismatch`), which would let a log owner publish one hash while
  showing different terms.

Attribution follows the tag's own 32 bytes: the tag is the signer's when
those 32 bytes lie in one signed range, even if the 32 bytes of `H` after
it run on into the unsigned header. Only the signer can have written the
tag's bytes, so no relayer can frame it by what it adds after them.

The signer, and the bytes the signature covers, are found by a lenient read
of the four COSE_Sign1 elements as they are, not by the strict decode of §9.
The read takes the first four items of an outer array of any length, and
any well-formed item as the unprotected header: neither is signed, and a
signer or a relayer can choose them (canopy admits both).
The outer array's head, the byte-string heads and the form of tag 18 are not
signed, and the signer chooses the encoding of its own protected header, so
a statement that fails the strict decode still has its signed tags
attributed: otherwise a signer could make a tag in its own payload
unattributable by writing a head longer than it needs.

Attribution follows the statement's `alg` (protected key 1) and, for KS256,
its `kid` (protected key 4, the signer's 20-byte address):

- **KS256, a `kid` with no code.** The auditor recovers the signer over the
  protected header and the payload as found, and attributes to the
  recovered address (`ecrecover`). The signature's last byte is `v`: 27 or
  28, which canopy and univocity accept, or the bare recovery id 0 or 1; the
  auditor normalises it before it recovers, and a `v` that is none of
  these four recovers nobody. A high s still recovers the key that signed.
- **KS256, a `kid` with code** (a Safe or other smart account, signing
  through ERC-1271). A recovered address is not the signer, so the auditor
  never attributes to it. It attributes to the `kid` only when an
  **ERC-1271 attestation** (see the
  [glossary](../glossary.md#erc-1271-attestation)) shows
  `isValidSignature(digest, signature)` returning the magic value
  `0x1626ba7e` at the block current at the entry's registration (its
  `idTimestamp`), where `digest` is the Keccak-256 of the Sig_structure and
  `signature` is the statement's. The attestation binds the chain, the
  contract address, the digest, the hash of the signature and the magic
  value, and the block it was read at, which must be the registration
  block; it is supplied to the checker as data (with that block, as the
  auditor's `registration_block`); it is the same read-only
  call canopy's route makes, so there is no transaction to find, and an
  auditor needs an archive node for older blocks. A contract-signed
  statement with no such attestation is reported **unattributed**.
- **Any other `alg`.** A statement whose `alg` is not KS256 has no KS256
  recovery, so it is not attributed that way. An ES256 statement yields no
  address: the auditor resolves its `kid` to a key and, only when the
  signature verifies under that key, attributes to it, otherwise to nobody:
  a `kid` alone names whoever the header claims, not whoever signed.

The reference checker and the vectors attribute KS256 statements only;
ES256 attribution by `kid` is outside them. Whether a `kid` has code, the registration block and
the attestations are the auditor's input to the checker, not read from the
statement.

An auditor never trusts key 2 alone; it recomputes the hash from the
published hop, and it scans every byte of a delegation statement, not only
key 2: a well-formed statement can hide a second publication, for example in
the bytes of key 5's signature, which the delegation hash does not cover.

| Vector | Publication | Verdict |
|---|---|---|
| `well-formed/D_AB` | `H(D_AB)` | well formed |
| `flag/tag-in-hop-signature` | `H(D_AB)` at key 2, and `H(D_HA)` inside key 5's signature bytes | well formed, and `outside-key-2` |
| `flag/hash-mismatch` | `H(D_HA)`, while key 5 shows `D_AB` | `hash-mismatch` |
| `flag/signed-digest-not-struct-hash` | the typed-data digest of `D_AB`, so `D_AB` stays unpublished | `hash-mismatch` |
| `flag/tag-in-another-statement-type` | `H(D_AB)`, from a statement of another type signed by someone else | `outside-key-2` |
| `refuse/spend-with-tag` | `H(D_AB)`, in a spend statement's unprotected header; refused on the route (§8.1) | `outside-key-2`, no signer |
| `refuse/revocation-with-tag` | `H(D_AB)`, in a revocation statement's unprotected header; refused on the route (§8.1) | `outside-key-2`, no signer |
| `well-formed/D_AB-tag18` | `H(D_AB)` in a tag-18 delegation statement, one byte later than in `well-formed/D_AB` | well formed |
| `refuse/spend-with-tag-tag18` | `H(D_AB)`, in a tag-18 spend statement's unprotected header; refused on the route (§8.1) | `outside-key-2`, no signer |
| `refuse/spend-with-tag-reencoded` | `H(D_AB)`, in a spend statement whose outer array head is longer than it needs; refused on the route (§8.1) | `outside-key-2`, no signer |
| `flag/tag-in-another-statement-type-reencoded` | `H(D_AB)`, in the payload of the stranger's statement whose outer array head is longer than it needs | `outside-key-2`, the stranger |
| `flag/tag-in-another-statement-type-tag18-long` | `H(D_AB)`, in the payload of the stranger's statement led by tag 18 written `0xd8 0x12` | `outside-key-2`, the stranger |
| `flag/tag-in-another-statement-type-indefinite-array` | `H(D_AB)`, in the payload of the stranger's statement whose outer array is indefinite-length | `outside-key-2`, the stranger |
| `flag/tag-in-another-statement-type-unprotected-simple` | `H(D_AB)`, in the payload of the stranger's statement with `{-70000: true}` in its unprotected header | `outside-key-2`, the stranger |
| `flag/tag-in-another-statement-type-chunked-payload` | `H(D_AB)`, in the payload of the stranger's statement whose payload is an indefinite-length byte string | `outside-key-2`, the stranger |
| `flag/tag-in-another-statement-type-high-s` | `H(D_AB)`, in the payload of the stranger's statement whose KS256 signature has a high s | `outside-key-2`, the stranger |
| `flag/tag-in-another-statement-type-v27`, `-v28` | `H(D_AB)`, in the payload of the stranger's statement whose signature ends in `v` 27, and in another ending in 28 | `outside-key-2`, the stranger |
| `flag/tag-in-contract-signed-statement-attested` | `H(D_AB)`, in a statement whose `kid` is a contract, signed with an owner's key, with an ERC-1271 attestation | `outside-key-2`, the contract |
| `flag/tag-in-contract-signed-statement-unattested` | the same statement, with no attestation | `outside-key-2`, no signer |

### 8.3 The statement vectors

| Vector | Statement | Shows |
|---|---|---|
| `delegation/D_HA` | the root hop, published by the human owner's statement key | a purpose with a description and an intent digest |
| `delegation/D_AB` | a hop beneath it, published by agent A's statement key | a purpose with a description only |
| `delegation/D_AB-tag18` | `delegation/D_AB` registered as a tag-18 COSE_Sign1 | the publication `prefix` starts with `0xd2` |
| `revocation/D_AB` | agent A disables `D_AB` | a bare hash, a reason and the disabling transaction |
| `spend/credits` | agent B buys credits through a payment leaf | the credits purpose digest, whose nonce is the leaf's salt |
| `spend/seller` | agent B pays a seller | kind 4, with the seller's reference as digest |
| `spend/credits-under-salted-hop` (`refused_spends`) | a credits spend naming a leaf that sits beneath a salted hop | refused, `binding`: key 8 is not a payment of the receipt |
| `spend/credits-salted-over-own-delegator` (`refused_spends`) | a credits spend whose leaf is salted with the nonce over the leaf's own delegator | refused, `root`: the chain's root is the human's account, not that delegator |
| `spend/credits-pays-the-agent` (`refused_spends`) | a credits spend whose leaf pins the transfer to agent B's own account | refused, `binding`: the rule, run with the registration payee, binds no payment |
| `spend/credits-wrong-receipt` (`refused_spends`) | a credits spend whose key 9 names a receipt that holds no payment of its leaf | refused, `binding` |
| `spend/credits-another-purchase` (`refused_spends`) | a credits spend whose purpose digest is not the one the payment's salt commits to | refused, `purpose` |
| `spend/credits-claimed-as-grant` (`refused_spends`) | the same payment claimed as kind 1, a grant | refused, `purpose` |
| `spend/credits-on-another-chain` (`refused_spends`) | the payment named under another chain | refused, `chain` |
| `spend/credits-under-another-manager` (`refused_spends`) | the payment named under another delegation manager | refused, `manager` |

## 9. Encoding

Every map in these statements, the protected header and the CWT claims
included, uses Core Deterministic Encoding
([P16](../rules/platform.md#p16--conformant-cosecbor-everywhere-with-one-named-exception)),
on encode and on decode. A decoder refuses a head longer than it needs, an
indefinite length, a tag other than the one leading tag 18 of §3, a repeated
or out-of-order key, and a payload key that the statement's type and version
do not define.

The vectors include a statement for a long head, an undefined payload key,
a purpose kind that is not an unsigned integer, a delegation purpose without
a description (§4, §7) and an unprotected label other than the endorsement's
(§3) (`decode_negatives`); none may decode. A decoder accepts any unsigned
purpose kind, because the kinds are an open registry (§7); the vectors
include a spend of kind 5 (`decode_accepts`), which must decode.

Bytewise order of the encoded keys (RFC 8949 section 4.2.1) is canon for
these statements and for every Forestrie format but the checkpoint
envelope, whose length-first exception
[P16](../rules/platform.md#p16--conformant-cosecbor-everywhere-with-one-named-exception)
and ADR-0068 name: length-first order is not canon for these statements. Every label these types use encodes in one
byte, so the two orders give the same bytes for these encodings today. The
vectors include one map whose labels differ in encoded length,
`map_key_order`, with its bytes in both orders and bytewise marked canon. A
decoder refuses the length-first bytes. A shared implementation that sorts
length-first diverges from P16
([implementation-status.md](./implementation-status.md)); a later version
that adds a longer label depends on that divergence closing.

## Open questions

- **The publication caveat's terms** (which univocity instance and log a hop
  names, and how the check finds the instance's verifier) belong to the
  contract that implements the check. This document fixes only the bytes the
  check rebuilds.

## References

- [checkpoints-and-receipts.md](./checkpoints-and-receipts.md) §4 — the
  entry leaf the publication check rebuilds.
- [leaf-admission-and-session-endorsement.md](./leaf-admission-and-session-endorsement.md)
  — who may sign a statement in a log.
- [rules/platform.md](../rules/platform.md) — P1 (hashes, not payloads),
  P16 (encoding) and P17 (authority used only once anchored).
- [ERC-7710](https://eips.ethereum.org/EIPS/eip-7710) and
  [EIP-712](https://eips.ethereum.org/EIPS/eip-712).
- [MetaMask Delegation Framework v1.3.0](https://github.com/MetaMask/delegation-framework/tree/v1.3.0)
  — `src/libraries/EncoderLib.sol` (the struct hash),
  `src/DelegationManager.sol` (`ROOT_AUTHORITY`, `ANY_DELEGATE`, the domain).
- [`vectors/fixtures/erc7710-statements.json`](../vectors/fixtures/erc7710-statements.json)
  — every value above, as bytes.
