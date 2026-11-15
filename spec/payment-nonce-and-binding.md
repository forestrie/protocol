# The payment nonce and the ERC-7710 payment binding

**Audience:** implementers of a registration service that charges for
grants, onboarding or credits, and of the payer tooling that pays it.
**Related:** [delegated-spend-statements.md](./delegated-spend-statements.md)
(the delegation hash and the hops a payment runs through),
[log-authority-and-grants.md](./log-authority-and-grants.md) (the grant a
payment buys), [rules/platform.md](../rules/platform.md) P7,
[glossary.md](../glossary.md), and the vectors in
[`vectors/fixtures/payment-nonce.json`](../vectors/fixtures/payment-nonce.json)
and [`vectors/fixtures/erc7710-leaf-salt-v1.json`](../vectors/fixtures/erc7710-leaf-salt-v1.json).

## Summary

A registration service may charge for three things: registering a grant,
onboarding a contract instance, and topping up an instance's credits. A
payment is public on chain, so anyone watching can present its transaction
hash. The **payment nonce** ties a payment to the one purpose it pays for:
every payer and every registration service compute it the same way, from
the purpose and the payer, and a payment counts only for the request that
derives the same nonce. The **binding**, `erc7710-leaf-salt/v1`, says
which delegation in a transaction carries a payment's nonce, and which
`Transfer` it paid with.

None of this touches authority. A grant is verified without reference to any
payment, and no verifier or contract reads payment state
([P7](../rules/platform.md#p7--a-grant-is-a-prepaid-provability-entitlement-payment-never-gates-authority)).
The nonce concerns only the registration service's decision to do the work
it was paid for.

## 1. What a nonce must cover

**The nonce commits to every input that decides what the payment buys.** A
transaction hash can be presented by anyone, and the registration service
accepts it only for a request that rebuilds the payment's nonce. So:

- a grant nonce covers the grant, whose content fixes the log, its owner and
  its size, and so its price. A copy presented by someone else registers the
  same grant, which is harmless;
- an onboarding nonce covers the onboarding request, which fixes the instance
  and its binding;
- a credits nonce covers the instance, the count and a purchase id. Without
  the instance, an observer could steer another buyer's credits to its own
  instance; without the purchase id, two purchases of the same count would
  share one nonce.

The nonce also covers the **payer**, so two payers paying for one purpose
claim two different nonces, and each payment is judged on its own.

## 2. The formula

```text
paymentNonce = SHA-256( TAG ‖ kind ‖ purposeDigest ‖ payer )

TAG            = UTF-8 "univocity/payment-nonce/v1"          26 bytes
kind           = 0x01 grant | 0x02 onboarding | 0x03 credits  1 byte
purposeDigest  = the purpose's digest (below)                 32 bytes
payer          = the account the payment leaves               20 bytes
```

| Kind | `purposeDigest` |
|---|---|
| grant (`0x01`) | `SHA-256(inner grant)`, where the inner grant is the payload form, keys `1` to `6` in Core Deterministic Encoding, exactly as a `Forestrie-Grant` carries it at `-65538` ([log-authority-and-grants.md](./log-authority-and-grants.md) §2) |
| onboarding (`0x02`) | `SHA-256(UTF-8 request id)`, the onboarding request's id exactly as the registration service issued it |
| credits (`0x03`) | `SHA-256(UTF-8 instance id ‖ 0x00 ‖ credits ‖ purchaseId)`: the instance id as a lowercase CAIP-10 account id, `eip155:<decimal chain id>:0x<40 lowercase hex>`; `credits` the count, 8 bytes big-endian, at least 1; `purchaseId = SHA-256(UTF-8 key)`, `key` the string an `Idempotency-Key` field carries, a Structured Field String taken unquoted and unescaped |

- **The payer** is the root delegator of a delegated payment: the funds
  account at the top of the delegation chain, which the payment's USDC
  leaves. For an EIP-3009 payment it is the authorization's `from`, and the
  nonce is the authorization's `nonce`.
- **A credit purchase paid by transaction hash carries an `Idempotency-Key`.**
  The key is the purchase id. A payer uses a fresh key for each purchase:
  the same key, count and instance from the same payer give the same nonce,
  and a purpose is admitted once, so a second payment for it buys nothing.
- **The nonce is the payment's salt.** A delegated payment carries it as the
  salt of the delegation that pins its transfer, a `uint256` whose 32
  big-endian bytes are the nonce.

### 2.1 The canonical preimage

Every request derives its nonce from a **canonical preimage**: exactly
79 bytes, `TAG`, then a kind byte of `0x01`, `0x02` or `0x03`, then 32 bytes
and 20 bytes. Bytes of any other shape are not a canonical preimage. Whoever
shows bytes that are not a canonical preimage, and whose SHA-256 is a
payment's salt, has proved that no request can ever bind that payment: a
request would need a canonical preimage with the same SHA-256. So a
registration service may refund such a payment to its payer on that proof
alone. The payer need not name a purpose the payment could never have
bought.

| Vector | Purpose | Shows |
|---|---|---|
| `grant` | the golden grant of `grant_vectors.json`, in payload form | the grant digest |
| `grant/another-payer` | the same grant, another payer | another nonce |
| `onboarding` | an onboarding request id | the onboarding digest |
| `credits` | 100 credits for an instance, under one `Idempotency-Key` | the credits digest and purchase id |
| `credits/another-purchase` | the same count and instance, another key | another nonce |
| `not_canonical` | an earlier tool's grant nonce; the canonical tag with kind `0x04` | preimages no request derives |

## 3. The binding: `erc7710-leaf-salt/v1`

A delegated payment is the redemption of a delegation chain whose root is
the payer's funds account. The **binding** says which delegation in a
transaction binds a payment, which `Transfer` it pairs with, and so which
request it pays. It reads only the receipt's logs, never the transaction's
calldata, so a bundler's `handleOps`, an EIP-7702 account or a batch all
work. It applies to a successful receipt only.

### 3.1 What the rule reads

The rule names one framework: the MetaMask Delegation Framework at version
1.3.0 ([delegated-spend-statements.md](./delegated-spend-statements.md)
§1). A verifier lists the delegation managers it accepts, each with the
`ExactExecutionEnforcer` and `LimitedCallsEnforcer` deployments of its
framework version, together with the USDC contract and the payee. It reads:

- `RedeemedDelegation(address indexed rootDelegator, address indexed
  redeemer, Delegation delegation)`, only from a listed delegation manager.
  The manager emits one for every delegation it redeems, each chain leaf
  first, after every execution of the call. The event's delegation includes
  the caveats' `args`, which its hash does not cover;
- `Transfer(from, to, value)`, only from USDC and only to the payee;
- `AuthorizationUsed(authorizer, nonce)`, only from USDC.

A log's **position** is its index among the transaction's own logs, from 0,
never the block-wide `logIndex`, which moves when a reorganisation
re-includes the transaction elsewhere. A verifier may bound how many of
these logs it decodes. A receipt beyond its bound yields no binding, never
a partial one.

### 3.2 The rule

1. **EIP-3009 transfers stand aside.** A `Transfer` whose log immediately
   follows USDC's `AuthorizationUsed` for the same `from` was made under an
   EIP-3009 authorization. It never pairs. It belongs to the path that
   presents that authorization, and the root's own code may run any pinned
   call beside it, so a pin proves nothing about it.
2. **Rebuild each chain.** Take the `RedeemedDelegation` logs of each
   manager in order. A chain is a run of them in which each delegation's
   `authority` is the delegation hash of the next, ending at a delegation
   whose `authority` is `ROOT_AUTHORITY`. Every event in it names that
   delegation's delegator as `rootDelegator`, and that delegator is the
   chain's **root**. A run that breaks off is no chain and binds nothing.
3. **One delegation per chain can bind: the one nearest the root that pins
   a transfer to the payee.** A delegation pins a transfer when it carries
   a caveat of the listed `ExactExecutionEnforcer` whose terms are exactly
   `USDC ‖ uint256(0) ‖ transfer(payee, amount)`: 20 bytes, then 32, then
   the 68 bytes of the call. The amount is the **pinned amount**. Walk the
   chain from the root down. The first delegation that pins a transfer is
   the chain's **binding delegation**, and no delegation beneath it can
   bind. So an agent that salts its own hop as well as its leaf gets one
   binding, not two. And a stranger who signs a child under an open leaf
   cannot take the leaf's payment.
4. **Pair across the whole receipt.** Take the binding delegations in the
   order of their `RedeemedDelegation` logs. Each takes the first unpaired
   `Transfer`, other than an EIP-3009 one, of its pinned amount from its
   root to the payee. If there is none, it pairs with nothing. Pairing is
   checked across the receipt, never per request: two binding delegations
   whose root's code moves the money once pair one `Transfer` between them.
   The pairing is deterministic, so a payment presented again pairs with
   the same `Transfer`.
5. **A paired binding delegation is a payment when it carries
   `LimitedCallsEnforcer(1)`**, a caveat of the listed enforcer whose terms
   are `uint256(1)`. A binding delegation without that call limit still
   takes part in pairing, so its `Transfer` is counted once, as money that
   nothing can bind. The call limit is what lets the manager redeem a
   delegation once, and so makes one delegation one payment.
6. **A payment pays the request whose nonce is its salt.** A request
   computes its payment nonce (§2) over each payment's root. It is paid by
   the payment whose salt equals that nonce.

A payment's **identity** is the CAIP-2 chain of its receipt, its
delegation manager and its binding delegation's hash. The delegation hash
leaves out the chain id, and the framework's manager has one address on
every chain it is deployed to, so without the chain one leaf redeemed on
two payment chains would give one identity. Two payments in one transaction stay two, and a payment
keeps its identity when a reorganisation re-includes its transaction. A
`Transfer` to the payee is **unbound** when no payment holds it: an
EIP-3009 transfer is not, while a `Transfer` that a binding delegation
without the call limit holds is. Whether a payment's amount is a price the
purpose accepts, and what becomes of an unbound `Transfer`, is the
registration service's to decide. The rule gives it the facts.

### 3.3 Paying a nonce again

A delegation's hash covers every field but the caveats' `args` and the
signature
([delegated-spend-statements.md](./delegated-spend-statements.md) §2). So a
leaf redeemed once cannot be redeemed again under its call limit, and other
`args` or a new signature leave its hash, and so its identity, unchanged.
A payer who must pay the same nonce again forms another leaf by giving it
another `TimestampEnforcer` bound. The bound is a caveat's terms, so it
changes the delegation hash, and the binding ignores every caveat but the
pin and the call limit. The new leaf binds the same nonce as a new payment,
under its own identity. Another hop between the parent and the leaf does
the same, at the cost of a signature.

### 3.4 Vectors

[`vectors/fixtures/erc7710-leaf-salt-v1.json`](../vectors/fixtures/erc7710-leaf-salt-v1.json)
gives each case as a receipt's logs and the expected EIP-3009 transfers,
chains, pairs, unpaired binding delegations, payments and unbound
transfers, and which requests it pays.

| Case | Shows |
|---|---|
| `one-payment` | one chain, one `Transfer`: one payment; a `Transfer` to someone else is ignored |
| `two-payments-one-root` | two chains from one root in one transaction: two payments, two identities |
| `salted-hop-above-salted-leaf` | the hop nearest the root binds; the salted leaf beneath it does not |
| `stranger-extends-leaf` | a stranger's child under the open leaf: the leaf still binds |
| `no-call-limit` | a binding delegation without the call limit pairs and binds nothing; its `Transfer` is unbound |
| `call-limit-two`, `call-limit-unlisted` | a call limit of two, or of one under an unlisted enforcer, is no call limit: the leaf pairs and binds nothing |
| `pin-unlisted-enforcer` | pin-shaped terms under an unlisted enforcer pin nothing: no binding, the `Transfer` unbound |
| `pin-other-target`, `pin-approve` | a pin on a contract that is not USDC, or on `approve` rather than `transfer`: no binding, the real `Transfer` unbound |
| `transfer-from-another-contract` | a `Transfer`-shaped log from a contract that is not USDC pairs with nothing |
| `authorization-used-from-another-contract`, `authorization-used-for-another-account` | an `AuthorizationUsed` from another contract, or USDC's for another account, before the root's `Transfer` does not make it an EIP-3009 one: it still pairs |
| `pin-to-another-payee` | a leaf pinning the amount to another account, first in log order, binds nothing; the valid leaf still binds |
| `no-call-limit-takes-part` | it takes the one `Transfer` before a leaf with the call limit, which pairs with nothing |
| `two-bindings-one-transfer` | two binding leaves, one `Transfer`: the first in log order binds |
| `two-roots-pair-by-root` | a chain from another root binds first and pins the same amount, its root moving nothing: it pairs with nothing, and the first root's leaf is the payment |
| `eip3009-transfer-beside-binding` | an EIP-3009 `Transfer` pairs with nothing |
| `unlisted-manager` | events from a manager the verifier does not list: no chain, the `Transfer` unbound |
| `transfer-differs-from-pin` | the root's code moves another amount: nothing pairs |
| `repay/first-leaf`, `repay/varied-leaf` | §3.3: another `TimestampEnforcer` bound, the same nonce, a new identity; other `args` leave the first leaf's hash |

## References

- [log-authority-and-grants.md](./log-authority-and-grants.md) §2 — the
  inner grant whose payload form the grant digest covers.
- [rules/platform.md](../rules/platform.md) — P7 (payment never gates
  authority).
- [delegated-spend-statements.md](./delegated-spend-statements.md) — the
  framework, the delegation hash and the hops a payment runs through.
- [MetaMask Delegation Framework v1.3.0](https://github.com/MetaMask/delegation-framework/tree/v1.3.0)
  — `src/DelegationManager.sol` (`redeemDelegations`, the
  `RedeemedDelegation` event), `src/enforcers/ExactExecutionEnforcer.sol`
  and `src/enforcers/LimitedCallsEnforcer.sol`.
- [CAIP-10](https://chainagnostic.org/CAIPs/caip-10) (account ids),
  [EIP-3009](https://eips.ethereum.org/EIPS/eip-3009) (transfer with
  authorization), and the IETF HTTPAPI
  [`Idempotency-Key` header field](https://datatracker.ietf.org/doc/draft-ietf-httpapi-idempotency-key-header/).
- [`vectors/fixtures/payment-nonce.json`](../vectors/fixtures/payment-nonce.json)
  and [`vectors/fixtures/erc7710-leaf-salt-v1.json`](../vectors/fixtures/erc7710-leaf-salt-v1.json)
  — the values above, as bytes.
