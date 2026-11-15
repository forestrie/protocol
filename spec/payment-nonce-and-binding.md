# The payment nonce and the ERC-7710 payment binding

**Audience:** implementers of a registration service that charges for
grants, onboarding or credits, and of the payer tooling that pays it.
**Related:** [delegated-spend-statements.md](./delegated-spend-statements.md)
(the delegation hash and the hops a payment runs through),
[log-authority-and-grants.md](./log-authority-and-grants.md) (the grant a
payment buys), [rules/platform.md](../rules/platform.md) P7,
[glossary.md](../glossary.md), and the vectors in
[`vectors/fixtures/payment-nonce.json`](../vectors/fixtures/payment-nonce.json).

## Summary

A registration service may charge for three things: registering a grant,
onboarding a contract instance, and topping up an instance's credits. A
payment is public on chain, so anyone watching can present its transaction
hash. The **payment nonce** ties a payment to the one purpose it pays for:
every payer and every registration service compute it the same way, from
the purpose and the payer, and a payment counts only for the request that
derives the same nonce.

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

## References

- [log-authority-and-grants.md](./log-authority-and-grants.md) §2 — the
  inner grant whose payload form the grant digest covers.
- [rules/platform.md](../rules/platform.md) — P7 (payment never gates
  authority).
- [CAIP-10](https://chainagnostic.org/CAIPs/caip-10) (account ids),
  [EIP-3009](https://eips.ethereum.org/EIPS/eip-3009) (transfer with
  authorization), and the IETF HTTPAPI
  [`Idempotency-Key` header field](https://datatracker.ietf.org/doc/draft-ietf-httpapi-idempotency-key-header/).
- [`vectors/fixtures/payment-nonce.json`](../vectors/fixtures/payment-nonce.json)
  — the values above, as bytes.
