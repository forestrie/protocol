# ADR-0069: Grant flag bit 35 is the operator's child-payment-required policy

**Status:** PROPOSED — records an assignment the operator's registration API
already makes in the band the contract reserves for it.
**Date:** 2026-09-19
**Related:** [spec/label-registry.md](../spec/label-registry.md) §5,
[spec/log-authority-and-grants.md](../spec/log-authority-and-grants.md) §3 and §7,
[rules/platform.md](../rules/platform.md) P7.

## Context

Grant flag bits 35–39 are reserved for operator-assigned derived policy: the
contract defines no constant for them, reads none of them, and no test
asserts that the algorithm-policy band stays clear of them. The operator's
registration API assigns bit 35 as `GF_CHILD_PAYMENT_REQUIRED` (wire byte 3,
mask `0x08`): when a parent grant carries it, the API requires payment before
it registers a child grant under that parent. The bit is committed in the
parent's leaf, so it is provable from the parent's receipt; it is never an
input to grant verification, on-chain or off.

Rule P7 was titled "Payment grants authority", which the specification
contradicts: payment identity is never an input to verification.

## Decision

1. Bit 35 is assigned to `GF_CHILD_PAYMENT_REQUIRED`, meaning "the
   operator's registration API requires payment before registering a child
   grant of this grant". It is recorded in the registry's flag table.
2. Bits 36–39 remain reserved for operator-assigned policy. An assignment in
   this band is recorded in the registry and by a decision; it is never read
   by the contract or by a verifier.
3. Rule P7 is retitled and restated: a grant is a prepaid provability
   entitlement; payment never gates authority; a parent flag may gate child
   *registration* at the operator.
4. Nothing in this band ever enters the fail-closed algorithm-policy check.
   A future widening of that band downward is a breaking change and needs its
   own decision.

## Consequences

- No wire change; the bit is already set on parent grants that use the
  policy, and already ignored by the contract and every verifier.
- A verifier that renders grant flags may name bit 35 by its display name in
  the registry; it must not treat the bit as affecting verification.
- The absence of an on-chain mask for bits 35–39 stays recorded in the
  registry as a fact about the contract.
