# ADR-0067: The WebAuthn assertion envelope label shares the algorithm's number

**Status:** PROPOSED — records a wire convention every implementation already
follows, so that the specification can state it as a decision rather than a
defect with no owner.
**Date:** 2026-09-19
**Related:** [spec/label-registry.md](../spec/label-registry.md) §4,
[spec/delegation-and-webauthn-envelopes.md](../spec/delegation-and-webauthn-envelopes.md)
§2, [ADR-0064](./adr-0064-passkey-session-key-endorsement.md).

## Context

`ALG_ES256_WEBAUTHN` (`-65800`) is the COSE algorithm for a P-256 key whose
signature is a WebAuthn assertion. The assertion material an off-chain
verifier needs — `[authenticatorData, clientDataJSON]` — rides in the
unprotected header under a COSE header parameter the specification names
`TBD1`. Every shipped implementation uses `-65800` for that header parameter
too: the TypeScript encoding package declares the label as an alias of the
algorithm constant, and the Go operator services declare it as a separate
named constant with the same value.

The two never occupy the same parse position — the algorithm is a value under
protected label `1`, the envelope a key in the unprotected map — so there is
no wire ambiguity. The costs are documentary and structural: the envelope's
legality is conditional on the algorithm, and every definition of the
session-key endorsement label (`-65801`) has to say it is not the envelope.

## Decision

1. The header parameter `TBD1` **is** `-65800` on the wire, and remains so
   until a distinct codepoint is assigned by a superseding decision.
2. Implementations MUST declare the header label and the algorithm as
   **separate named constants**, even while their values coincide, so that a
   reassignment is a one-line change at each declaration site.
3. An envelope under `-65800` in an unprotected header is legal only when the
   protected algorithm is `ALG_ES256_WEBAUTHN`; under any other algorithm it
   is refused before signature work, per the fail-closed rules.
4. The specification describes this as the convention in force, not as a bug.
   [spec/label-registry.md](../spec/label-registry.md) §4 states the cost.

## Consequences

- No wire change; every frozen vector and every deployed verifier is
  unaffected.
- A future assignment of a distinct `TBD1` is a wire change for certificates
  and endorsements, and will need its own decision, a transition rule for
  verifiers (accept both during the transition) and new vectors.
- The aliasing in the TypeScript package is a divergence from rule 2 and is
  recorded in [spec/implementation-status.md](../spec/implementation-status.md).
