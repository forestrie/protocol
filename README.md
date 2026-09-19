# Forestrie protocol

The normative description of what a Forestrie receipt means, how a log's
authority is established and delegated, how leaves are admitted, and the
conformance vectors every implementation must pass. It is written for an
outside reader: someone who wants to verify a receipt without trusting the
operator that issued it, and who therefore needs every input to that check to
be public.

## Audience and ownership rule

This repository is the **specification**. Implementations cite it by URL and
do not restate it; where an implementation and this text disagree, the text is
wrong or the implementation is, and either way the fix lands here first.
Operator services, agent tooling, infrastructure and product strategy live
elsewhere and are not needed to read or apply anything here.

The text is durable and low-churn. Changes go through a pull request, and a
change that alters the meaning of a receipt, a grant or a trust root is a
decision recorded under `decisions/` before it appears under `spec/`.

## Layout

| Directory | What it holds |
|---|---|
| `spec/` | The protocol documents: [receipt trust model](spec/receipt-trust-model.md), [checkpoints and receipts](spec/checkpoints-and-receipts.md), [log authority and grants](spec/log-authority-and-grants.md), [leaf admission and session endorsement](spec/leaf-admission-and-session-endorsement.md), [delegation and WebAuthn envelopes](spec/delegation-and-webauthn-envelopes.md), [key custody and choice](spec/key-custody-and-choice.md), [trust boundaries and operator powers](spec/trust-boundaries-and-operator-powers.md), the [COSE label registry](spec/label-registry.md), and [implementation status](spec/implementation-status.md), the one place that records where an implementation and the specification differ |
| `decisions/` | The decisions the specification rests on: [ADR-0045](decisions/adr-0045-receipt-verify-offline-contract.md), [ADR-0064](decisions/adr-0064-passkey-session-key-endorsement.md), [ADR-0065](decisions/adr-0065-endorsed-session-key-admission.md), [ARC-0019](decisions/arc-0019-grant-verification-model.md), and the three wire conventions recorded as [ADR-0066](decisions/adr-0066-webauthn-envelope-label-shares-the-algorithm-number.md), [ADR-0067](decisions/adr-0067-checkpoint-envelope-canonicalisation-exception.md) and [ADR-0068](decisions/adr-0068-grant-flag-bit-35-child-payment-required.md). They are historical records in their own voice; where a decision and `spec/` differ in wording, `spec/` is the current statement. Numbers are stable identifiers; implementations may cite them by number |
| `rules/` | [`platform.md`](rules/platform.md): the platform invariants P1–P16, each linking to the document that carries its reasoning |
| `vectors/` | Conformance vectors: the [grant and leaf format](vectors/grant-and-leaf-format.md) with its cross-language vectors, and the golden receipt set. `SHA256SUMS` pins every file |
| `glossary.md` | [Terms](glossary.md) used across the documents, defined once |

Start with [`spec/receipt-trust-model.md`](spec/receipt-trust-model.md). It names
the four questions a verifier answers — split-view, sealing, authority and
attribution — and the four trust roots a caller can hold: two signature roots
(the forest genesis document, or a known log key) and two accumulator roots (a
known accumulator, or a retained checkpoint chain). They are alternatives, not a
progression; which one applies depends on what the caller already holds, and a
result says which questions the root it used did not answer.

A **forest** is the set of logs anchored by one deployed contract instance.
Its genesis document is written once per forest, at deployment, and records
the bootstrap key the contract binds; there is no per-log genesis.

Then read, in any order:

- [checkpoints and receipts](spec/checkpoints-and-receipts.md) for the wire
  formats and why anyone holding public data can mint a receipt;
- [log authority and grants](spec/log-authority-and-grants.md) for where a
  log's authority comes from;
- [delegation and WebAuthn envelopes](spec/delegation-and-webauthn-envelopes.md)
  for how a root key delegates sealing, and how a passkey signs at all;
- [leaf admission](spec/leaf-admission-and-session-endorsement.md) for who
  may sign an entry;
- [key custody and choice](spec/key-custody-and-choice.md) for where a root
  key can live and how to leave;
- [trust boundaries](spec/trust-boundaries-and-operator-powers.md) for what
  the operator can and cannot do;
- the [label registry](spec/label-registry.md) for every codepoint.

`vectors/` holds the conformance vectors: the cross-language grant and leaf
fixtures, a golden grant receipt that verifies from a forest genesis document,
and a burial bundle of retained checkpoints; [`vectors/README.md`](vectors/README.md)
says what each proves. Terms are defined in [glossary.md](glossary.md), and
[`spec/implementation-status.md`](spec/implementation-status.md) is the one
place that says where an implementation differs from the text.

### By audience

- **Implementing a verifier:** the trust model; checkpoints and receipts; the
  label registry; log authority and grants §2 and §4; delegation §5 and §7;
  leaf admission §3 and §6; then `vectors/`.
- **Implementing a client that writes entries:** log authority and grants;
  leaf admission; delegation; key custody; the label registry.
- **Reviewing the security model:** trust boundaries; key custody; the trust
  model; `rules/platform.md`; then implementation status for the distance
  between the text and the code.

## Conformance

Implementations of the grant and leaf formats and of receipt verification are
expected to pass the vectors under `vectors/`. The bytes were generated by the
TypeScript and Go implementations and frozen here; this repository is now
their source of truth, and the arithmetic is fixed by these public vectors,
not by whoever ships a verifier. [`vectors/README.md`](vectors/README.md)
says what each set proves and what result to expect. To check the vectors
themselves:

```
sha256sum -c vectors/SHA256SUMS
```

CI on this repository renders every diagram, checks that no link points into a
private repository, checks that every vector file is pinned and its digest
matches, recomputes the fixtures from their fields, and verifies the golden
sets with the published verifier at a pinned version.

## Implementations

- `@forestrie/receipt-verify`, `@forestrie/merklelog`, `@forestrie/encoding`:
  the TypeScript verifier libraries, published to npm with provenance from
  [forestrie/canopy](https://github.com/forestrie/canopy).
- [forestrie/forestrie-cli](https://github.com/forestrie/forestrie-cli): the
  command-line client (`verify`, `verify-grant`, `decode-receipt`).
- [forestrie/mcp-verify](https://github.com/forestrie/mcp-verify): the
  verify-only MCP server, `@forestrie/mcp-verify` on npm.
- [forestrie/go-univocity](https://github.com/forestrie/go-univocity) and
  [forestrie/go-merklelog](https://github.com/forestrie/go-merklelog): the Go
  codec and MMR implementation.
- [forestrie/univocity](https://github.com/forestrie/univocity): the on-chain
  contract that anchors checkpoints.

The receipt and proof profile is specified in
[draft-bryce-cose-receipts-mmr-profile](https://datatracker.ietf.org/doc/draft-bryce-cose-receipts-mmr-profile/).

## Licence

MIT. See [LICENSE](LICENSE).
