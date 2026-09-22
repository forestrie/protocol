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
| `spec/` | The protocol documents: [receipt trust model](spec/receipt-trust-model.md), [checkpoints and receipts](spec/checkpoints-and-receipts.md), [log authority and grants](spec/log-authority-and-grants.md), [leaf admission and session endorsement](spec/leaf-admission-and-session-endorsement.md), [delegation and WebAuthn envelopes](spec/delegation-and-webauthn-envelopes.md), [key custody and choice](spec/key-custody-and-choice.md), [trust boundaries and operator powers](spec/trust-boundaries-and-operator-powers.md), and the [COSE label registry](spec/label-registry.md) |
| `decisions/` | The accepted decisions the specification rests on: [ADR-0045](decisions/adr-0045-receipt-verify-offline-contract.md), [ADR-0064](decisions/adr-0064-passkey-session-key-endorsement.md), [ADR-0065](decisions/adr-0065-endorsed-session-key-admission.md), [ADR-0066](decisions/adr-0066-sec-signed-checkpoint-size.md), [ARC-0019](decisions/arc-0019-grant-verification-model.md). They are historical records in their own voice; where a decision and `spec/` differ in wording, `spec/` is the current statement. Numbers are stable identifiers; implementations may cite them by number |
| `rules/` | [`platform.md`](rules/platform.md): the platform invariants P1–P16, each linking to the document that carries its reasoning |
| `vectors/` | The protocol's formats and hashes as bytes: the [grant and leaf fixtures](vectors/grant-and-leaf-format.md), the [checkpoint receipt KAT-39](vectors/checkpoint-receipt-format.md), and the golden receipt sets. Every implementation tests against them; see [Conformance vectors](#conformance-vectors) |
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
says what each proves. Terms are defined in [glossary.md](glossary.md).

## Conformance vectors

The documents under `spec/` say what the formats and hashes are in prose and
CDDL. The files under `vectors/` say it in bytes. Where a reading of the prose
and the bytes could differ, the bytes are the protocol, and they belong to no
implementation.

| Set | What it holds | What it settles |
|---|---|---|
| `vectors/fixtures/leaf_vectors.json`, `grant_vectors.json` | grant fields with the exact CBOR and the digests they must produce | the grant wire map and the leaf commitment, in every language |
| `vectors/fixtures/grant_vectors_negative.json` | grant maps a decoder must refuse | that the retired keys stay retired |
| `vectors/fixtures/checkpoint-receipt-kat39.json` | a 39-node tree, every consistency pair, rejected proof shapes, protected-header classes, signed receipts of consistency | the consistency fold and the checkpoint signature rules of [checkpoints and receipts](spec/checkpoints-and-receipts.md) §1.3 |
| `vectors/golden/` | a forest genesis document with a sealed grant's receipt; a retained checkpoint chain with a receipt whose peak the log has since buried | that a receipt verifies from a trust root using nothing but these files |

**How they are used.** An implementation copies the files it needs into its
own test suite and asserts against them; the Go, TypeScript and Solidity
implementations listed below do this. Someone implementing a verifier from
`spec/` checks their work against the same bytes. [`vectors/README.md`](vectors/README.md)
names, for each set, the verifier entry point, the trust root, and the result
to expect for the clean case and for each tampered case.

**What keeps them trustworthy.** The bytes are frozen and pinned in
`vectors/SHA256SUMS`; a change to a vector is a protocol change and lands
with the decision that made it. CI checks that every data file under
`vectors/` is pinned and matches its digest, that the field-derived fixtures
recompute from their fields, and that the golden sets verify with the
published verifier at a pinned version, so a vector cannot contradict the
specification or the shipped code without the build saying so. To check the
pins yourself:

```
sha256sum -c vectors/SHA256SUMS
```

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
