# Implementation status

**Audience:** implementers checking whether a specified behaviour is built,
and reviewers checking that the specification and the code agree.
**Related:** every document under `spec/`, each of which links here rather
than describing implementation state inline.

## What this document is

The specification describes the protocol. Where an implementation does not
yet do what the specification says, or does something the specification says
it should not, that fact is recorded **here and nowhere else**. An entry
names the component, what it does, what the specification says, and where
the work is tracked when a public tracker exists. An entry is removed when
the code and the specification agree.

Nothing in this document changes what a receipt, a grant or a trust root
means. It records distance from the specification, not decisions about it.

## Verifiers

| Component | What it does | What the specification says | Tracked |
|---|---|---|---|
| Every verifier — the off-chain grant-chain walk | Reaches the authority anchor on-chain, or off-chain only as far as a delegation certificate reaches. No verifier walks from grant records and their inclusion proofs to the forest genesis document | [receipt-trust-model.md](./receipt-trust-model.md) question 3 describes the walk as one of the three routes to an authority answer; under the signature roots a deeper child log's authority needs it | No public tracker |
| The command-line client and the MCP verification server — attribution | Neither runs the endorsed-leaf check. The TypeScript library exposes it as `verifyEndorsedLeaf` | [receipt-trust-model.md](./receipt-trust-model.md) question 4: attribution is answerable from the entry bytes and the log's root key under every root | No public tracker |
| The command-line client — the `--genesis` help text | Says the genesis root "derives" the key-to-log binding "from the grant chain", which is the walk above | The same | [forestrie-cli #57](https://github.com/forestrie/forestrie-cli/pull/57) |
| The Go log library — the idtimestamp byte splitter | Guards `len(b) < 8` and then reads `b[1:]`, so an exactly 8-byte input panics instead of being rejected | [checkpoints-and-receipts.md](./checkpoints-and-receipts.md) §5: the identifier is 8 bytes | [go-merklelog #10](https://github.com/forestrie/go-merklelog/pull/10) |
| The TypeScript verifier library — endorsement verification cache | No cache of verified endorsements exists | [leaf-admission-and-session-endorsement.md](./leaf-admission-and-session-endorsement.md) §5.4 constrains one if it is ever added | Not planned |

## The contract

| Component | What it does | What the specification says | Tracked |
|---|---|---|---|
| Origin pinning | The delegation verifier implements the `rpIdHash` comparison in full; both production call sites pass a zero pin, which disables it. No policy channel can enable it per log | [delegation-and-webauthn-envelopes.md](./delegation-and-webauthn-envelopes.md) §6: the design intent is per-log policy over the same grant-flag channel as user verification; the contract's own comment notes a 32-byte hash does not fit a grant flag, so the channel is undecided | Tracked in the operator's private tracker |
| The leaf-encoding library's padding comment | Says the log id is right-padded to 32 bytes; every producer left-pads and the hashes agree, so only the comment is wrong | [log-authority-and-grants.md](./log-authority-and-grants.md) §4 | [univocity #41](https://github.com/forestrie/univocity/issues/41) |
| The exclusion trie root | Not anchored on-chain, so no succinct absence proof exists | [trust-boundaries-and-operator-powers.md](./trust-boundaries-and-operator-powers.md) §6: absence is provable against a replicated log; the succinct form needs an authenticated secondary index. How to anchor the root is open | No public tracker |

## Operator services and libraries

| Component | What it does | What the specification says | Tracked |
|---|---|---|---|
| The admission edge and the client pre-flight — user verification policy | The edge derives the requirement from the grant flag; the client pre-flight derives it from deployment configuration. They can disagree, and then a turn the user has already paid for is refused after the fact | [leaf-admission-and-session-endorsement.md](./leaf-admission-and-session-endorsement.md) §5.2: the grant flag is the one declaration | Tracked in the operator's private tracker |
| The Go log library and the certificate builders — CBOR map key order | The checkpoint protected header is encoded with length-first canonical key order, which [ADR-0066](../decisions/adr-0066-sec-signed-checkpoint-size.md) D9 now specifies and every verifier enforces; certificates use core-deterministic order. The two agree while every map label is a single byte; the certificate maps are in that band | [rules/platform.md](../rules/platform.md) P16 names the checkpoint envelope's order as the one exception to core-deterministic encoding | Closed by ADR-0066 D9 for checkpoints; the certificate order is unchanged |
| The admission edge and the browser client — timing constants | The endorsement not-before skew is declared in both, independently; the browser's not-before backdate is sized against that skew with no code linkage | [leaf-admission-and-session-endorsement.md](./leaf-admission-and-session-endorsement.md) §7 lists the values that must agree | No public tracker |
| Every TypeScript consumer — codepoint constants | Most sites re-declare the numbers instead of importing them from the encoding package | [label-registry.md](./label-registry.md): the "Declared in" column names the module to import from | No public tracker |
| The encoding package — the `-65800` header label | Declared as a literal alias of the algorithm constant | [label-registry.md](./label-registry.md) §4: `TBD1` is the envelope label and needs its own assignment | No public tracker |
| The command-line client and the MCP verification server — display names | The MCP server's label table omits the `-65800` header entry, `-65933` and `-66535`; both tools' notes for `395` and `396` predate the RFC; the client's `-65800` algorithm string omits session-key endorsements | [label-registry.md](./label-registry.md): one display name per codepoint, adopted in the order registry, client, server | Client: [forestrie-cli #57](https://github.com/forestrie/forestrie-cli/pull/57); the server follows |

## Designed, not built

These are accepted direction with no implementation. The specification does
not describe them as shipped behaviour, and nothing should be reviewed
against them as if it were.

- **Multi-key endorsement for recovery.** The intended answer to root loss
  under a software root is for the authority to endorse more than one key per
  log ([key-custody-and-choice.md](./key-custody-and-choice.md) §5).
- **A succinct-absence secondary index.** Depends on anchoring the exclusion
  trie root, above.
- **Bonded, tracked and slashed reputation.** Assessor standing as on-chain
  history plus bond plus delegated stake, so that recognition and Sybil cost
  are one property set by hierarchy position. Nothing in `spec/` describes it.
