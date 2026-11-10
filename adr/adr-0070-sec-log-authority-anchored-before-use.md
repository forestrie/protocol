---
id: adr-0070-sec-log-authority-anchored-before-use
title: A log's authority is used only once it is anchored on chain
status: discuss
created: 2026-11-09
updated: 2026-11-10
categories: [SECURITY, AUTHORITY]
decisions: [adr-0045-receipt-verify-offline-contract]
refs: ["devdocs:ADR-0075"]
---

# A log's authority is used only once it is anchored on chain

## Context

The [receipt trust model](../spec/receipt-trust-model.md#3-authority--is-this-log-authorised-back-to-the-genesis--bootstrap-key)
answers "is this log authorised?" with the grant hierarchy. A child log's
authority is the inclusion of its create grant in its owner log, walked up to
the bootstrap key. Operator storage that surfaces the hierarchy is a
convenience, not a trust source.

An operator still has to answer the question at admission, before it
sequences a statement: does this signer speak for this log? Until now an
operator could take a log's root key from its own storage as soon as some
grant named it, before anything about that log was anchored. That storage can
be written by parties other than the log's owner, and the key in it need not
be the key the chain later records for the log.

The contract fixes each key once:

- The forest root's key is the bootstrap key, bound into the contract at
  deployment.
- Any other log's root key is set at that log's first published checkpoint.
  It is the `grantData` of a create grant whose inclusion in the owner log the
  contract proves against the accumulator it holds for the owner.

So a log's key is decided by the chain as soon as a published checkpoint of
its owner covers its create grant. That is before the log's own first
checkpoint, which cannot happen until the log has entries.

## Decision

1. **A log's authority is anchored when one of these holds:**
   - the log is the forest root and its contract is deployed. The root's key
     is the contract's bootstrap key. A genesis document cannot substitute for
     it, and a root whose contract is not yet deployed is pending;
   - the log has a published checkpoint, so the contract holds its root key;
   - its create grant is included in a published checkpoint of its owner log,
     proved against the accumulator the contract holds for the owner.

   The anchored key is the bootstrap key, the contract's root key for the log,
   or that create grant's `grantData`, respectively. An operator that holds a
   claim for the log takes the contract's key only if it matches the claim
   (decision 6).
2. **Until then the log's authority is pending, and nothing that depends on it
   is admitted.** An operator refuses, before sequencing, every statement
   whose authority runs through a pending log: statements in that log and
   grants it issues. The refusal tells the caller to retry later. A signed
   grant is not sequenced ([P12](../rules/platform.md)), and a sequenced
   grant is not anchored.
3. **Anchoring is permanent, with one check left.** Accumulators only grow
   and the contract sets each key once, so an anchored log's key never
   changes. One check remains, made once, when the log's own first checkpoint
   is published (decision 6). After it the log is never re-evaluated. The
   chain is read at most twice per log, not once per statement
   ([P5](../rules/platform.md)).
4. **Steps that lead to anchoring are allowed while pending**, because the
   contract checks them again at publish. An operator may record the claim of
   a log's create grant, and accept a delegation certificate under the key
   that grant names. If that key is wrong, the log cannot be checkpointed; no
   other log's authority is affected. A claim whose grant is not committed
   for sequencing is a reservation, and lapses after a time the operator
   sets. A claim whose grant is committed does not lapse, because the grant
   is then in the owner's log for good.
5. **The chain paces onboarding.** A log takes its first statement after the
   owner's next published checkpoint that covers its create grant. A log n
   levels below the root needs n publishes in turn. This is intended.
6. **A log whose chain record differs from its claim is conflicted, and is
   not used.** The contract takes a log's owner and key from the create grant
   presented with the log's first checkpoint, and nothing the log's key signs
   names its owner. So the chain can record a different owner, or a different
   owner and key, from the claim an operator holds for that log id. An
   operator compares the owner and key the chain records at the log's first
   checkpoint with its claim. If they differ, the log is **conflicted**: the
   operator admits, seals and publishes nothing more for it, whatever it
   answered before. Conflicted is final.

Grant verification is still three-part ([P10](../rules/platform.md)). This
decision adds a precondition to admission; it does not replace any of the
three parts.

## Consequences

- At admission, the key an operator uses for a log is the key the chain holds
  or will hold for it. Operator storage stops being a source of authority at
  admission, as the trust model already requires for verification.
- Position metadata cannot make a grant usable. The grant's leaf is found by
  matching its commitment in the owner's log and is then proved against the
  owner's accumulator, so no stored position is trusted.
- [Platform rule P17](../rules/platform.md) states this decision, and
  [log-authority-and-grants.md](../spec/log-authority-and-grants.md) §5.1
  carries it.
- The chain can still record a different owner, or a different owner and
  key, from an operator's claim. Either the owner signed two create grants for
  the log, which claiming once refuses at the operator, or another owner log
  on the same instance named the log in a create grant of its own and reached
  the chain first. Decision 6 detects both and stops using the log, whose
  creator then starts a new one. Binding a log id to its owner on chain would
  prevent the second case; it is left to a later decision.
- A client that creates a log and then writes to it must wait, or retry, until
  the log is anchored. How long it waits depends on how often the owner's
  checkpoints are published.
- Offline verification is unchanged. It already takes no key from operator
  storage ([ADR-0045](../decisions/adr-0045-receipt-verify-offline-contract.md)).

## Alternatives Considered

- **Trust the operator's stored key until the log's own first checkpoint.**
  This was the earlier behaviour. It is rejected because the stored key can be
  written by someone other than the owner and is not bound to the chain.
- **Anchor at the log's own first checkpoint.** It is rejected because it
  deadlocks: a log cannot be checkpointed until it has entries, and it could
  take none while pending.
- **Anchor at the owner's sealed checkpoint, before it is published.** It would
  be faster. It is rejected because the contract has not gated a sealed
  checkpoint for consistency, so the operator could still show two histories
  ([P4](../rules/platform.md)).
- **Admit optimistically and mark entries pending until anchored.** It is
  rejected because committed history is permanent ([P9](../rules/platform.md)).
  A statement admitted under a key that turns out to be wrong cannot be
  removed. Failing safe means refusing before sequencing.
- **Bind a log id to its owner on chain now.** It would stop another owner
  log taking a claimed log id at its first checkpoint, which decision 6 only
  detects. It is deferred: it changes the contract and how every log id is
  made, and detection limits the harm to a log its creator replaces.

## References

- [Receipt trust model, question 3](../spec/receipt-trust-model.md#3-authority--is-this-log-authorised-back-to-the-genesis--bootstrap-key):
  authority is the grant hierarchy, not operator storage.
- [Platform rules](../rules/platform.md): P4 (non-equivocation by the
  contract), P5 (the chain is never the hot path), P9 (append-only), P10
  (three-part grant verification), P12 (signed is not sequenced), P14 (one
  instance root, set once).
- [ADR-0045 offline receipt verification](../decisions/adr-0045-receipt-verify-offline-contract.md).
