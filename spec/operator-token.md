# The operator token

**Audience:** operators, and implementers of the registration and
onboarding paths.
**Related:**
[log-authority-and-grants.md](./log-authority-and-grants.md) (§5, how a log
gains authority),
[trust-boundaries-and-operator-powers.md](./trust-boundaries-and-operator-powers.md)
(the hosting operator),
[key-custody-and-choice.md](./key-custody-and-choice.md) (§3.5, custodial
logs), [rules/platform.md](../rules/platform.md) P6 and P18.

## Summary

An operator token is a credential that an operator's own services accept
from the operator. Onboard tokens and the delegation coordinator's
application token are examples. It is not part of the protocol's authority
model: no grant, statement, checkpoint or receipt carries it, and no
verifier checks it. Authority comes from grants and their receipts (P6).

An onboard token bought through self-service onboarding is not an operator
token. Any root holder can obtain one by paying for an instance, without
the operator's discretion: it is a payment receipt that genesis redeems.
An onboard token that operations mint directly (break-glass) is an operator
token.

## What it is for

The token serves two purposes, and only these:

1. **An operator onboarding its own logs.** Someone running the operator
   software uses their own logs for their own operational or commercial
   purposes. Logs onboarded this way are owned by that operator. They may
   use the custodial signing model
   ([key-custody-and-choice.md](./key-custody-and-choice.md) §3.5), though
   they need not.
2. **A direct console relationship.** An operator wants a closer
   relationship with consoles and applications built from the mandate and
   thinker templates.

## What it is not

It is not the way a root holder onboards. A root holder's logs, and their
children, need no operator credential and no bootstrap or special log:

- The forest root is created by its genesis.
- A child log is created by a create grant that its parent's owner signs.
  The operator registers the grant and forwards it for sequencing. Preparing
  a child before it exists records a reservation under that parent-signed
  grant ([log-authority-and-grants.md](./log-authority-and-grants.md) §5).

Both paths are permissionless in the sense of P6: what the operator checks
is the grant chain, not who is asking.

## For implementations

Where an implementation checks the operator token (an onboard-token mint,
registration of a grant, preparing a child, the coordinator's routes), the
check gates only the two purposes above. A path that requires the token for
a root holder's log, or for that log's children, is a defect against P18.
