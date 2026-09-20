# ADR-0066: Signed checkpoint tree sizes — recorded in devdocs

The full record is
**[`devdocs/adr/adr-0066-sec-signed-checkpoint-size.md`](https://github.com/forestrie/devdocs/blob/main/adr/adr-0066-sec-signed-checkpoint-size.md)**
(plan-2609-10, FOR-568).

**Status:** ACCEPTED, 2026-09-19; amended 2026-09-20. The checkpoint
receipt's `tree-size-2` is carried under the signature as a dedicated
protected-header label (`-65933`; profile draft `TBD_2`; `-65932` withdrawn),
the protected header is deterministic CBOR (D9), and every consistency
verifier takes `tree-size-1` from trusted state, requires the signed
`tree-size-2` to equal the declared one, and runs the size-driven fold. The
current statement is [spec/checkpoints-and-receipts.md](../spec/checkpoints-and-receipts.md)
§1.3 and [spec/label-registry.md](../spec/label-registry.md) §2.2.
