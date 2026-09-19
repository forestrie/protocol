# ADR-0066: Signed checkpoint tree sizes — recorded in devdocs

The full record is
**[`devdocs/adr/adr-0066-sec-signed-checkpoint-size.md`](https://github.com/forestrie/devdocs/blob/main/adr/adr-0066-sec-signed-checkpoint-size.md)**
(plan-2609-10, FOR-568).

**Status:** ACCEPTED, 2026-09-19. The checkpoint receipt's `tree-size-1` and
`tree-size-2` are carried under the signature as dedicated protected-header
labels (`-65932`, `-65933`; profile draft `TBD_2`/`TBD_3`), and every
consistency verifier takes `tree-size-1` from trusted state, requires the
signed sizes to equal the declared ones, and runs the size-driven fold. The
current statement is [spec/checkpoints-and-receipts.md](../spec/checkpoints-and-receipts.md)
§1.3 and [spec/label-registry.md](../spec/label-registry.md) §2.2.
