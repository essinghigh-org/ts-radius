# Protocol fixtures

Deterministic RFC-driven packet vectors live under:

- `protocol/rfc2865/packets/`
- `protocol/rfc2869/packets/`

### Fixture format

Packet fixtures use JSON and include:

- `packetHex`: canonical packet bytes
- `expected`: parsed packet expectations (header + attributes)
- `authenticatorHexPattern`: allows wildcard bytes (`??`) for non-deterministic fields

These fixtures are consumed by `tests/helpers/packet-fixtures.ts` so future protocol TDD can assert packet bytes without depending on randomness.