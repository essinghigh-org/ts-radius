# Protocol fixtures

Deterministic RFC-driven packet vectors live under:

- `tests/fixtures/protocol/rfc2865/packets/`
- `tests/fixtures/protocol/rfc2869/packets/`
- `tests/fixtures/protocol/rfc5176/packets/`

### Fixture format

Packet fixtures use JSON and include:

- `packetHex`: canonical packet bytes
- `expected`: parsed packet expectations (header + attributes)
- `authenticatorHexPattern`: allows wildcard bytes (`??`) for non-deterministic fields

These fixtures are consumed by `tests/helpers/packet-fixtures.ts` so future protocol TDD can assert packet bytes without depending on randomness.

### Schema location and validation

- Fixture files must be loaded via paths relative to `tests/fixtures/`.
- Structural validation currently lives in `tests/helpers/packet-fixtures.ts` (`isRadiusPacketFixture`).
- There is no standalone JSON Schema file yet, so `$schema` references are intentionally omitted.
- If a standalone schema is introduced later, place it under `tests/fixtures/schema/` and document its relative reference path from fixture files.