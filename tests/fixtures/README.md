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
- Canonical JSON Schema lives at `tests/fixtures/schema/radius-packet-fixture.schema.json`.
- `loadRadiusPacketFixture` in `tests/helpers/packet-fixtures.ts` validates every fixture JSON document against this schema before returning it.
- Validation is strict (`additionalProperties: false` on fixture objects and attribute entries), so unknown fields are rejected.
- Fixture files may optionally include a `$schema` reference, but it is not required for runtime validation because the test helper loads the schema directly.