# ts-radius-client

A standards-compliant RADIUS client for TypeScript/Bun, extracted from a production OAuth2 proxy.

## Features

- **Standards Compliant**: Supports RFC 2865 (PAP/CHAP authentication) and RFC 2869.
- **Accounting Support**: Sends RFC 2866 Accounting-Request packets (Start, Interim-Update, Stop).
- **Dynamic Authorization**: Supports RFC 5176 CoA and Disconnect requests (ACK/NAK + Error-Cause).
- **Failover**: Automatic failover to backup hosts on timeout.
- **Health Checks**: Background health checks to restore primary hosts.
- **Configurable**: extensive configuration for timeouts, retries, and attribute extraction.
- **TypeScript**: Written in TypeScript with full type definitions.
- **Bun**: Optimized for Bun runtime.

## Installation

Install directly from GitHub:

```bash
bun add github:essinghigh-org/ts-radius
```

## Usage

```typescript
import { RadiusClient, RadiusConfig } from "ts-radius-client";

const config: RadiusConfig = {
  host: "10.0.0.1",
  hosts: ["10.0.0.1", "10.0.0.2"], // Failover hosts
  secret: "my-shared-secret",
  timeoutMs: 5000,
  accountingPort: 1813,
  healthCheckUser: "probe-user",
  healthCheckPassword: "probe-password",
};

const client = new RadiusClient(config);

try {
  const result = await client.authenticate("username", "password");

  if (result.ok) {
    console.log("Authentication successful!");
    if (result.class) {
      console.log("Received Class attribute:", result.class);
    }
  } else {
    console.log("Authentication failed:", result.error || "Unknown error");
  }

  await client.accountingStart({
    username: "username",
    sessionId: "session-123"
  });

  await client.accountingInterim({
    username: "username",
    sessionId: "session-123",
    sessionTime: 300,
    inputOctets64: 0x1_0000_0200n,
    outputOctets64: 0x1_0000_0400n
  });

  await client.accountingStop({
    username: "username",
    sessionId: "session-123",
    sessionTime: 600,
    terminateCause: 1
  });

  await client.sendCoa({
    username: "username",
    sessionId: "session-123",
    attributes: [{ type: 11, value: "new-filter" }]
  });

  await client.sendDisconnect({
    username: "username",
    sessionId: "session-123"
  });
} catch (err) {
  console.error("Client error:", err);
} finally {
  // Clean up timers if shutting down the app
  client.shutdown();
}
```

`radiusStatusServerProbe` is part of the public root export for direct probe calls:

```typescript
import { radiusStatusServerProbe } from "ts-radius-client";
```

## Configuration (`RadiusConfig`)

| Option | Type | Default | Description |
|---|---|---|---|
| `host` | `string` | (Required) | Primary RADIUS host IP/hostname. |
| `hosts` | `string[]` | `[host]` | Ordered list of hosts for failover. |
| `secret` | `string` | (Required) | Shared secret. |
| `port` | `number` | `1812` | RADIUS port. |
| `accountingPort` | `number` | `1813` | RADIUS accounting port used by `sendAccounting`, `accountingStart`, `accountingInterim`, and `accountingStop`. |
| `dynamicAuthorizationPort` | `number` | `3799` | CoA/Disconnect UDP port used by `sendCoa` and `sendDisconnect`. |
| `timeoutMs` | `number` | `5000` | Request timeout in milliseconds. |
| `authMethod` | `'pap' \| 'chap'` | `'pap'` | Access-Request password encoding mode. |
| `chapId` | `number` | random `0..255` | Optional deterministic CHAP identifier override when `authMethod` is `'chap'`. |
| `chapChallenge` | `Buffer` | random 16 bytes | Optional deterministic CHAP challenge override when `authMethod` is `'chap'`. |
| `healthCheckIntervalMs` | `number` | `1800000` | (30m) Interval for background health checks. |
| `healthCheckProbeMode` | `'auth' \| 'status-server'` | `'auth'` | Probe mode for health checks. `'status-server'` uses RFC3539-oriented probes (see RFC 3539; also referenced by RFC 2865) and falls back to Access-Request auth probes (RFC 2865) for compatibility. |
| `healthCheckTimeoutMs` | `number` | `5000` | Timeout for health-check probe requests. |
| `healthCheckUser` | `string` | (Required) | Username for health probes. |
| `healthCheckPassword` | `string` | (Required) | Password for health probes. |
| `retry` | `object` | `{ maxAttempts: 1 }` | Retry policy for transport failures during `authenticate`, accounting operations, `sendCoa`, and `sendDisconnect`. |
| `retry.maxAttempts` | `number` | `1` | Total attempts per call for `authenticate`, accounting operations, `sendCoa`, and `sendDisconnect`, including the first. |
| `retry.initialDelayMs` | `number` | `100` | Base delay before the first retry attempt (milliseconds). |
| `retry.backoffMultiplier` | `number` | `2` | Exponential multiplier for retry delays. |
| `retry.maxDelayMs` | `number` | `5000` | Maximum delay cap for retries (milliseconds). |
| `retry.jitterRatio` | `number` | `0` | Symmetric jitter ratio in range `[0,1]` (e.g. `0.5` = ±50%). |
| `dynamicAuthorizationRetryIdentityMode` | `'per_attempt' \| 'stable'` | `'per_attempt'` | CoA/Disconnect retry identity mode. `stable` reuses the same RFC5176 Identifier + Request Authenticator for all retries in a single call. |
| `assignmentAttributeId` | `number` | `25` | Attribute ID to extract (e.g., 25 for Class). |
| `vendorId` | `number` | `undefined` | Vendor-Id for VSA extraction when `assignmentAttributeId` is `26`. |
| `vendorType` | `number` | `undefined` | Vendor-Type for VSA extraction when `assignmentAttributeId` is `26`. |
| `valuePattern` | `string` | `undefined` | Optional regex used to extract a subgroup from the assignment attribute value. |
| `validateResponseSource` | `boolean` | `true` | Validates response source host/port against request target host/port. |
| `responseMessageAuthenticatorPolicy` | `'compatibility' \| 'strict'` | `'compatibility'` | Access-response Message-Authenticator handling (`strict` rejects invalid/missing values). |
| `responseLengthValidationPolicy` | `'strict' \| 'allow_trailing_bytes'` | `'strict'` | Low-level response length policy; `allow_trailing_bytes` trims extra datagram bytes beyond declared RADIUS length. |

## Advanced options parity matrix

| Operation / path | Retry behavior (`retry.*`) | Advanced options forwarded / applied | Notes |
|---|---|---|---|
| `authenticate` | ✅ Retries up to `retry.maxAttempts` on: `timeout`, `malformed_response`, `authenticator_mismatch`, `unknown_code` | `validateResponseSource`, `responseLengthValidationPolicy`, `responseMessageAuthenticatorPolicy`, `authMethod`, `chapId`, `chapChallenge`, `assignmentAttributeId`, `vendorId`, `vendorType`, `valuePattern` | `access_reject` and `access_challenge` are terminal for the call (no retry). Timeout still triggers async health verification/failover logic. |
| `sendAccounting` (`accountingStart` / `accountingInterim` / `accountingStop` / `accountingOn` / `accountingOff`) | ✅ Retries up to `retry.maxAttempts` on: `timeout`, `malformed_response`, `identifier_mismatch`, `authenticator_mismatch`, `unknown_code` | `validateResponseSource`, `responseLengthValidationPolicy`, `responseMessageAuthenticatorPolicy` | Uses `accountingPort` (or `port`, default 1813). Helpers map to `Acct-Status-Type` values, including `Accounting-On` and `Accounting-Off`. |
| `sendCoa` | ✅ Retries up to `retry.maxAttempts` on: `timeout`, `malformed_response`, `identifier_mismatch`, `authenticator_mismatch`, `unknown_code` | `validateResponseSource`, `responseLengthValidationPolicy`, `responseMessageAuthenticatorPolicy`, `dynamicAuthorizationRetryIdentityMode` | `coa_nak` is terminal (no retry). `dynamicAuthorizationRetryIdentityMode: "stable"` reuses one Identifier/Request-Authenticator across attempts. |
| `sendDisconnect` | ✅ Retries up to `retry.maxAttempts` on: `timeout`, `malformed_response`, `identifier_mismatch`, `authenticator_mismatch`, `unknown_code` | `validateResponseSource`, `responseLengthValidationPolicy`, `responseMessageAuthenticatorPolicy`, `dynamicAuthorizationRetryIdentityMode` | `disconnect_nak` is terminal (no retry). Same retry identity behavior as CoA. |
| health probes (`failover` / background checks) | 🚫 `retry.*` is not used for probe calls (single probe attempt per host per cycle) | `healthCheckProbeMode`, `healthCheckTimeoutMs`; auth/status-server probe path applies `validateResponseSource`, `authMethod`, `chapId`, `chapChallenge` | `healthCheckProbeMode: "status-server"` first uses `radiusStatusServerProbe`; non-healthy results/errors fall back to auth probes for compatibility. Accounting/CoA/Disconnect timeout probe paths currently do not forward `validateResponseSource` (they use protocol default strict source validation, effectively `true`). Probe paths currently use strict length handling (no `responseLengthValidationPolicy` forwarding). |

## Feature parity highlights

| Feature | Public API surface | Runtime behavior |
|---|---|---|
| Access-Challenge continuation | `radiusAuthenticateWithContinuation`, `radiusContinueAuthenticate` | `maxChallengeRounds` defaults to 3. Continuation context carries `State`/`Proxy-State`; malformed/missing context returns `malformed_challenge_context`; limit overflow returns `challenge_round_limit_exceeded`. |
| CHAP authentication | `authenticate` + auth health probes (including status-server fallback auth probes) | `authMethod: "chap"` enables CHAP credentials. `chapId` and `chapChallenge` can be set for deterministic behavior. |
| Accounting On/Off operations | `accountingOn`, `accountingOff` (both call `sendAccounting`) | Encodes `Acct-Status-Type` as `Accounting-On` / `Accounting-Off`. `username` and `sessionId` are optional for On/Off variants. |
| Dynamic authorization retry identity | `sendCoa`, `sendDisconnect`, `dynamicAuthorizationRetryIdentityMode` | `per_attempt` (default) uses a fresh identity each attempt; `stable` reuses one identity across retries in a single send call. |
| 64-bit accounting counters | `sendAccounting` and accounting helpers | `inputOctets64` / `outputOctets64` are split into low/high words (`42/52`, `43/53`) and take precedence over 32-bit fields when both are provided. |

### Validation policy notes

- `validateResponseSource` defaults to `true` and is enforced for all top-level client operations.
- Health-probe caveat: auth/status-server probe paths forward `validateResponseSource`, but accounting/CoA/disconnect timeout probe paths currently do not forward this flag and therefore use default strict source validation (`true`).
- `responseMessageAuthenticatorPolicy` affects Access responses (authentication and auth health probes):
  - `compatibility`: warn on invalid Message-Authenticator and continue.
  - `strict`: reject missing/invalid Message-Authenticator as `malformed_response`.
- `responseLengthValidationPolicy` is forwarded to `authenticate`, accounting, CoA, and Disconnect operations:
  - `strict`: declared RADIUS length must equal UDP datagram length.
  - `allow_trailing_bytes`: accepts trailing bytes and parses only the declared packet length.

### Assignment extraction knobs

- `assignmentAttributeId` selects which attribute is extracted into `result.class`.
- For Vendor-Specific extraction (`assignmentAttributeId: 26`), set both `vendorId` and `vendorType`.
- `valuePattern` can return either capture group 1 (if present) or full regex match.

## License

MIT
