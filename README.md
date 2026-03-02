# ts-radius-client

A standards-compliant RADIUS client for TypeScript/Bun, extracted from a production OAuth2 proxy.

## Features

- **Standards Compliant**: Supports RFC 2865 (PAP authentication) and RFC 2869.
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
    inputOctets: 1024,
    outputOctets: 2048
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
| `healthCheckIntervalMs` | `number` | `1800000` | (30m) Interval for background health checks. |
| `healthCheckProbeMode` | `'auth' \| 'status-server'` | `'auth'` | Probe mode for health checks. `'status-server'` uses RFC3539-oriented probes (see RFC 3539; also referenced by RFC 2865) and falls back to Access-Request auth probes (RFC 2865) for compatibility. |
| `healthCheckTimeoutMs` | `number` | `5000` | Timeout for health-check probe requests. |
| `healthCheckUser` | `string` | (Required) | Username for health probes. |
| `healthCheckPassword` | `string` | (Required) | Password for health probes. |
| `retry` | `object` | `{ maxAttempts: 1 }` | Retry policy for transport failures during `authenticate`. |
| `retry.maxAttempts` | `number` | `1` | Total auth attempts per call, including the first. |
| `retry.initialDelayMs` | `number` | `100` | Base delay before the first retry attempt (milliseconds). |
| `retry.backoffMultiplier` | `number` | `2` | Exponential multiplier for retry delays. |
| `retry.maxDelayMs` | `number` | `5000` | Maximum delay cap for retries (milliseconds). |
| `retry.jitterRatio` | `number` | `0` | Symmetric jitter ratio in range `[0,1]` (e.g. `0.5` = ±50%). |
| `assignmentAttributeId` | `number` | `25` | Attribute ID to extract (e.g., 25 for Class). |

## License

MIT
