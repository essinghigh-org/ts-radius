# ts-radius-client

A standards-compliant RADIUS client for TypeScript/Bun, extracted from a production OAuth2 proxy.

## Features

- **Standards Compliant**: Supports RFC 2865 (PAP authentication) and RFC 2869.
- **Accounting Support**: Sends RFC 2866 Accounting-Request packets (Start, Interim-Update, Stop).
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
} catch (err) {
  console.error("Client error:", err);
} finally {
  // Clean up timers if shutting down the app
  client.shutdown();
}
```

## Configuration (`RadiusConfig`)

| Option | Type | Default | Description |
|Prefix|---|---|---|
| `host` | `string` | (Required) | Primary RADIUS host IP/hostname. |
| `hosts` | `string[]` | `[host]` | Ordered list of hosts for failover. |
| `secret` | `string` | (Required) | Shared secret. |
| `port` | `number` | `1812` | RADIUS port. |
| `accountingPort` | `number` | `1813` | RADIUS accounting port used by `sendAccounting*` APIs. |
| `timeoutMs` | `number` | `5000` | Request timeout in milliseconds. |
| `healthCheckIntervalMs` | `number` | `1800000` | (30m) Interval for background health checks. |
| `healthCheckTimeoutMs` | `number` | `5000` | Timeout for health-check probe requests. |
| `healthCheckUser` | `string` | (Required) | Username for health probes. |
| `healthCheckPassword` | `string` | (Required) | Password for health probes. |
| `assignmentAttributeId` | `number` | `25` | Attribute ID to extract (e.g., 25 for Class). |

## License

MIT
