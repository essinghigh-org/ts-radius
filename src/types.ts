export interface Logger {
  debug(message: string, ...args: unknown[]): void;
  info(message: string, ...args: unknown[]): void;
  warn(message: string, ...args: unknown[]): void;
  error(message: string, ...args: unknown[]): void;
}

export class ConsoleLogger implements Logger {
  debug(message: string, ...args: unknown[]): void {
    console.log(`[debug] ${message}`, ...args);
  }
  info(message: string, ...args: unknown[]): void {
    console.info(`[info] ${message}`, ...args);
  }
  warn(message: string, ...args: unknown[]): void {
    console.warn(`[warn] ${message}`, ...args);
  }
  error(message: string, ...args: unknown[]): void {
    console.error(`[error] ${message}`, ...args);
  }
}

export interface ParsedAttribute {
  id: number;
  name: string;
  value: unknown;
  raw: string; // Hex string of value for reference
}

export interface VendorSpecificAttribute {
  id: 26;
  name: "Vendor-Specific";
  vendorId: number;
  value: unknown; // If parsed, structure; else hex string
  raw: string;
}

export type ParsedRadiusAttribute = ParsedAttribute | VendorSpecificAttribute;

export interface RadiusResult {
  ok: boolean;
  class?: string;
  attributes?: ParsedRadiusAttribute[];
  raw?: string;
  error?: string;
}

export interface RadiusProtocolOptions {
  secret: string;
  port?: number;
  timeoutMs?: number;
  assignmentAttributeId?: number;
  vendorId?: number;
  vendorType?: number;
  valuePattern?: string;
}

export interface RadiusRetryOptions {
  /** Total auth attempts per call, including the first attempt (default: 1) */
  maxAttempts?: number;
  /** Base delay before retry #1 in milliseconds (default: 100) */
  initialDelayMs?: number;
  /** Exponential multiplier for subsequent retry delays (default: 2) */
  backoffMultiplier?: number;
  /** Maximum delay cap for retry sleeps in milliseconds (default: 5000) */
  maxDelayMs?: number;
  /** Symmetric jitter ratio in [0, 1], where 0.5 means ±50% (default: 0) */
  jitterRatio?: number;
}

export type HealthCheckProbeMode = "auth" | "status-server";

export interface RadiusConfig extends RadiusProtocolOptions {
  /** Primary RADIUS host */
  host: string;
  /** Ordered list of failover hosts (includes primary if desired) */
  hosts?: string[];
  /** Health check interval in milliseconds (default: 1800000 = 30m) */
  healthCheckIntervalMs?: number;
  /** Health check timeout in milliseconds (default: 5000) */
  healthCheckTimeoutMs?: number;
  /** Probe strategy for host health checks (default: "auth") */
  healthCheckProbeMode?: HealthCheckProbeMode;
  /** User for health check probe (Required) */
  healthCheckUser: string;
  /** Password for health check probe (Required) */
  healthCheckPassword: string;
  /** Retry behavior for authenticate() transport-level failures */
  retry?: RadiusRetryOptions;
}
