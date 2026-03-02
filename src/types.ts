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

export interface ExtendedAttributeValue {
  format: "extended" | "long-extended";
  extendedType: number;
  data: string;
  flags?: number;
  hasMore?: boolean;
  malformed?: boolean;
  reason?: string;
}

export interface ExtendedRadiusAttribute extends ParsedAttribute {
  id: 241 | 242 | 243 | 244 | 245 | 246;
  value: ExtendedAttributeValue;
}

export interface VendorSpecificAttribute {
  id: 26;
  name: "Vendor-Specific";
  vendorId: number;
  value: unknown; // If parsed, structure; else hex string
  raw: string;
}

export type ParsedRadiusAttribute = ParsedAttribute | ExtendedRadiusAttribute | VendorSpecificAttribute;

export interface RadiusResult {
  ok: boolean;
  class?: string;
  attributes?: ParsedRadiusAttribute[];
  raw?: string;
  error?: string;
}

export interface RadiusAttribute {
  type: number;
  value: string | number | Buffer;
}

export type RadiusDynamicAuthorizationAttribute = RadiusAttribute;

export interface RadiusDynamicAuthorizationRequestBase {
  /** Optional session identification attribute (User-Name / type 1) */
  username?: string;
  /** Optional session identification attribute (Acct-Session-Id / type 44) */
  sessionId?: string;
  /** Additional RADIUS attributes for identification and/or authorization changes */
  attributes?: RadiusDynamicAuthorizationAttribute[];
}

export type RadiusCoaRequest = RadiusDynamicAuthorizationRequestBase;
export type RadiusDisconnectRequest = RadiusDynamicAuthorizationRequestBase;

export interface RadiusDynamicAuthorizationResult {
  ok: boolean;
  acknowledged: boolean;
  attributes?: ParsedRadiusAttribute[];
  raw?: string;
  error?: string;
  errorCause?: number;
}

export type RadiusCoaResult = RadiusDynamicAuthorizationResult;
export type RadiusDisconnectResult = RadiusDynamicAuthorizationResult;

export type ResponseLengthValidationPolicy = "strict" | "allow_trailing_bytes";
export type ResponseMessageAuthenticatorPolicy = "compatibility" | "strict";

export interface RadiusProtocolOptions {
  secret: string;
  port?: number;
  accountingPort?: number;
  dynamicAuthorizationPort?: number;
  timeoutMs?: number;
  assignmentAttributeId?: number;
  vendorId?: number;
  vendorType?: number;
  valuePattern?: string;
  /** Validate response source host/port against request target host/port (default: true). */
  validateResponseSource?: boolean;
  /**
   * How to handle a present response Message-Authenticator (Type 80).
   * - compatibility (default): warn on invalid value and continue.
   * - strict: reject malformed/invalid values.
   */
  responseMessageAuthenticatorPolicy?: ResponseMessageAuthenticatorPolicy;
  /**
   * How response length mismatches are handled.
   * - strict (default): declared packet length must equal UDP datagram length.
   * - allow_trailing_bytes: accept datagrams with extra trailing bytes and parse only declared length.
   */
  responseLengthValidationPolicy?: ResponseLengthValidationPolicy;
}

export type RadiusAccountingStatusType = 'Start' | 'Stop' | 'Interim-Update';

export type RadiusAccountingAttribute = RadiusAttribute;

export interface RadiusAccountingRequestBase {
  username: string;
  sessionId: string;
  sessionTime?: number;
  inputOctets?: number;
  outputOctets?: number;
  inputPackets?: number;
  outputPackets?: number;
  delayTime?: number;
  terminateCause?: number;
  attributes?: RadiusAccountingAttribute[];
}

export interface RadiusAccountingRequest extends RadiusAccountingRequestBase {
  statusType: RadiusAccountingStatusType;
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
  /** User for health check probes (required, including "status-server" mode for auth-fallback compatibility) */
  healthCheckUser: string;
  /** Password for health check probes (required, including "status-server" mode for auth-fallback compatibility) */
  healthCheckPassword: string;
  /** Retry behavior for authenticate() transport-level failures */
  retry?: RadiusRetryOptions;
}
