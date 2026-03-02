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

export type ResponseMessageAuthenticatorPolicy = "compatibility" | "strict";

export interface RadiusProtocolOptions {
  secret: string;
  port?: number;
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
}

export interface RadiusConfig extends RadiusProtocolOptions {
  /** Primary RADIUS host */
  host: string;
  /** Ordered list of failover hosts (includes primary if desired) */
  hosts?: string[];
  /** Health check interval in milliseconds (default: 1800000 = 30m) */
  healthCheckIntervalMs?: number;
  /** Health check timeout in milliseconds (default: 5000) */
  healthCheckTimeoutMs?: number;
  /** User for health check probe (Required) */
  healthCheckUser: string;
  /** Password for health check probe (Required) */
  healthCheckPassword: string;
}
