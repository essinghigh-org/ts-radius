export interface Logger {
  debug(message: string, ...args: any[]): void;
  info(message: string, ...args: any[]): void;
  warn(message: string, ...args: any[]): void;
  error(message: string, ...args: any[]): void;
}

export class ConsoleLogger implements Logger {
  debug(message: string, ...args: any[]): void {
    console.log(`[debug] ${message}`, ...args);
  }
  info(message: string, ...args: any[]): void {
    console.info(`[info] ${message}`, ...args);
  }
  warn(message: string, ...args: any[]): void {
    console.warn(`[warn] ${message}`, ...args);
  }
  error(message: string, ...args: any[]): void {
    console.error(`[error] ${message}`, ...args);
  }
}

export interface ParsedAttribute {
  id: number;
  name: string;
  value: any;
  raw: string; // Hex string of value for reference
}

export interface VendorSpecificAttribute {
  id: 26;
  name: "Vendor-Specific";
  vendorId: number;
  value: any; // If parsed, structure; else hex string
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
