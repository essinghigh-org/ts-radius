export interface Logger {
  debug(message: string, ...args: any[]): void;
  info(message: string, ...args: any[]): void;
  warn(message: string, ...args: any[]): void;
  error(message: string, ...args: any[]): void;
}

export class ConsoleLogger implements Logger {
  debug(message: string, ...args: any[]): void {
    console.debug(`[debug] ${message}`, ...args);
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

export interface RadiusResult {
  ok: boolean;
  class?: string;
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
