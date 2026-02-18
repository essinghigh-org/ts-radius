import { radiusAuthenticate } from "./protocol";
import { type RadiusConfig, type RadiusResult, type Logger, ConsoleLogger } from "./types";

interface HostHealth {
  host: string;
  lastOkAt: number | null;
  lastTriedAt: number | null;
  consecutiveFailures: number;
}

export class RadiusClient {
  private config: RadiusConfig;
  private logger: Logger;
  private hosts: string[] = [];
  private health: Map<string, HostHealth> = new Map();
  private activeHost: string | null = null;
  private inProgress: boolean = false;
  private intervalHandle: ReturnType<typeof setInterval> | null = null;

  constructor(config: RadiusConfig, logger?: Logger) {
    this.config = config;
    if (!this.config.secret) {
      throw new Error('[radius-client] config.secret is required');
    }
    if (!this.config.healthCheckUser || !this.config.healthCheckPassword) {
      throw new Error('[radius-client] health check credentials (healthCheckUser, healthCheckPassword) are required');
    }
    this.logger = logger || new ConsoleLogger();
    this.reloadHostsFromConfig();
    this.selectInitialActive();
    this.scheduleHealthChecks();
  }

  public shutdown() {
    if (this.intervalHandle) {
      clearInterval(this.intervalHandle);
      this.intervalHandle = null;
    }
  }

  public async authenticate(username: string, password: string): Promise<RadiusResult> {
    const host = this.getActiveHost();
    const timeoutMs = this.config.timeoutMs || 5000;
    const port = this.config.port || 1812;

    this.logger.debug('[radius-client] authenticate start', { host, user: username });

    try {
      // Create a config object for the protocol layer
      const protocolOptions = {
        secret: this.config.secret,
        port: port,
        timeoutMs: timeoutMs,
        assignmentAttributeId: this.config.assignmentAttributeId,
        vendorId: this.config.vendorId,
        vendorType: this.config.vendorType,
        valuePattern: this.config.valuePattern
      };

      const result = await radiusAuthenticate(host, username, password, protocolOptions, this.logger);

      if (!result.ok && result.error === 'timeout') {
        this.logger.warn('[radius-client] auth timeout detected', { host });
        // Trigger failover check asynchronously
        this.onAuthTimeout().catch(e => this.logger.warn('[radius-client] onAuthTimeout error', e));
      }

      return result;
    } catch (e) {
      this.logger.error('[radius-client] authenticate exception', { error: e });
      throw e;
    }
  }

  // --- Internal Failover / Health Logic ---

  private reloadHostsFromConfig() {
    const list = this.config.hosts && this.config.hosts.length > 0
      ? this.config.hosts
      : [this.config.host];

    this.hosts = list.filter(Boolean);
    for (const h of this.hosts) {
      if (!this.health.has(h)) {
        this.health.set(h, { host: h, lastOkAt: null, lastTriedAt: null, consecutiveFailures: 0 });
      }
    }
  }

  private selectInitialActive() {
    if (!this.activeHost && this.hosts.length) {
      // Try hosts in priority order until one responds (fast probe sequence)
      this.fastFailoverSequence().catch(e => this.logger.warn('[radius-client] initial sequence error', e));
    }
  }

  public getActiveHost(): string {
    if (this.activeHost) return this.activeHost;
    // Fallback: first host while we have not yet validated any
    return this.hosts[0] || this.config.host;
  }

  private async fastFailoverSequence(): Promise<string | null> {
    if (this.inProgress) return this.activeHost;
    this.inProgress = true;
    try {
      for (const host of this.hosts) {
        const ok = await this.probeHost(host);
        if (ok) {
          this.setActiveHost(host, 'initial');
          return host;
        }
      }
      this.logger.warn('[radius-client] No RADIUS hosts responded during initial probe');
      return null;
    } finally {
      this.inProgress = false;
    }
  }

  private setActiveHost(host: string, reason: string) {
    if (this.activeHost === host) return;
    const prev = this.activeHost;
    this.activeHost = host;
    this.logger.info('[radius-client] active host updated', { host, prev, reason });
  }

  private scheduleHealthChecks() {
    const intervalMs = this.config.healthCheckIntervalMs || 1800000; // 30m default
    if (this.intervalHandle) clearInterval(this.intervalHandle);
    this.intervalHandle = setInterval(() => {
      this.backgroundHealthCycle().catch(e => this.logger.warn('[radius-client] background health cycle error', e));
    }, Math.max(5000, intervalMs));
  }

  private async backgroundHealthCycle() {
    // If we have an active host, probe it; if it's down trigger failover attempts immediately.
    if (this.activeHost) {
      const ok = await this.probeHost(this.activeHost);
      if (!ok) {
        this.logger.warn('[radius-client] active host failed health check, starting failover sequence', { host: this.activeHost });
        await this.failover();
      }
      return;
    }
    // No active host yet: cycle through hosts once
    for (const host of this.hosts) {
      const ok = await this.probeHost(host);
      if (ok) {
        this.setActiveHost(host, 'healthcycle');
        break;
      }
    }
  }

  public async failover(): Promise<string | null> {
    if (this.inProgress) return null;
    this.inProgress = true;
    try {
      // Try next hosts in order starting after current active
      const startIndex = this.activeHost ? this.hosts.indexOf(this.activeHost) + 1 : 0;
      const ordered = [...this.hosts.slice(startIndex), ...this.hosts.slice(0, startIndex)];
      for (const host of ordered) {
        if (host === this.activeHost) continue;
        const ok = await this.probeHost(host);
        if (ok) {
          this.setActiveHost(host, 'failover');
          return host;
        }
      }
      // None responded; clear active host so next cycle re-attempts from first
      this.logger.warn('[radius-client] failover sequence found no responsive hosts');
      this.activeHost = null;
      return null;
    } finally {
      this.inProgress = false;
    }
  }

  private async probeHost(host: string): Promise<boolean> {
    const hcUser = this.config.healthCheckUser!;
    const hcPass = this.config.healthCheckPassword!;
    const timeoutMs = this.config.healthCheckTimeoutMs || 5000;

    const entry = this.health.get(host)!;
    entry.lastTriedAt = Date.now();
    try {
      this.logger.debug('[radius-client] probing host', { host });
      const port = this.config.port || 1812;

      const protocolOptions = {
        secret: this.config.secret,
        port: port,
        timeoutMs: timeoutMs
      };

      const res = await radiusAuthenticate(host, hcUser, hcPass, protocolOptions, this.logger);

      // Any response (accept/reject) counts as alive. Timeout or malformed counts as dead.
      if (res.ok) {
         entry.lastOkAt = Date.now();
         entry.consecutiveFailures = 0;
         this.logger.debug('[radius-client] probe success', { host });
         return true;
      }

      if (res.error === 'timeout' || res.error === 'malformed_response') {
         entry.consecutiveFailures++;
         this.logger.debug('[radius-client] probe failed (timeout/malformed)', { host });
         return false;
      }

      // If we got here, it's a valid RADIUS response (likely Access-Reject), so the server is alive.
      // We do NOT increment consecutiveFailures because the server responded.
      // It failed authentication (expected with dummy creds), but the host is healthy.
      entry.lastOkAt = Date.now();
      entry.consecutiveFailures = 0;
      this.logger.debug('[radius-client] probe negative response (server alive)', { host });
      return true;

    } catch (e) {
      entry.consecutiveFailures++;
      this.logger.debug('[radius-client] probe exception', { host, error: (e as Error).message });
      return false;
    }
  }

  // Called when an authentication attempt times out to opportunistically verify active host
  private async onAuthTimeout() {
    this.logger.warn('[radius-client] auth timeout detected; probing active host');
    if (this.activeHost) {
      const alive = await this.probeHost(this.activeHost);
      if (!alive) await this.failover();
    } else {
      await this.backgroundHealthCycle();
    }
  }
}
