import { randomUUID } from "node:crypto";

import { radiusAccounting, radiusAuthenticate, radiusCoa, radiusDisconnect, radiusStatusServerProbe } from "./protocol";
import {
  type RadiusAccountingRequest,
  type RadiusAccountingRequestBase,
  type RadiusCoaRequest,
  type RadiusCoaResult,
  type RadiusConfig,
  type RadiusDynamicAuthorizationRequestBase,
  type RadiusDynamicAuthorizationResult,
  type RadiusDisconnectRequest,
  type RadiusDisconnectResult,
  type RadiusProtocolOptions,
  type RadiusResult,
  type Logger,
  ConsoleLogger
} from "./types";

interface HostHealth {
  host: string;
  lastOkAt: number | null;
  lastTriedAt: number | null;
  consecutiveFailures: number;
}

interface RetryPolicy {
  maxAttempts: number;
  initialDelayMs: number;
  backoffMultiplier: number;
  maxDelayMs: number;
  jitterRatio: number;
}

type ProbeMode = "auth" | "accounting" | "coa" | "disconnect";

type RadiusProtocolAdapter = {
  radiusAuthenticate: typeof radiusAuthenticate;
  radiusStatusServerProbe: typeof radiusStatusServerProbe;
  radiusAccounting: typeof radiusAccounting;
  radiusCoa: typeof radiusCoa;
  radiusDisconnect: typeof radiusDisconnect;
};

type RadiusClientDependencies = {
  protocol?: RadiusProtocolAdapter;
};

const defaultProtocolAdapter: RadiusProtocolAdapter = {
  radiusAuthenticate,
  radiusStatusServerProbe,
  radiusAccounting,
  radiusCoa,
  radiusDisconnect,
};

export class RadiusClient {
  private config: RadiusConfig;
  private logger: Logger;
  private protocol: RadiusProtocolAdapter;
  private hosts: string[] = [];
  private health: Map<string, HostHealth> = new Map();
  private activeHost: string | null = null;
  private inProgress: boolean = false;
  private inProgressWaiters: Array<() => void> = [];
  private intervalHandle: ReturnType<typeof setInterval> | null = null;

  constructor(config: RadiusConfig, logger?: Logger, dependencies?: RadiusClientDependencies) {
    this.config = config;
    if (!this.isNonEmptyText(this.config.secret)) {
      throw new Error('[radius-client] config.secret is required');
    }
    if (!this.isNonEmptyText(this.config.healthCheckUser) || !this.isNonEmptyText(this.config.healthCheckPassword)) {
      throw new Error('[radius-client] health check credentials (healthCheckUser, healthCheckPassword) are required');
    }
    this.logger = logger || new ConsoleLogger();
    this.protocol = dependencies?.protocol ?? defaultProtocolAdapter;
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
    const timeoutMs = this.config.timeoutMs || 5000;
    const port = this.config.port || 1812;
    const retryPolicy = this.getRetryPolicy();
    const maxAttempts = Number.isFinite(retryPolicy.maxAttempts)
      ? Math.max(1, Math.floor(retryPolicy.maxAttempts))
      : 1;

    // Create a config object for the protocol layer
    const protocolOptions = {
      secret: this.config.secret,
      port: port,
      timeoutMs: timeoutMs,
      assignmentAttributeId: this.config.assignmentAttributeId,
      vendorId: this.config.vendorId,
      vendorType: this.config.vendorType,
      valuePattern: this.config.valuePattern,
      validateResponseSource: this.config.validateResponseSource,
      responseMessageAuthenticatorPolicy: this.config.responseMessageAuthenticatorPolicy,
    };

    let lastResult: RadiusResult = { ok: false, error: 'timeout' };

    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      const host = this.getActiveHost();

      this.logger.debug('[radius-client] authenticate start', {
        host,
        attempt,
        maxAttempts
      });

      try {
        const result = await this.protocol.radiusAuthenticate(host, username, password, protocolOptions, this.logger);
        lastResult = result;

        if (result.ok || !this.isRetryableAuthFailure(result) || attempt >= maxAttempts) {
          if (!result.ok && result.error === 'timeout') {
            this.logger.warn('[radius-client] auth timeout detected', { host, attempt, maxAttempts });
            // Trigger failover check asynchronously to preserve legacy health behavior.
            this.onAuthTimeout().catch((error: unknown) => { this.logger.warn('[radius-client] onAuthTimeout error', error); });
          }

          return result;
        }

        this.logger.warn('[radius-client] auth transport failure; trying in-call failover before retry', {
          host,
          attempt,
          maxAttempts,
          error: result.error
        });
        await this.failover();

        const retryDelayMs = this.getRetryDelayMs(attempt, retryPolicy);
        if (retryDelayMs > 0) {
          this.logger.debug('[radius-client] waiting before retry', {
            delayMs: retryDelayMs,
            nextAttempt: attempt + 1,
            maxAttempts
          });
          await Bun.sleep(retryDelayMs);
        }
      } catch (e) {
        this.logger.error('[radius-client] authenticate exception', { error: e });
        throw e;
      }
    }

    return lastResult;
  }

  private getRetryPolicy(): RetryPolicy {
    const retry = this.config.retry;
    const maxAttempts = Math.floor(this.getFiniteRetryNumber(retry?.maxAttempts, 1));
    const initialDelayMs = this.getFiniteRetryNumber(retry?.initialDelayMs, 100);
    const backoffMultiplier = this.getFiniteRetryNumber(retry?.backoffMultiplier, 2);
    const maxDelayMs = this.getFiniteRetryNumber(retry?.maxDelayMs, 5000);
    const jitterRatio = this.getFiniteRetryNumber(retry?.jitterRatio, 0);

    return {
      maxAttempts: Math.max(1, maxAttempts),
      initialDelayMs: Math.max(0, initialDelayMs),
      backoffMultiplier: Math.max(1, backoffMultiplier),
      maxDelayMs: Math.max(0, maxDelayMs),
      jitterRatio: Math.max(0, Math.min(1, jitterRatio))
    };
  }

  private getFiniteRetryNumber(value: number | undefined, fallback: number): number {
    if (typeof value !== 'number' || !Number.isFinite(value)) {
      return fallback;
    }

    return value;
  }

  private getRetryDelayMs(attempt: number, retryPolicy: RetryPolicy): number {
    const retryIndex = Math.max(0, attempt - 1);
    const baseDelay = Math.min(
      retryPolicy.maxDelayMs,
      retryPolicy.initialDelayMs * (retryPolicy.backoffMultiplier ** retryIndex)
    );
    const jitterMultiplier = retryPolicy.jitterRatio > 0
      ? 1 + ((Math.random() * 2 - 1) * retryPolicy.jitterRatio)
      : 1;

    const jitteredDelay = baseDelay * jitterMultiplier;
    if (!Number.isFinite(jitteredDelay)) {
      return retryPolicy.maxDelayMs;
    }

    return Math.min(retryPolicy.maxDelayMs, Math.max(0, Math.round(jitteredDelay)));
  }

  private isNonEmptyText(value: unknown): value is string {
    return typeof value === 'string' && value.trim().length > 0;
  }

  private normalizeHost(host: unknown): string | null {
    if (!this.isNonEmptyText(host)) {
      return null;
    }

    return host.trim();
  }

  private isRetryableAuthFailure(result: RadiusResult): boolean {
    if (result.ok) return false;

    return result.error === 'timeout'
      || result.error === 'malformed_response'
      || result.error === 'authenticator_mismatch'
      || result.error === 'unknown_code';
  }

  private isRetryableAccountingFailure(result: RadiusResult): boolean {
    if (result.ok) return false;

    return result.error === 'timeout'
      || result.error === 'malformed_response'
      || result.error === 'identifier_mismatch'
      || result.error === 'authenticator_mismatch'
      || result.error === 'unknown_code';
  }

  public async sendAccounting(request: RadiusAccountingRequest): Promise<RadiusResult> {
    const timeoutMs = this.config.timeoutMs || 5000;
    const accountingPort = this.config.accountingPort || this.config.port || 1813;
    const retryPolicy = this.getRetryPolicy();
    const maxAttempts = Number.isFinite(retryPolicy.maxAttempts)
      ? Math.max(1, Math.floor(retryPolicy.maxAttempts))
      : 1;

    let lastResult: RadiusResult = { ok: false, error: 'timeout' };

    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      const host = this.getActiveHost();

      this.logger.debug("[radius-client] accounting start", {
        host,
        statusType: request.statusType,
        sessionId: request.sessionId,
        attempt,
        maxAttempts
      });

      try {
        const protocolOptions = {
          secret: this.config.secret,
          port: accountingPort,
          accountingPort,
          timeoutMs: timeoutMs
        };

        const result = await this.protocol.radiusAccounting(host, request, protocolOptions, this.logger);
        lastResult = result;

        if (result.ok || !this.isRetryableAccountingFailure(result) || attempt >= maxAttempts) {
          if (!result.ok && result.error === "timeout") {
            this.logger.warn("[radius-client] accounting timeout detected", {
              host,
              statusType: request.statusType,
              sessionId: request.sessionId,
              attempt,
              maxAttempts
            });
            this.onAccountingTimeout(request).catch((error: unknown) => {
              this.logger.warn("[radius-client] onAccountingTimeout error", error);
            });
          }

          return result;
        }

        this.logger.warn('[radius-client] accounting transport failure; trying in-call failover before retry', {
          host,
          statusType: request.statusType,
          sessionId: request.sessionId,
          attempt,
          maxAttempts,
          error: result.error
        });

        await this.failover('accounting');

        const retryDelayMs = this.getRetryDelayMs(attempt, retryPolicy);
        if (retryDelayMs > 0) {
          this.logger.debug('[radius-client] accounting waiting before retry', {
            delayMs: retryDelayMs,
            nextAttempt: attempt + 1,
            maxAttempts
          });
          await Bun.sleep(retryDelayMs);
        }
      } catch (e) {
        this.logger.error("[radius-client] accounting exception", { error: e });
        throw e;
      }
    }

    return lastResult;
  }

  public accountingStart(request: RadiusAccountingRequestBase): Promise<RadiusResult> {
    return this.sendAccounting({ ...request, statusType: "Start" });
  }

  public accountingInterim(request: RadiusAccountingRequestBase): Promise<RadiusResult> {
    return this.sendAccounting({ ...request, statusType: "Interim-Update" });
  }

  public accountingStop(request: RadiusAccountingRequestBase): Promise<RadiusResult> {
    return this.sendAccounting({ ...request, statusType: "Stop" });
  }

  private async sendDynamicAuthorizationRequest(
    mode: "coa" | "disconnect",
    request: RadiusDynamicAuthorizationRequestBase,
    protocolCall: (
      host: string,
      requestPayload: RadiusDynamicAuthorizationRequestBase,
      protocolOptions: RadiusProtocolOptions,
      logger: Logger
    ) => Promise<RadiusDynamicAuthorizationResult>
  ): Promise<RadiusDynamicAuthorizationResult> {
    const host = this.getActiveHost();
    const timeoutMs = this.config.timeoutMs || 5000;
    const dynamicAuthorizationPort = this.config.dynamicAuthorizationPort ?? 3799;

    this.logger.debug(`[radius-client] ${mode} start`, {
      host,
      username: request.username,
      sessionId: request.sessionId
    });

    try {
      const protocolOptions: RadiusProtocolOptions = {
        secret: this.config.secret,
        port: dynamicAuthorizationPort,
        dynamicAuthorizationPort,
        timeoutMs
      };

      const result = await protocolCall(host, request, protocolOptions, this.logger);

      if (!result.ok && result.error === "timeout") {
        this.logger.warn(`[radius-client] ${mode} timeout detected`, {
          host,
          username: request.username,
          sessionId: request.sessionId
        });
        this.onDynamicAuthorizationTimeout(mode).catch((error: unknown) => {
          this.logger.warn("[radius-client] onDynamicAuthorizationTimeout error", error);
        });
      }

      return result;
    } catch (e) {
      this.logger.error(`[radius-client] ${mode} exception`, { error: e });
      throw e;
    }
  }

  public async sendCoa(request: RadiusCoaRequest): Promise<RadiusCoaResult> {
    return this.sendDynamicAuthorizationRequest("coa", request, (host, requestPayload, protocolOptions, logger) =>
      this.protocol.radiusCoa(host, requestPayload, protocolOptions, logger)
    );
  }

  public async sendDisconnect(request: RadiusDisconnectRequest): Promise<RadiusDisconnectResult> {
    return this.sendDynamicAuthorizationRequest("disconnect", request, (host, requestPayload, protocolOptions, logger) =>
      this.protocol.radiusDisconnect(host, requestPayload, protocolOptions, logger)
    );
  }

  // --- Internal Failover / Health Logic ---

  private reloadHostsFromConfig() {
    const list = this.config.hosts && this.config.hosts.length > 0
      ? this.config.hosts
      : [this.config.host];

    this.hosts = list
      .map((host) => this.normalizeHost(host))
      .filter((host): host is string => host !== null);

    if (this.hosts.length === 0) {
      throw new Error('[radius-client] at least one non-empty host is required');
    }

    const newHosts = new Set(this.hosts);

    // Add new hosts
    for (const h of this.hosts) {
      if (!this.health.has(h)) {
        this.health.set(h, { host: h, lastOkAt: null, lastTriedAt: null, consecutiveFailures: 0 });
      }
    }

    // Clean up removed hosts
    for (const h of this.health.keys()) {
      if (!newHosts.has(h)) {
        this.health.delete(h);
      }
    }
  }

  private selectInitialActive() {
    if (!this.activeHost && this.hosts.length) {
      // Try hosts in priority order until one responds (fast probe sequence)
      this.fastFailoverSequence().catch((error: unknown) => { this.logger.warn('[radius-client] initial sequence error', error); });
    }
  }

  public getActiveHost(): string {
    if (this.activeHost) return this.activeHost;
    // Fallback: first host while we have not yet validated any
    const fallback = this.hosts[0] || this.normalizeHost(this.config.host);
    if (!fallback) {
      throw new Error('[radius-client] No active or fallback host available');
    }
    return fallback;
  }

  private async fastFailoverSequence(): Promise<string | null> {
    if (!this.acquireHealthOperationLock()) return this.activeHost;
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
      this.releaseHealthOperationLock();
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
      this.backgroundHealthCycle().catch((error: unknown) => { this.logger.warn('[radius-client] background health cycle error', error); });
    }, intervalMs);
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

  public async failover(probeType: ProbeMode = "auth"): Promise<string | null> {
    if (this.inProgress) {
      const releasedBeforeTimeout = await this.waitForHealthOperationRelease(100);
      if (!releasedBeforeTimeout) {
        this.logger.debug('[radius-client] failover skipped while another health operation is still in progress');
        return null;
      }
    }

    if (!this.acquireHealthOperationLock()) {
      this.logger.debug('[radius-client] failover skipped while another health operation is still in progress');
      return null;
    }

    try {
      // Try next hosts in order starting after current active
      const startIndex = this.activeHost ? this.hosts.indexOf(this.activeHost) + 1 : 0;
      const ordered = [...this.hosts.slice(startIndex), ...this.hosts.slice(0, startIndex)];
      for (const host of ordered) {
        if (host === this.activeHost) continue;
        const ok = await this.probeHost(host, probeType);
        if (ok) {
          const reason = probeType === "auth"
            ? "failover"
            : `failover-${probeType}`;
          this.setActiveHost(host, reason);
          return host;
        }
      }
      // None responded; clear active host so next cycle re-attempts from first
      this.logger.warn('[radius-client] failover sequence found no responsive hosts');
      this.activeHost = null;
      return null;
    } finally {
      this.releaseHealthOperationLock();
    }
  }

  private async probeHost(host: string, probeType: ProbeMode = "auth"): Promise<boolean> {
    const hcUser = this.config.healthCheckUser;
    const hcPass = this.config.healthCheckPassword;
    const timeoutMs = this.config.healthCheckTimeoutMs || 5000;
    const probeMode = this.config.healthCheckProbeMode || 'auth';

    const existingEntry = this.health.get(host);
    const entry = existingEntry ?? {
      host,
      lastOkAt: null,
      lastTriedAt: null,
      consecutiveFailures: 0,
    };

    if (!existingEntry) {
      this.health.set(host, entry);
    }

    entry.lastTriedAt = Date.now();

    const markHealthy = (reason: string): boolean => {
      entry.lastOkAt = Date.now();
      entry.consecutiveFailures = 0;
      this.logger.debug('[radius-client] probe success', { host, reason });
      return true;
    };

    const markUnhealthy = (reason: string): boolean => {
      entry.consecutiveFailures++;
      this.logger.debug('[radius-client] probe failure', { host, reason });
      return false;
    };

    const evaluateAuthProbeResponse = (res: RadiusResult): boolean => {
      if (res.ok) {
        return markHealthy('auth-access-accept');
      }

      if (res.error === 'timeout' || res.error === 'malformed_response' || res.error === 'authenticator_mismatch') {
        return markUnhealthy(`auth-${res.error}`);
      }

      // Any valid auth response (e.g. Access-Reject) still proves liveness.
      return markHealthy(`auth-${res.error || 'negative-response'}`);
    };

    try {
      this.logger.debug('[radius-client] probing host', { host, probeType, mode: probeMode });

      if (probeType === "accounting") {
        const accountingPort = this.config.accountingPort || this.config.port || 1813;
        const accountingProbeRequest: RadiusAccountingRequest = {
          username: hcUser,
          sessionId: this.createHealthProbeSessionId(),
          statusType: "Interim-Update"
        };
        const accountingOptions = {
          secret: this.config.secret,
          port: accountingPort,
          accountingPort,
          timeoutMs
        };

        const accountingRes = await this.protocol.radiusAccounting(
          host,
          accountingProbeRequest,
          accountingOptions,
          this.logger
        );

        if (accountingRes.ok) {
          return markHealthy('accounting');
        }

        return markUnhealthy(`accounting-${accountingRes.error || 'negative-response'}`);
      }

      if (probeType === "coa" || probeType === "disconnect") {
        const dynamicAuthorizationPort = this.config.dynamicAuthorizationPort ?? 3799;
        const protocolOptions = {
          secret: this.config.secret,
          port: dynamicAuthorizationPort,
          dynamicAuthorizationPort,
          timeoutMs,
        };
        const request = {
          username: hcUser,
        };

        const dynamicResult = probeType === "coa"
          ? await this.protocol.radiusCoa(host, request, protocolOptions, this.logger)
          : await this.protocol.radiusDisconnect(host, request, protocolOptions, this.logger);

        if (dynamicResult.ok) {
          return markHealthy(probeType);
        }

        if (
          dynamicResult.error === 'timeout'
          || dynamicResult.error === 'malformed_response'
          || dynamicResult.error === 'identifier_mismatch'
          || dynamicResult.error === 'authenticator_mismatch'
        ) {
          return markUnhealthy(`${probeType}-${dynamicResult.error}`);
        }

        // NAK/unknown still indicates dynamic-authorization reachability.
        return markHealthy(`${probeType}-${dynamicResult.error || 'negative-response'}`);
      }

      const port = this.config.port || 1812;

      const protocolOptions = {
        secret: this.config.secret,
        port: port,
        timeoutMs: timeoutMs,
        validateResponseSource: this.config.validateResponseSource,
        responseMessageAuthenticatorPolicy: this.config.responseMessageAuthenticatorPolicy,
      };

      if (probeMode === 'status-server') {
        try {
          const statusResult = await this.protocol.radiusStatusServerProbe(host, protocolOptions, this.logger);
          if (statusResult.ok) {
            return markHealthy('status-server');
          }

          this.logger.debug('[radius-client] status-server probe non-healthy result; falling back to auth probe', {
            host,
            error: statusResult.error
          });
        } catch (e) {
          this.logger.debug('[radius-client] status-server probe exception; falling back to auth probe', {
            host,
            error: (e as Error).message
          });
        }
      }

      const authProbe = await this.protocol.radiusAuthenticate(host, hcUser, hcPass, protocolOptions, this.logger);
      return evaluateAuthProbeResponse(authProbe);

    } catch (e) {
      return markUnhealthy(`exception:${(e as Error).message}`);
    }
  }

  private acquireHealthOperationLock(): boolean {
    if (this.inProgress) {
      return false;
    }

    this.inProgress = true;
    return true;
  }

  private releaseHealthOperationLock(): void {
    this.inProgress = false;
    const waiters = this.inProgressWaiters.splice(0);
    for (const waiter of waiters) {
      waiter();
    }
  }

  private async waitForHealthOperationRelease(timeoutMs: number): Promise<boolean> {
    if (!this.inProgress) {
      return true;
    }

    return await new Promise<boolean>((resolve) => {
      let settled = false;
      let timer: ReturnType<typeof setTimeout> | null = null;

      const settle = (released: boolean): void => {
        if (settled) {
          return;
        }

        settled = true;
        if (timer) {
          clearTimeout(timer);
        }

        const waiterIndex = this.inProgressWaiters.indexOf(onRelease);
        if (waiterIndex >= 0) {
          this.inProgressWaiters.splice(waiterIndex, 1);
        }

        resolve(released);
      };

      const onRelease = (): void => {
        settle(true);
      };

      this.inProgressWaiters.push(onRelease);

      if (!this.inProgress) {
        settle(true);
        return;
      }

      timer = setTimeout(() => {
        settle(false);
      }, timeoutMs);
    });
  }

  private createHealthProbeSessionId(): string {
    const timestamp = String(Date.now());
    return `health-${timestamp}-${randomUUID()}`;
  }

  // Called when an authentication attempt times out to opportunistically verify active host
  private async onAuthTimeout() {
    this.logger.warn('[radius-client] auth timeout detected; probing active host');
    if (this.activeHost) {
      const alive = await this.probeHost(this.activeHost, "auth");
      if (!alive) await this.failover("auth");
    } else {
      await this.backgroundHealthCycle();
    }
  }

  // Called when an accounting attempt times out to verify accounting path health before failover.
  private async onAccountingTimeout(request: RadiusAccountingRequest) {
    this.logger.warn('[radius-client] accounting timeout detected; probing active host on accounting path', {
      statusType: request.statusType,
      sessionId: request.sessionId
    });
    if (this.activeHost) {
      const alive = await this.probeHost(this.activeHost, "accounting");
      if (!alive) await this.failover("accounting");
    } else {
      await this.failover("accounting");
    }
  }

  private async onDynamicAuthorizationTimeout(mode: "coa" | "disconnect") {
    this.logger.warn('[radius-client] dynamic authorization timeout detected; probing active host', { mode });
    if (this.activeHost) {
      const alive = await this.probeHost(this.activeHost, mode);
      if (!alive) await this.failover(mode);
    } else {
      await this.failover(mode);
    }
  }
}
