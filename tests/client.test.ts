import { describe, test, expect, beforeEach, afterEach, mock } from 'bun:test';
import { RadiusClient } from '../src/client';
import type {
  RadiusAccountingRequest,
  RadiusCoaRequest,
  RadiusCoaResult,
  RadiusConfig,
  RadiusDisconnectRequest,
  RadiusDisconnectResult,
  RadiusResult,
  RadiusProtocolOptions
} from '../src/types';

interface RadiusStatusProbeResult {
  ok: boolean;
  error?: string;
}

// State for mock
let responsiveHosts: Set<string> = new Set();
// Hosts that return Access-Reject (still alive)
let rejectingHosts: Set<string> = new Set();
let statusResponsiveHosts: Set<string> = new Set();
let statusUnsupportedHosts: Set<string> = new Set();
let responsiveAccountingHosts: Set<string> = new Set();
let responsiveCoaHosts: Set<string> = new Set();
let responsiveDisconnectHosts: Set<string> = new Set();
let authCalls: {
  host: string;
  username: string;
  password: string;
  options: RadiusProtocolOptions;
  logger: unknown;
}[] = [];
let statusCalls: {
  host: string;
  options: RadiusProtocolOptions;
  logger: unknown;
}[] = [];
let accountingCalls: {
  host: string;
  request: RadiusAccountingRequest;
  options: RadiusProtocolOptions;
  logger: unknown;
}[] = [];
let coaCalls: {
  host: string;
  request: RadiusCoaRequest;
  options: RadiusProtocolOptions;
  logger: unknown;
}[] = [];
let disconnectCalls: {
  host: string;
  request: RadiusDisconnectRequest;
  options: RadiusProtocolOptions;
  logger: unknown;
}[] = [];

// Mock the protocol layer
void mock.module('../src/protocol', () => ({
  radiusAuthenticate: async (
    host: string,
    username: string,
    password: string,
    options: RadiusProtocolOptions,
    logger?: unknown
  ): Promise<RadiusResult> => {
    authCalls.push({ host, username, password, options, logger });

    if (rejectingHosts.has(host)) {
      // Simulate Access-Reject (server alive but auth failed)
      return { ok: false, error: 'access_reject' };
    }
    if (!responsiveHosts.has(host)) {
      // Simulate timeout
      return { ok: false, error: 'timeout' };
    }
    return { ok: true };
  },
  radiusStatusServerProbe: async (
    host: string,
    options: RadiusProtocolOptions,
    logger?: unknown
  ): Promise<RadiusStatusProbeResult> => {
    statusCalls.push({ host, options, logger });

    if (statusUnsupportedHosts.has(host)) {
      return { ok: false, error: 'unknown_code' };
    }

    if (!statusResponsiveHosts.has(host)) {
      return { ok: false, error: 'timeout' };
    }

    return { ok: true };
  },
  radiusAccounting: async (
    host: string,
    request: RadiusAccountingRequest,
    options: RadiusProtocolOptions,
    logger?: unknown
  ): Promise<RadiusResult> => {
    accountingCalls.push({ host, request, options, logger });

    if (!responsiveAccountingHosts.has(host)) {
      return { ok: false, error: 'timeout' };
    }

    return { ok: true };
  },
  radiusCoa: async (
    host: string,
    request: RadiusCoaRequest,
    options: RadiusProtocolOptions,
    logger?: unknown
  ): Promise<RadiusCoaResult> => {
    coaCalls.push({ host, request, options, logger });

    if (!responsiveCoaHosts.has(host)) {
      return { ok: false, acknowledged: false, error: 'timeout' };
    }

    return { ok: true, acknowledged: true };
  },
  radiusDisconnect: async (
    host: string,
    request: RadiusDisconnectRequest,
    options: RadiusProtocolOptions,
    logger?: unknown
  ): Promise<RadiusDisconnectResult> => {
    disconnectCalls.push({ host, request, options, logger });

    if (!responsiveDisconnectHosts.has(host)) {
      return { ok: false, acknowledged: false, error: 'timeout' };
    }

    return { ok: true, acknowledged: true };
  }
}));

describe('RadiusClient Failover', () => {
  let client: RadiusClient;
  const config: RadiusConfig = {
    host: '10.0.0.1',
    hosts: ['10.0.0.1', '10.0.0.2', '10.0.0.3'],
    secret: 'secret',
    timeoutMs: 100,
    accountingPort: 1813,
    healthCheckIntervalMs: 1000,
    healthCheckTimeoutMs: 100,
    healthCheckUser: 'test_health_user',
    healthCheckPassword: 'test_health_password'
  };
  const healthTimeoutMs = config.healthCheckTimeoutMs ?? 100;

  const waitForCondition = async (
    condition: () => boolean,
    timeoutMs: number,
    errorMessage: string,
    pollIntervalMs = 5
  ): Promise<void> => {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() <= deadline) {
      if (condition()) return;
      await Bun.sleep(pollIntervalMs);
    }
    throw new Error(errorMessage);
  };

  const expectConditionToHold = async (
    condition: () => boolean,
    durationMs: number,
    errorMessage: string,
    pollIntervalMs = 5
  ): Promise<void> => {
    const deadline = Date.now() + durationMs;
    while (Date.now() <= deadline) {
      if (!condition()) {
        throw new Error(errorMessage);
      }
      await Bun.sleep(pollIntervalMs);
    }
  };

  beforeEach(() => {
    responsiveHosts = new Set(['10.0.0.1']);
    rejectingHosts = new Set();
    statusResponsiveHosts = new Set(['10.0.0.1']);
    statusUnsupportedHosts = new Set();
    responsiveAccountingHosts = new Set(['10.0.0.1']);
    responsiveCoaHosts = new Set(['10.0.0.1']);
    responsiveDisconnectHosts = new Set(['10.0.0.1']);
    authCalls = [];
    statusCalls = [];
    accountingCalls = [];
    coaCalls = [];
    disconnectCalls = [];
    client = new RadiusClient(config);
  });

  afterEach(() => {
    client.shutdown();
  });

  test('initial active host selection chooses first responsive host', async () => {
    // Force a re-selection logic if needed, but constructor already did it.
    // However, fastFailoverSequence is async and might not have finished.
    // We can manually trigger it or wait.
    // But getActiveHost returns default immediately.

    // Wait for async initialization?
    // The constructor calls fastFailoverSequence() without await.
    // So getActiveHost() might return '10.0.0.1' (default) immediately.

    // To test failover logic properly, we should call failover() explicitly or mock the state.

    // Let's verify default state first.
    expect(client.getActiveHost()).toBe('10.0.0.1');
  });

  test('authenticate forwards username/password and expected protocol options', async () => {
    const result = await client.authenticate('alice', 'hunter2');
    expect(result.ok).toBe(true);

    const userCall = authCalls.find(
      (call) => call.username === 'alice' && call.password === 'hunter2'
    );

    expect(userCall).toBeDefined();

    if (!userCall) {
      throw new Error('Expected a protocol call with supplied username/password');
    }

    expect(userCall.host).toBe('10.0.0.1');
    expect(userCall.options).toMatchObject({
      secret: 'secret',
      port: 1812,
      timeoutMs: 100
    });

    expect(userCall.logger).toBeDefined();
  });

  test('failover activates next responsive host when current fails', async () => {
    // Setup: 10.0.0.1 is responsive initially.
    expect(client.getActiveHost()).toBe('10.0.0.1');

    // Now make 10.0.0.1 unresponsive, and 10.0.0.2 responsive.
    responsiveHosts = new Set(['10.0.0.2']);

    // Trigger failover manually
    const newHost = await client.failover();

    expect(newHost).toBe('10.0.0.2');
    expect(client.getActiveHost()).toBe('10.0.0.2');
  });

  test('clears active host if none responsive', async () => {
    responsiveHosts = new Set();
    const newHost = await client.failover();

    expect(newHost).toBeNull();
    // When no active host, getActiveHost returns fallback (primary)
    expect(client.getActiveHost()).toBe('10.0.0.1');
  });

  test('authenticate triggers failover on timeout', async () => {
    // 10.0.0.1 is responsive
    responsiveHosts = new Set(['10.0.0.1']);

    // Auth should succeed
    let res = await client.authenticate('user', 'pass');
    expect(res.ok).toBe(true);

    // Make 10.0.0.1 unresponsive, 10.0.0.2 responsive
    responsiveHosts = new Set(['10.0.0.2']);
    authCalls = [];

    // Auth should fail with timeout on 10.0.0.1
    // And internally trigger failover
    res = await client.authenticate('user', 'pass');
    expect(res.ok).toBe(false);
    expect(res.error).toBe('timeout');

    await waitForCondition(
      () => client.getActiveHost() === '10.0.0.2',
      Math.max(healthTimeoutMs * 3, 250),
      'Expected active host to fail over to 10.0.0.2 after timeout'
    );

    // Should have switched to 10.0.0.2
    expect(client.getActiveHost()).toBe('10.0.0.2');

    // Next auth should succeed on 10.0.0.2
    res = await client.authenticate('user', 'pass');
    expect(res.ok).toBe(true);
  });

  test('host returning Access-Reject is considered healthy and does not trigger failover', async () => {
    // 10.0.0.1 responds with Access-Reject (e.g. invalid creds)
    responsiveHosts = new Set(['10.0.0.1']);
    rejectingHosts = new Set(['10.0.0.1']);

    // Auth should fail
    const res = await client.authenticate('user', 'pass');
    expect(res.ok).toBe(false);
    expect(res.error).toBe('access_reject');

    // Should NOT trigger failover
    await expectConditionToHold(
      () => client.getActiveHost() === '10.0.0.1',
      healthTimeoutMs + 50,
      'Active host changed unexpectedly after Access-Reject'
    );

    expect(client.getActiveHost()).toBe('10.0.0.1');
  });

  test('authenticate retries timeout results with exponential backoff', async () => {
    const retryClient = new RadiusClient({
      ...config,
      hosts: ['10.0.0.1'],
      healthCheckIntervalMs: 60000,
      retry: {
        maxAttempts: 3,
        initialDelayMs: 25,
        backoffMultiplier: 2,
        maxDelayMs: 1000,
        jitterRatio: 0
      }
    });

    responsiveHosts = new Set();
    authCalls = [];

    const startedAt = Date.now();
    const result = await retryClient.authenticate('retry-user', 'retry-pass');
    const elapsedMs = Date.now() - startedAt;

    const retryUserCalls = authCalls.filter((call) => call.username === 'retry-user');

    expect(retryUserCalls).toHaveLength(3);
    expect(result.ok).toBe(false);
    expect(result.error).toBe('timeout');
    expect(elapsedMs).toBeGreaterThanOrEqual(75);

    retryClient.shutdown();
  });

  test('authenticate treats NaN maxAttempts as one bounded attempt', async () => {
    const retryClient = new RadiusClient({
      ...config,
      hosts: ['10.0.0.1'],
      healthCheckIntervalMs: 60000,
      retry: {
        maxAttempts: Number.NaN,
        initialDelayMs: 1,
        backoffMultiplier: 1,
        maxDelayMs: 1,
        jitterRatio: 0
      }
    });

    responsiveHosts = new Set();
    authCalls = [];

    const result = await retryClient.authenticate('nan-max-attempts-user', 'retry-pass');
    const retryUserCalls = authCalls.filter((call) => call.username === 'nan-max-attempts-user');

    expect(retryUserCalls).toHaveLength(1);
    expect(result.ok).toBe(false);
    expect(result.error).toBe('timeout');

    retryClient.shutdown();
  });

  test('authenticate treats Infinity maxAttempts as one bounded attempt', async () => {
    const retryClient = new RadiusClient({
      ...config,
      hosts: ['10.0.0.1'],
      healthCheckIntervalMs: 60000,
      retry: {
        maxAttempts: Number.POSITIVE_INFINITY,
        initialDelayMs: 1,
        backoffMultiplier: 1,
        maxDelayMs: 1,
        jitterRatio: 0
      }
    });

    responsiveHosts = new Set();
    authCalls = [];

    const makeHostResponsiveTimer = setTimeout(() => {
      responsiveHosts = new Set(['10.0.0.1']);
    }, 5);

    try {
      const result = await retryClient.authenticate('infinity-max-attempts-user', 'retry-pass');
      const retryUserCalls = authCalls.filter((call) => call.username === 'infinity-max-attempts-user');

      expect(retryUserCalls).toHaveLength(1);
      expect(result.ok).toBe(false);
      expect(result.error).toBe('timeout');
    } finally {
      clearTimeout(makeHostResponsiveTimer);
      retryClient.shutdown();
    }
  });

  test('authenticate sanitizes non-finite retry delay values', async () => {
    const retryClient = new RadiusClient({
      ...config,
      hosts: ['10.0.0.1'],
      healthCheckIntervalMs: 60000,
      retry: {
        maxAttempts: 2,
        initialDelayMs: Number.NaN,
        backoffMultiplier: Number.NaN,
        maxDelayMs: Number.NaN,
        jitterRatio: Number.NaN
      }
    });

    responsiveHosts = new Set();
    authCalls = [];

    const startedAt = Date.now();
    const result = await retryClient.authenticate('non-finite-delay-user', 'retry-pass');
    const elapsedMs = Date.now() - startedAt;

    const retryUserCalls = authCalls.filter((call) => call.username === 'non-finite-delay-user');

    expect(retryUserCalls).toHaveLength(2);
    expect(result.ok).toBe(false);
    expect(result.error).toBe('timeout');
    expect(elapsedMs).toBeGreaterThanOrEqual(60);

    retryClient.shutdown();
  });

  test('authenticate applies jitter to retry backoff delay', async () => {
    const originalRandom = Math.random;
    Math.random = () => 1;

    try {
      const retryClient = new RadiusClient({
        ...config,
        hosts: ['10.0.0.1'],
        healthCheckIntervalMs: 60000,
        retry: {
          maxAttempts: 2,
          initialDelayMs: 40,
          backoffMultiplier: 2,
          maxDelayMs: 1000,
          jitterRatio: 0.5
        }
      });

      responsiveHosts = new Set();
      authCalls = [];

      const startedAt = Date.now();
      const result = await retryClient.authenticate('jitter-user', 'retry-pass');
      const elapsedMs = Date.now() - startedAt;

      const jitterUserCalls = authCalls.filter((call) => call.username === 'jitter-user');

      expect(jitterUserCalls).toHaveLength(2);
      expect(result.ok).toBe(false);
      expect(result.error).toBe('timeout');
      // Base delay (40ms) + max positive jitter (20ms)
      expect(elapsedMs).toBeGreaterThanOrEqual(60);

      retryClient.shutdown();
    } finally {
      Math.random = originalRandom;
    }
  });

  test('authenticate can fail over and succeed within the same call when retries are enabled', async () => {
    responsiveHosts = new Set(['10.0.0.1', '10.0.0.2']);

    const retryClient = new RadiusClient({
      ...config,
      hosts: ['10.0.0.1', '10.0.0.2'],
      healthCheckIntervalMs: 60000,
      retry: {
        maxAttempts: 2,
        initialDelayMs: 1,
        backoffMultiplier: 1,
        maxDelayMs: 1,
        jitterRatio: 0
      }
    });

    // First host times out, second host responds.
    responsiveHosts = new Set(['10.0.0.2']);
    authCalls = [];

    const result = await retryClient.authenticate('inline-failover-user', 'pass');

    const userCalls = authCalls
      .filter((call) => call.username === 'inline-failover-user')
      .map((call) => call.host);

    expect(result.ok).toBe(true);
    expect(userCalls).toEqual(['10.0.0.1', '10.0.0.2']);
    expect(retryClient.getActiveHost()).toBe('10.0.0.2');

    retryClient.shutdown();
  });

  test('failover uses Status-Server probing when configured', async () => {
    const statusClient = new RadiusClient({
      ...config,
      healthCheckIntervalMs: 60000,
      healthCheckProbeMode: 'status-server'
    });

    statusResponsiveHosts = new Set(['10.0.0.2']);
    responsiveHosts = new Set();
    authCalls = [];
    statusCalls = [];

    const newHost = await statusClient.failover();

    expect(newHost).toBe('10.0.0.2');
    expect(statusCalls.some((call) => call.host === '10.0.0.2')).toBe(true);

    const authProbeCalls = authCalls.filter(
      (call) => call.host === '10.0.0.2' && call.username === config.healthCheckUser
    );
    expect(authProbeCalls).toHaveLength(0);

    statusClient.shutdown();
  });

  test('status-server probing falls back to auth probe for compatibility when unsupported', async () => {
    const statusClient = new RadiusClient({
      ...config,
      healthCheckIntervalMs: 60000,
      healthCheckProbeMode: 'status-server'
    });

    statusResponsiveHosts = new Set();
    statusUnsupportedHosts = new Set(['10.0.0.2']);
    responsiveHosts = new Set(['10.0.0.2']);
    rejectingHosts = new Set(['10.0.0.2']);
    authCalls = [];
    statusCalls = [];

    const newHost = await statusClient.failover();

    expect(newHost).toBe('10.0.0.2');
    expect(statusCalls.some((call) => call.host === '10.0.0.2')).toBe(true);

    const fallbackAuthProbe = authCalls.find(
      (call) => call.host === '10.0.0.2' && call.username === config.healthCheckUser
    );
    expect(fallbackAuthProbe).toBeDefined();

    statusClient.shutdown();
  });

  test('sendCoa forwards request and expected protocol options', async () => {
    const result = await client.sendCoa({
      username: 'alice',
      sessionId: 'session-77',
      attributes: [{ type: 11, value: 'filter-prod' }]
    });

    expect(result.ok).toBe(true);

    const call = coaCalls[0];
    if (!call) {
      throw new Error('Expected a CoA protocol call');
    }

    expect(call.host).toBe('10.0.0.1');
    expect(call.request).toEqual({
      username: 'alice',
      sessionId: 'session-77',
      attributes: [{ type: 11, value: 'filter-prod' }]
    });
    expect(call.options).toMatchObject({
      secret: 'secret',
      port: 3799,
      dynamicAuthorizationPort: 3799,
      timeoutMs: 100
    });
    expect(call.logger).toBeDefined();
  });

  test('sendDisconnect forwards request and expected protocol options', async () => {
    const result = await client.sendDisconnect({
      username: 'alice',
      sessionId: 'session-88'
    });

    expect(result.ok).toBe(true);

    const call = disconnectCalls[0];
    if (!call) {
      throw new Error('Expected a Disconnect protocol call');
    }

    expect(call.host).toBe('10.0.0.1');
    expect(call.request).toEqual({
      username: 'alice',
      sessionId: 'session-88'
    });
    expect(call.options).toMatchObject({
      secret: 'secret',
      port: 3799,
      dynamicAuthorizationPort: 3799,
      timeoutMs: 100
    });
    expect(call.logger).toBeDefined();
  });

  test('sendCoa timeout triggers failover using dynamic-authorization reachability', async () => {
    responsiveCoaHosts = new Set(['10.0.0.2']);
    // Keep auth healthy on the current host to verify we are not using auth probing.
    responsiveHosts = new Set(['10.0.0.1']);

    const result = await client.sendCoa({
      username: 'alice',
      sessionId: 'session-timeout'
    });

    expect(result.ok).toBe(false);
    expect(result.error).toBe('timeout');

    await waitForCondition(
      () => client.getActiveHost() === '10.0.0.2',
      Math.max(healthTimeoutMs * 3, 250),
      'Expected active host to fail over to 10.0.0.2 after CoA timeout'
    );
  });

  test('sendDisconnect timeout triggers failover using dynamic-authorization reachability', async () => {
    responsiveDisconnectHosts = new Set(['10.0.0.2']);
    // Keep auth healthy on the current host to verify we are not using auth probing.
    responsiveHosts = new Set(['10.0.0.1']);

    const result = await client.sendDisconnect({
      username: 'alice',
      sessionId: 'session-disconnect-timeout'
    });

    expect(result.ok).toBe(false);
    expect(result.error).toBe('timeout');

    await waitForCondition(
      () => client.getActiveHost() === '10.0.0.2',
      Math.max(healthTimeoutMs * 3, 250),
      'Expected active host to fail over to 10.0.0.2 after Disconnect timeout'
    );
  });

  test('accountingStart/accountingInterim/accountingStop send typed status values', async () => {
    await client.accountingStart({
      username: 'alice',
      sessionId: 'session-1'
    });

    await client.accountingInterim({
      username: 'alice',
      sessionId: 'session-1',
      sessionTime: 30,
      inputOctets: 2048,
      outputOctets: 4096
    });

    await client.accountingStop({
      username: 'alice',
      sessionId: 'session-1',
      sessionTime: 60,
      terminateCause: 1
    });

    expect(accountingCalls).toHaveLength(3);

    const [startCall, interimCall, stopCall] = accountingCalls;

    expect(startCall?.request.statusType).toBe('Start');
    expect(interimCall?.request.statusType).toBe('Interim-Update');
    expect(stopCall?.request.statusType).toBe('Stop');

    expect(startCall?.options).toMatchObject({
      secret: 'secret',
      port: 1813,
      timeoutMs: 100
    });
  });

  test('sendAccounting timeout triggers failover when auth path is healthy but accounting path is unhealthy', async () => {
    responsiveHosts = new Set(['10.0.0.1', '10.0.0.2']);
    responsiveAccountingHosts = new Set(['10.0.0.2']);

    const authResult = await client.authenticate('alice', 'password');
    expect(authResult.ok).toBe(true);
    expect(client.getActiveHost()).toBe('10.0.0.1');

    const result = await client.sendAccounting({
      username: 'alice',
      sessionId: 'session-timeout',
      statusType: 'Start'
    });

    expect(result.ok).toBe(false);
    expect(result.error).toBe('timeout');

    await waitForCondition(
      () => client.getActiveHost() === '10.0.0.2',
      Math.max(healthTimeoutMs * 3, 250),
      'Expected active host to fail over to 10.0.0.2 after accounting timeout'
    );
  });
});
