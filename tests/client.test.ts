import { describe, test, expect, beforeEach, afterEach } from 'bun:test';
import { RadiusClient } from '../src/client';
import type {
  Logger,
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
let authResponseByUsername: Map<string, RadiusResult[]> = new Map();
let authDelayMsByHost: Map<string, number> = new Map();
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
let accountingResponseBySessionId: Map<string, RadiusResult[]> = new Map();
let coaResponseBySessionId: Map<string, RadiusCoaResult[]> = new Map();
let disconnectResponseBySessionId: Map<string, RadiusDisconnectResult[]> = new Map();
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

const protocolMock = {
  radiusAuthenticate: async (
    host: string,
    username: string,
    password: string,
    options: RadiusProtocolOptions,
    logger?: unknown
  ): Promise<RadiusResult> => {
    authCalls.push({ host, username, password, options, logger });

    const scriptedResponses = authResponseByUsername.get(username);
    if (scriptedResponses && scriptedResponses.length > 0) {
      const scriptedResponse = scriptedResponses.shift();
      if (scriptedResponse) {
        return scriptedResponse;
      }
    }

    const delayMs = authDelayMsByHost.get(host) ?? 0;
    if (delayMs > 0) {
      await Bun.sleep(delayMs);
    }

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

    const scriptedResponses = request.sessionId
      ? accountingResponseBySessionId.get(request.sessionId)
      : undefined;
    if (scriptedResponses && scriptedResponses.length > 0) {
      const scriptedResponse = scriptedResponses.shift();
      if (scriptedResponse) {
        return scriptedResponse;
      }
    }

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

    const scriptedResponses = request.sessionId
      ? coaResponseBySessionId.get(request.sessionId)
      : undefined;
    if (scriptedResponses && scriptedResponses.length > 0) {
      const scriptedResponse = scriptedResponses.shift();
      if (scriptedResponse) {
        return scriptedResponse;
      }
    }

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

    const scriptedResponses = request.sessionId
      ? disconnectResponseBySessionId.get(request.sessionId)
      : undefined;
    if (scriptedResponses && scriptedResponses.length > 0) {
      const scriptedResponse = scriptedResponses.shift();
      if (scriptedResponse) {
        return scriptedResponse;
      }
    }

    if (!responsiveDisconnectHosts.has(host)) {
      return { ok: false, acknowledged: false, error: 'timeout' };
    }

    return { ok: true, acknowledged: true };
  }
};

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

  const createInMemoryLogger = (): {
    logger: Logger;
    debugEntries: Array<{ message: string; args: unknown[] }>;
  } => {
    const debugEntries: Array<{ message: string; args: unknown[] }> = [];

    const logger: Logger = {
      debug(message: string, ...args: unknown[]): void {
        debugEntries.push({ message, args });
      },
      info(): void {
        // Intentionally no-op for tests.
      },
      warn(): void {
        // Intentionally no-op for tests.
      },
      error(): void {
        // Intentionally no-op for tests.
      }
    };

    return { logger, debugEntries };
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
    authResponseByUsername = new Map();
    authDelayMsByHost = new Map();
    statusCalls = [];
    accountingCalls = [];
    accountingResponseBySessionId = new Map();
    coaResponseBySessionId = new Map();
    disconnectResponseBySessionId = new Map();
    coaCalls = [];
    disconnectCalls = [];

    client = new RadiusClient(config, undefined, { protocol: protocolMock });
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

  test('constructor rejects blank secret values', () => {
    expect(() => {
      new RadiusClient({
        ...config,
        secret: '   '
      });
    }).toThrow('[radius-client] config.secret is required');
  });

  test('constructor rejects blank health check credentials', () => {
    expect(() => {
      new RadiusClient({
        ...config,
        healthCheckUser: '   '
      });
    }).toThrow('[radius-client] health check credentials (healthCheckUser, healthCheckPassword) are required');

    expect(() => {
      new RadiusClient({
        ...config,
        healthCheckPassword: '\t'
      });
    }).toThrow('[radius-client] health check credentials (healthCheckUser, healthCheckPassword) are required');
  });

  test('constructor rejects configuration with no usable hosts', () => {
    expect(() => {
      new RadiusClient({
        ...config,
        host: '   ',
        hosts: ['', '  ', '\t']
      });
    }).toThrow('[radius-client] at least one non-empty host is required');
  });

  test('host list fallback ignores blank entries and chooses first usable host', () => {
    const hostEdgeClient = new RadiusClient({
      ...config,
      host: '   ',
      hosts: ['  ', '', '10.0.0.9', '10.0.0.10'],
      healthCheckIntervalMs: 60000
    });

    expect(hostEdgeClient.getActiveHost()).toBe('10.0.0.9');

    hostEdgeClient.shutdown();
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

  test('authenticate forwards advanced protocol response validation options', async () => {
    const forwardingClient = new RadiusClient({
      ...config,
      healthCheckIntervalMs: 60000,
      validateResponseSource: false,
      responseLengthValidationPolicy: 'allow_trailing_bytes',
      responseMessageAuthenticatorPolicy: 'strict'
    }, undefined, { protocol: protocolMock });

    try {
      const result = await forwardingClient.authenticate('advanced-auth-user', 'hunter2');
      expect(result.ok).toBe(true);

      const userCall = authCalls.find(
        (call) => call.username === 'advanced-auth-user' && call.password === 'hunter2'
      );

      expect(userCall).toBeDefined();

      if (!userCall) {
        throw new Error('Expected protocol authenticate call for advanced option forwarding');
      }

      expect(userCall.options).toMatchObject({
        validateResponseSource: false,
        responseLengthValidationPolicy: 'allow_trailing_bytes',
        responseMessageAuthenticatorPolicy: 'strict'
      });
    } finally {
      forwardingClient.shutdown();
    }
  });

  test('authenticate logging avoids emitting raw username PII', async () => {
    const { logger, debugEntries } = createInMemoryLogger();
    const loggingClient = new RadiusClient(config, logger, { protocol: protocolMock });

    try {
      const username = 'sensitive.user@example.com';
      const result = await loggingClient.authenticate(username, 'hunter2');
      expect(result.ok).toBe(true);

      const authenticateStartLog = debugEntries.find(
        (entry) => entry.message === '[radius-client] authenticate start'
      );

      expect(authenticateStartLog).toBeDefined();

      const serializedMetadata = JSON.stringify(authenticateStartLog?.args ?? []);
      expect(serializedMetadata).not.toContain(username);
    } finally {
      loggingClient.shutdown();
    }
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
    }, undefined, { protocol: protocolMock });

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

  for (const retryableError of ['malformed_response', 'authenticator_mismatch', 'unknown_code'] as const) {
    test(`authenticate retries ${retryableError} failures when attempts remain`, async () => {
      const retryClient = new RadiusClient({
        ...config,
        hosts: ['10.0.0.1'],
        healthCheckIntervalMs: 60000,
        retry: {
          maxAttempts: 2,
          initialDelayMs: 0,
          backoffMultiplier: 1,
          maxDelayMs: 0,
          jitterRatio: 0
        }
      }, undefined, { protocol: protocolMock });

      try {
        const username = `auth-retry-${retryableError}`;

        responsiveHosts = new Set(['10.0.0.1']);
        rejectingHosts = new Set();
        authCalls = [];
        authResponseByUsername = new Map([
          [username, [
            { ok: false, error: retryableError },
            { ok: true }
          ]]
        ]);

        const result = await retryClient.authenticate(username, 'retry-pass');
        const userCalls = authCalls.filter((call) => call.username === username);

        expect(result.ok).toBe(true);
        expect(userCalls).toHaveLength(2);
        expect(userCalls.map((call) => call.host)).toEqual(['10.0.0.1', '10.0.0.1']);
      } finally {
        retryClient.shutdown();
      }
    });
  }

  test('authenticate does not retry non-retryable failures', async () => {
    const retryClient = new RadiusClient({
      ...config,
      hosts: ['10.0.0.1', '10.0.0.2'],
      healthCheckIntervalMs: 60000,
      retry: {
        maxAttempts: 3,
        initialDelayMs: 1,
        backoffMultiplier: 1,
        maxDelayMs: 1,
        jitterRatio: 0
      }
    }, undefined, { protocol: protocolMock });

    responsiveHosts = new Set(['10.0.0.1', '10.0.0.2']);
    rejectingHosts = new Set(['10.0.0.1']);
    authCalls = [];

    const result = await retryClient.authenticate('non-retryable-user', 'pass');

    const nonRetryableUserCalls = authCalls.filter((call) => call.username === 'non-retryable-user');

    expect(result.ok).toBe(false);
    expect(result.error).toBe('access_reject');
    expect(nonRetryableUserCalls).toHaveLength(1);
    expect(nonRetryableUserCalls[0]?.host).toBe('10.0.0.1');
    expect(retryClient.getActiveHost()).toBe('10.0.0.1');

    retryClient.shutdown();
  });

  test('authenticate preserves access_challenge compatibility without retries', async () => {
    const retryClient = new RadiusClient({
      ...config,
      hosts: ['10.0.0.1', '10.0.0.2'],
      healthCheckIntervalMs: 60000,
      retry: {
        maxAttempts: 3,
        initialDelayMs: 1,
        backoffMultiplier: 1,
        maxDelayMs: 1,
        jitterRatio: 0
      }
    }, undefined, { protocol: protocolMock });

    responsiveHosts = new Set(['10.0.0.1', '10.0.0.2']);
    authCalls = [];
    authResponseByUsername = new Map([
      ['challenge-user', [{ ok: false, error: 'access_challenge' }]]
    ]);

    const result = await retryClient.authenticate('challenge-user', 'pass');
    const challengeUserCalls = authCalls.filter((call) => call.username === 'challenge-user');

    expect(result.ok).toBe(false);
    expect(result.error).toBe('access_challenge');
    expect(challengeUserCalls).toHaveLength(1);
    expect(challengeUserCalls[0]?.host).toBe('10.0.0.1');

    retryClient.shutdown();
  });

  test('failover returns null when another health operation exceeds the wait window', async () => {
    responsiveHosts = new Set(['10.0.0.2']);
    authCalls = [];
    authDelayMsByHost = new Map([['10.0.0.2', 250]]);

    const firstFailover = client.failover();

    await waitForCondition(
      () => authCalls.some((call) => call.username === config.healthCheckUser && call.host === '10.0.0.2'),
      100,
      'Expected first failover to begin probing 10.0.0.2'
    );

    const failoverResult = await client.failover();
    const firstFailoverResult = await firstFailover;

    const healthProbeCalls = authCalls.filter((call) => call.username === config.healthCheckUser);

    expect(failoverResult).toBeNull();
    expect(firstFailoverResult).toBe('10.0.0.2');
    expect(healthProbeCalls.length).toBeGreaterThanOrEqual(1);
  });

  test('failover waits for in-progress operation to complete and then proceeds', async () => {
    responsiveHosts = new Set();
    authCalls = [];
    authDelayMsByHost = new Map([['10.0.0.2', 30]]);

    const firstFailover = client.failover();

    await waitForCondition(
      () => authCalls.some((call) => call.username === config.healthCheckUser && call.host === '10.0.0.2'),
      100,
      'Expected first failover to begin probing 10.0.0.2'
    );

    const makeHostResponsiveTimer = setTimeout(() => {
      responsiveHosts = new Set(['10.0.0.2']);
    }, 40);

    try {
      const failoverResult = await client.failover();
      const firstFailoverResult = await firstFailover;

      expect(firstFailoverResult).toBeNull();
      expect(failoverResult).toBe('10.0.0.2');
      expect(client.getActiveHost()).toBe('10.0.0.2');
    } finally {
      clearTimeout(makeHostResponsiveTimer);
    }
  });

  test('releaseHealthOperationLock isolates waiter failures and continues notifying remaining waiters', () => {
    const warnEntries: Array<{ message: string; args: unknown[] }> = [];

    const logger: Logger = {
      debug(): void {
        // Intentionally no-op for tests.
      },
      info(): void {
        // Intentionally no-op for tests.
      },
      warn(message: string, ...args: unknown[]): void {
        warnEntries.push({ message, args });
      },
      error(): void {
        // Intentionally no-op for tests.
      }
    };

    const lockClient = new RadiusClient(
      {
        ...config,
        healthCheckIntervalMs: 60000
      },
      logger,
      { protocol: protocolMock }
    );

    try {
      const internals = lockClient as unknown as {
        inProgress: boolean;
        inProgressWaiters: Array<() => void>;
        releaseHealthOperationLock: () => void;
      };

      const invocationOrder: string[] = [];
      internals.inProgress = true;
      internals.inProgressWaiters.push(
        () => {
          invocationOrder.push('first');
          throw new Error('waiter exploded');
        },
        () => {
          invocationOrder.push('second');
        }
      );

      expect(() => {
        internals.releaseHealthOperationLock();
      }).not.toThrow();
      expect(invocationOrder).toEqual(['first', 'second']);
      expect(internals.inProgress).toBe(false);
      expect(internals.inProgressWaiters).toHaveLength(0);
      expect(warnEntries.some((entry) => entry.message === '[radius-client] health operation waiter threw')).toBe(true);
    } finally {
      lockClient.shutdown();
    }
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
    }, undefined, { protocol: protocolMock });

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
    }, undefined, { protocol: protocolMock });

    responsiveHosts = new Set();
    authCalls = [];

    // Intentionally make the host responsive shortly after the first call.
    // If a regression causes extra attempts, this would flip the outcome and expose it.
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
    }, undefined, { protocol: protocolMock });

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
      }, undefined, { protocol: protocolMock });

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
    }, undefined, { protocol: protocolMock });

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
    }, undefined, { protocol: protocolMock });

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
    }, undefined, { protocol: protocolMock });

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

  test('status-server auth fallback forwards validateResponseSource from config', async () => {
    const statusClient = new RadiusClient({
      ...config,
      healthCheckIntervalMs: 60000,
      healthCheckProbeMode: 'status-server',
      validateResponseSource: false
    }, undefined, { protocol: protocolMock });

    statusResponsiveHosts = new Set();
    statusUnsupportedHosts = new Set(['10.0.0.2']);
    responsiveHosts = new Set(['10.0.0.2']);
    authCalls = [];
    statusCalls = [];

    const newHost = await statusClient.failover();

    expect(newHost).toBe('10.0.0.2');

    const statusProbeCall = statusCalls.find((call) => call.host === '10.0.0.2');
    expect(statusProbeCall).toBeDefined();

    if (!statusProbeCall) {
      throw new Error('Expected status-server probe call to verify validateResponseSource forwarding');
    }

    expect(statusProbeCall.options.validateResponseSource).toBe(false);

    const fallbackAuthProbe = authCalls.find(
      (call) => call.host === '10.0.0.2' && call.username === config.healthCheckUser
    );
    expect(fallbackAuthProbe).toBeDefined();

    if (!fallbackAuthProbe) {
      throw new Error('Expected fallback auth probe to verify validateResponseSource forwarding');
    }

    expect(fallbackAuthProbe.options.validateResponseSource).toBe(false);

    statusClient.shutdown();
  });

  test('status-server auth fallback forwards CHAP health probe options when configured', async () => {
    const chapChallenge = Buffer.from('00112233445566778899aabbccddeeff', 'hex');
    const statusClient = new RadiusClient({
      ...config,
      healthCheckIntervalMs: 60000,
      healthCheckProbeMode: 'status-server',
      authMethod: 'chap',
      chapId: 77,
      chapChallenge
    }, undefined, { protocol: protocolMock });

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

    if (!fallbackAuthProbe) {
      throw new Error('Expected fallback auth probe to be issued for CHAP forwarding test');
    }

    expect(fallbackAuthProbe.options.authMethod).toBe('chap');
    expect(fallbackAuthProbe.options.chapId).toBe(77);
    expect(fallbackAuthProbe.options.chapChallenge?.equals(chapChallenge)).toBe(true);

    statusClient.shutdown();
  });

  test('auth timeout probes omit responseLengthValidationPolicy forwarding and keep strict defaults', async () => {
    const probeClient = new RadiusClient({
      ...config,
      healthCheckIntervalMs: 60000,
      responseLengthValidationPolicy: 'allow_trailing_bytes'
    }, undefined, { protocol: protocolMock });

    const internals = probeClient as unknown as {
      activeHost: string | null;
      onAuthTimeout: () => Promise<void>;
    };

    internals.activeHost = '10.0.0.1';

    responsiveHosts = new Set(['10.0.0.1']);
    authCalls = [];

    await internals.onAuthTimeout();

    const authProbeCall = authCalls.find((call) => call.username === config.healthCheckUser);
    expect(authProbeCall).toBeDefined();

    if (!authProbeCall) {
      throw new Error('Expected auth timeout probe call to validate response length policy forwarding semantics');
    }

    expect(Object.prototype.hasOwnProperty.call(authProbeCall.options, 'responseLengthValidationPolicy')).toBe(false);

    probeClient.shutdown();
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

  test('sendCoa forwards advanced protocol response validation options', async () => {
    const forwardingClient = new RadiusClient({
      ...config,
      healthCheckIntervalMs: 60000,
      validateResponseSource: false,
      responseLengthValidationPolicy: 'allow_trailing_bytes',
      responseMessageAuthenticatorPolicy: 'strict'
    }, undefined, { protocol: protocolMock });

    try {
      const sessionId = 'session-coa-advanced-forwarding';
      const result = await forwardingClient.sendCoa({
        username: 'alice',
        sessionId
      });

      expect(result.ok).toBe(true);

      const call = coaCalls.find((entry) => entry.request.sessionId === sessionId);
      expect(call).toBeDefined();

      if (!call) {
        throw new Error('Expected a CoA protocol call for advanced option forwarding');
      }

      expect(call.options).toMatchObject({
        validateResponseSource: false,
        responseLengthValidationPolicy: 'allow_trailing_bytes',
        responseMessageAuthenticatorPolicy: 'strict'
      });
    } finally {
      forwardingClient.shutdown();
    }
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

  test('sendDisconnect forwards advanced protocol response validation options', async () => {
    const forwardingClient = new RadiusClient({
      ...config,
      healthCheckIntervalMs: 60000,
      validateResponseSource: false,
      responseLengthValidationPolicy: 'allow_trailing_bytes',
      responseMessageAuthenticatorPolicy: 'strict'
    }, undefined, { protocol: protocolMock });

    try {
      const sessionId = 'session-disconnect-advanced-forwarding';
      const result = await forwardingClient.sendDisconnect({
        username: 'alice',
        sessionId
      });

      expect(result.ok).toBe(true);

      const call = disconnectCalls.find((entry) => entry.request.sessionId === sessionId);
      expect(call).toBeDefined();

      if (!call) {
        throw new Error('Expected a Disconnect protocol call for advanced option forwarding');
      }

      expect(call.options).toMatchObject({
        validateResponseSource: false,
        responseLengthValidationPolicy: 'allow_trailing_bytes',
        responseMessageAuthenticatorPolicy: 'strict'
      });
    } finally {
      forwardingClient.shutdown();
    }
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

  test('dynamic-authorization timeout probes omit validateResponseSource forwarding', async () => {
    const probeClient = new RadiusClient({
      ...config,
      healthCheckIntervalMs: 60000,
      validateResponseSource: false
    }, undefined, { protocol: protocolMock });

    const internals = probeClient as unknown as {
      activeHost: string | null;
      onDynamicAuthorizationTimeout: (mode: 'coa' | 'disconnect') => Promise<void>;
    };

    internals.activeHost = '10.0.0.1';

    responsiveCoaHosts = new Set(['10.0.0.1']);
    responsiveDisconnectHosts = new Set(['10.0.0.1']);
    coaCalls = [];
    disconnectCalls = [];

    await internals.onDynamicAuthorizationTimeout('coa');
    await internals.onDynamicAuthorizationTimeout('disconnect');

    const coaProbeCall = coaCalls.find((call) => call.request.username === config.healthCheckUser);
    expect(coaProbeCall).toBeDefined();

    if (!coaProbeCall) {
      throw new Error('Expected CoA timeout probe call to validate option forwarding semantics');
    }

    expect(Object.prototype.hasOwnProperty.call(coaProbeCall.options, 'validateResponseSource')).toBe(false);

    const disconnectProbeCall = disconnectCalls.find((call) => call.request.username === config.healthCheckUser);
    expect(disconnectProbeCall).toBeDefined();

    if (!disconnectProbeCall) {
      throw new Error('Expected Disconnect timeout probe call to validate option forwarding semantics');
    }

    expect(Object.prototype.hasOwnProperty.call(disconnectProbeCall.options, 'validateResponseSource')).toBe(false);

    probeClient.shutdown();
  });

  test('dynamic-authorization timeout probes omit responseLengthValidationPolicy forwarding and keep strict defaults', async () => {
    const probeClient = new RadiusClient({
      ...config,
      healthCheckIntervalMs: 60000,
      responseLengthValidationPolicy: 'allow_trailing_bytes'
    }, undefined, { protocol: protocolMock });

    const internals = probeClient as unknown as {
      activeHost: string | null;
      onDynamicAuthorizationTimeout: (mode: 'coa' | 'disconnect') => Promise<void>;
    };

    internals.activeHost = '10.0.0.1';

    responsiveCoaHosts = new Set(['10.0.0.1']);
    responsiveDisconnectHosts = new Set(['10.0.0.1']);
    coaCalls = [];
    disconnectCalls = [];

    await internals.onDynamicAuthorizationTimeout('coa');
    await internals.onDynamicAuthorizationTimeout('disconnect');

    const coaProbeCall = coaCalls.find((call) => call.request.username === config.healthCheckUser);
    expect(coaProbeCall).toBeDefined();

    if (!coaProbeCall) {
      throw new Error('Expected CoA timeout probe call to validate response length policy forwarding semantics');
    }

    expect(Object.prototype.hasOwnProperty.call(coaProbeCall.options, 'responseLengthValidationPolicy')).toBe(false);

    const disconnectProbeCall = disconnectCalls.find((call) => call.request.username === config.healthCheckUser);
    expect(disconnectProbeCall).toBeDefined();

    if (!disconnectProbeCall) {
      throw new Error('Expected Disconnect timeout probe call to validate response length policy forwarding semantics');
    }

    expect(Object.prototype.hasOwnProperty.call(disconnectProbeCall.options, 'responseLengthValidationPolicy')).toBe(false);

    probeClient.shutdown();
  });

  test('sendCoa retries transient timeout failures with backoff and can recover', async () => {
    const retryClient = new RadiusClient({
      ...config,
      hosts: ['10.0.0.1', '10.0.0.2'],
      healthCheckIntervalMs: 60000,
      retry: {
        maxAttempts: 2,
        initialDelayMs: 25,
        backoffMultiplier: 1,
        maxDelayMs: 1000,
        jitterRatio: 0
      }
    }, undefined, { protocol: protocolMock });

    const timeoutHookModes: Array<'coa' | 'disconnect'> = [];
    (retryClient as unknown as {
      onDynamicAuthorizationTimeout: (mode: 'coa' | 'disconnect') => Promise<void>;
    }).onDynamicAuthorizationTimeout = async (mode: 'coa' | 'disconnect'): Promise<void> => {
      timeoutHookModes.push(mode);
    };

    responsiveCoaHosts = new Set(['10.0.0.2']);
    coaCalls = [];

    const startedAt = Date.now();
    const result = await retryClient.sendCoa({
      username: 'alice',
      sessionId: 'coa-retry-success'
    });
    const elapsedMs = Date.now() - startedAt;

    const userCalls = coaCalls
      .filter((call) => call.request.sessionId === 'coa-retry-success')
      .map((call) => call.host);

    expect(result.ok).toBe(true);
    expect(userCalls).toEqual(['10.0.0.1', '10.0.0.2']);
    expect(elapsedMs).toBeGreaterThanOrEqual(25);
    expect(timeoutHookModes).toHaveLength(0);
    expect(retryClient.getActiveHost()).toBe('10.0.0.2');

    retryClient.shutdown();
  });

  for (const retryableError of ['malformed_response', 'identifier_mismatch', 'authenticator_mismatch', 'unknown_code'] as const) {
    test(`sendCoa retries ${retryableError} failures when attempts remain`, async () => {
      const retryClient = new RadiusClient({
        ...config,
        hosts: ['10.0.0.1'],
        healthCheckIntervalMs: 60000,
        retry: {
          maxAttempts: 2,
          initialDelayMs: 0,
          backoffMultiplier: 1,
          maxDelayMs: 0,
          jitterRatio: 0
        }
      }, undefined, { protocol: protocolMock });

      try {
        const sessionId = `coa-retry-${retryableError}`;

        responsiveCoaHosts = new Set(['10.0.0.1']);
        coaCalls = [];
        coaResponseBySessionId = new Map([
          [sessionId, [
            { ok: false, acknowledged: false, error: retryableError },
            { ok: true, acknowledged: true }
          ]]
        ]);

        const result = await retryClient.sendCoa({
          username: 'alice',
          sessionId
        });

        const userCalls = coaCalls.filter((call) => call.request.sessionId === sessionId);

        expect(result.ok).toBe(true);
        expect(result.acknowledged).toBe(true);
        expect(userCalls).toHaveLength(2);
        expect(userCalls.map((call) => call.host)).toEqual(['10.0.0.1', '10.0.0.1']);
      } finally {
        retryClient.shutdown();
      }
    });
  }

  test('sendCoa retries keep default per-attempt identity behavior when no identity mode is configured', async () => {
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
    }, undefined, { protocol: protocolMock });

    responsiveCoaHosts = new Set(['10.0.0.2']);
    coaCalls = [];
    coaResponseBySessionId = new Map([
      ['coa-default-identity-mode', [
        { ok: false, acknowledged: false, error: 'timeout' },
        { ok: true, acknowledged: true }
      ]]
    ]);

    const result = await retryClient.sendCoa({
      username: 'alice',
      sessionId: 'coa-default-identity-mode'
    });

    const userCalls = coaCalls.filter((call) => call.request.sessionId === 'coa-default-identity-mode');

    expect(result.ok).toBe(true);
    expect(userCalls.map((call) => call.host)).toEqual(['10.0.0.1', '10.0.0.2']);
    expect(
      userCalls.every((call) => call.options.dynamicAuthorizationRequestIdentity === undefined)
    ).toBe(true);

    retryClient.shutdown();
  });

  test('sendCoa retries reuse the same transaction identity across failover when stable identity mode is enabled', async () => {
    const retryClient = new RadiusClient({
      ...config,
      hosts: ['10.0.0.1', '10.0.0.2'],
      healthCheckIntervalMs: 60000,
      dynamicAuthorizationRetryIdentityMode: 'stable',
      retry: {
        maxAttempts: 2,
        initialDelayMs: 1,
        backoffMultiplier: 1,
        maxDelayMs: 1,
        jitterRatio: 0
      }
    }, undefined, { protocol: protocolMock });

    responsiveCoaHosts = new Set(['10.0.0.2']);
    coaCalls = [];
    coaResponseBySessionId = new Map([
      ['coa-stable-identity-mode', [
        { ok: false, acknowledged: false, error: 'timeout' },
        { ok: true, acknowledged: true }
      ]]
    ]);

    const result = await retryClient.sendCoa({
      username: 'alice',
      sessionId: 'coa-stable-identity-mode'
    });

    const userCalls = coaCalls.filter((call) => call.request.sessionId === 'coa-stable-identity-mode');
    const identities = userCalls
      .map((call) => call.options.dynamicAuthorizationRequestIdentity)
      .filter((identity): identity is NonNullable<typeof identity> => identity !== undefined);

    expect(result.ok).toBe(true);
    expect(userCalls.map((call) => call.host)).toEqual(['10.0.0.1', '10.0.0.2']);
    expect(identities).toHaveLength(2);

    const firstIdentity = identities[0];
    if (!firstIdentity) {
      throw new Error('Expected first CoA retry identity to be defined');
    }

    for (const identity of identities.slice(1)) {
      expect(identity.identifier).toBe(firstIdentity.identifier);
      expect(identity.requestAuthenticator.equals(firstIdentity.requestAuthenticator)).toBe(true);
    }

    retryClient.shutdown();
  });

  test('sendDisconnect does not retry terminal NAK responses', async () => {
    const retryClient = new RadiusClient({
      ...config,
      hosts: ['10.0.0.1', '10.0.0.2'],
      healthCheckIntervalMs: 60000,
      retry: {
        maxAttempts: 3,
        initialDelayMs: 1,
        backoffMultiplier: 1,
        maxDelayMs: 1,
        jitterRatio: 0
      }
    }, undefined, { protocol: protocolMock });

    const timeoutHookModes: Array<'coa' | 'disconnect'> = [];
    (retryClient as unknown as {
      onDynamicAuthorizationTimeout: (mode: 'coa' | 'disconnect') => Promise<void>;
    }).onDynamicAuthorizationTimeout = async (mode: 'coa' | 'disconnect'): Promise<void> => {
      timeoutHookModes.push(mode);
    };

    disconnectCalls = [];
    disconnectResponseBySessionId = new Map([
      ['disconnect-terminal-nak', [
        { ok: false, acknowledged: false, error: 'disconnect_nak', errorCause: 401 }
      ]]
    ]);

    const result = await retryClient.sendDisconnect({
      username: 'alice',
      sessionId: 'disconnect-terminal-nak'
    });

    const userCalls = disconnectCalls.filter((call) => call.request.sessionId === 'disconnect-terminal-nak');

    expect(result.ok).toBe(false);
    expect(result.error).toBe('disconnect_nak');
    expect(userCalls).toHaveLength(1);
    expect(userCalls[0]?.host).toBe('10.0.0.1');
    expect(timeoutHookModes).toHaveLength(0);
    expect(retryClient.getActiveHost()).toBe('10.0.0.1');

    retryClient.shutdown();
  });

  for (const retryableError of ['malformed_response', 'identifier_mismatch', 'authenticator_mismatch', 'unknown_code'] as const) {
    test(`sendDisconnect retries ${retryableError} failures when attempts remain`, async () => {
      const retryClient = new RadiusClient({
        ...config,
        hosts: ['10.0.0.1'],
        healthCheckIntervalMs: 60000,
        retry: {
          maxAttempts: 2,
          initialDelayMs: 0,
          backoffMultiplier: 1,
          maxDelayMs: 0,
          jitterRatio: 0
        }
      }, undefined, { protocol: protocolMock });

      try {
        const sessionId = `disconnect-retry-${retryableError}`;

        responsiveDisconnectHosts = new Set(['10.0.0.1']);
        disconnectCalls = [];
        disconnectResponseBySessionId = new Map([
          [sessionId, [
            { ok: false, acknowledged: false, error: retryableError },
            { ok: true, acknowledged: true }
          ]]
        ]);

        const result = await retryClient.sendDisconnect({
          username: 'alice',
          sessionId
        });

        const userCalls = disconnectCalls.filter((call) => call.request.sessionId === sessionId);

        expect(result.ok).toBe(true);
        expect(result.acknowledged).toBe(true);
        expect(userCalls).toHaveLength(2);
        expect(userCalls.map((call) => call.host)).toEqual(['10.0.0.1', '10.0.0.1']);
      } finally {
        retryClient.shutdown();
      }
    });
  }

  test('sendDisconnect retries reuse the same transaction identity across failover when stable identity mode is enabled', async () => {
    const retryClient = new RadiusClient({
      ...config,
      hosts: ['10.0.0.1', '10.0.0.2'],
      healthCheckIntervalMs: 60000,
      dynamicAuthorizationRetryIdentityMode: 'stable',
      retry: {
        maxAttempts: 2,
        initialDelayMs: 1,
        backoffMultiplier: 1,
        maxDelayMs: 1,
        jitterRatio: 0
      }
    }, undefined, { protocol: protocolMock });

    responsiveDisconnectHosts = new Set(['10.0.0.2']);
    disconnectCalls = [];
    disconnectResponseBySessionId = new Map([
      ['disconnect-stable-identity-mode', [
        { ok: false, acknowledged: false, error: 'timeout' },
        { ok: true, acknowledged: true }
      ]]
    ]);

    const result = await retryClient.sendDisconnect({
      username: 'alice',
      sessionId: 'disconnect-stable-identity-mode'
    });

    const userCalls = disconnectCalls.filter((call) => call.request.sessionId === 'disconnect-stable-identity-mode');
    const identities = userCalls
      .map((call) => call.options.dynamicAuthorizationRequestIdentity)
      .filter((identity): identity is NonNullable<typeof identity> => identity !== undefined);

    expect(result.ok).toBe(true);
    expect(userCalls.map((call) => call.host)).toEqual(['10.0.0.1', '10.0.0.2']);
    expect(identities).toHaveLength(2);

    const firstIdentity = identities[0];
    if (!firstIdentity) {
      throw new Error('Expected first Disconnect retry identity to be defined');
    }

    for (const identity of identities.slice(1)) {
      expect(identity.identifier).toBe(firstIdentity.identifier);
      expect(identity.requestAuthenticator.equals(firstIdentity.requestAuthenticator)).toBe(true);
    }

    retryClient.shutdown();
  });

  test('sendCoa invokes timeout handling only after final timeout attempt', async () => {
    const retryClient = new RadiusClient({
      ...config,
      hosts: ['10.0.0.1'],
      healthCheckIntervalMs: 60000,
      retry: {
        maxAttempts: 3,
        initialDelayMs: 1,
        backoffMultiplier: 1,
        maxDelayMs: 1,
        jitterRatio: 0
      }
    }, undefined, { protocol: protocolMock });

    const timeoutHookModes: Array<'coa' | 'disconnect'> = [];
    (retryClient as unknown as {
      onDynamicAuthorizationTimeout: (mode: 'coa' | 'disconnect') => Promise<void>;
    }).onDynamicAuthorizationTimeout = async (mode: 'coa' | 'disconnect'): Promise<void> => {
      timeoutHookModes.push(mode);
    };

    coaCalls = [];
    coaResponseBySessionId = new Map([
      ['coa-final-timeout', [
        { ok: false, acknowledged: false, error: 'timeout' },
        { ok: false, acknowledged: false, error: 'timeout' },
        { ok: false, acknowledged: false, error: 'timeout' }
      ]]
    ]);

    const result = await retryClient.sendCoa({
      username: 'alice',
      sessionId: 'coa-final-timeout'
    });

    const userCalls = coaCalls.filter((call) => call.request.sessionId === 'coa-final-timeout');

    expect(result.ok).toBe(false);
    expect(result.error).toBe('timeout');
    expect(userCalls).toHaveLength(3);
    expect(timeoutHookModes).toEqual(['coa']);

    retryClient.shutdown();
  });

  test('accounting helper methods map to expected typed status values including On/Off', async () => {
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

    await client.accountingOn({
      delayTime: 5
    });

    await client.accountingOff({
      attributes: [{ type: 87, value: 'nas-down' }]
    });

    expect(accountingCalls).toHaveLength(5);

    const [startCall, interimCall, stopCall, onCall, offCall] = accountingCalls;

    expect(startCall?.request.statusType).toBe('Start');
    expect(interimCall?.request.statusType).toBe('Interim-Update');
    expect(stopCall?.request.statusType).toBe('Stop');
    expect(onCall?.request.statusType).toBe('Accounting-On');
    expect(offCall?.request.statusType).toBe('Accounting-Off');

    expect(onCall?.request.username).toBeUndefined();
    expect(onCall?.request.sessionId?.startsWith('acct-onoff-')).toBe(true);
    expect(offCall?.request.username).toBeUndefined();
    expect(offCall?.request.sessionId?.startsWith('acct-onoff-')).toBe(true);
    expect(onCall?.request.sessionId).not.toBe(offCall?.request.sessionId);

    expect(startCall?.options).toMatchObject({
      secret: 'secret',
      port: 1813,
      timeoutMs: 100
    });
  });

  test('sendAccounting forwards advanced protocol response validation options', async () => {
    const forwardingClient = new RadiusClient({
      ...config,
      healthCheckIntervalMs: 60000,
      validateResponseSource: false,
      responseLengthValidationPolicy: 'allow_trailing_bytes',
      responseMessageAuthenticatorPolicy: 'strict'
    }, undefined, { protocol: protocolMock });

    try {
      const sessionId = 'session-accounting-advanced-forwarding';
      const result = await forwardingClient.sendAccounting({
        username: 'alice',
        sessionId,
        statusType: 'Interim-Update'
      });

      expect(result.ok).toBe(true);

      const call = accountingCalls.find((entry) => entry.request.sessionId === sessionId);
      expect(call).toBeDefined();

      if (!call) {
        throw new Error('Expected an Accounting protocol call for advanced option forwarding');
      }

      expect(call.options).toMatchObject({
        validateResponseSource: false,
        responseLengthValidationPolicy: 'allow_trailing_bytes',
        responseMessageAuthenticatorPolicy: 'strict'
      });
    } finally {
      forwardingClient.shutdown();
    }
  });

  test('accounting probe session IDs are collision-safe and retain health- prefix', async () => {
    const originalDateNow = Date.now;
    Date.now = () => 1717171717171;

    responsiveAccountingHosts = new Set(['10.0.0.3']);
    accountingCalls = [];

    try {
      const failoverResult = await client.failover('accounting');
      expect(failoverResult).toBe('10.0.0.3');

      const accountingProbeSessionIds = accountingCalls
        .filter((call) => call.request.username === config.healthCheckUser)
        .map((call) => call.request.sessionId)
        .filter((sessionId): sessionId is string => typeof sessionId === 'string');

      expect(accountingProbeSessionIds.length).toBeGreaterThanOrEqual(2);
      expect(accountingProbeSessionIds.every((sessionId) => sessionId.startsWith('health-'))).toBe(true);
      expect(new Set(accountingProbeSessionIds).size).toBe(accountingProbeSessionIds.length);
    } finally {
      Date.now = originalDateNow;
    }
  });

  test('sendAccounting retries transient timeout failures with backoff and can recover', async () => {
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
    }, undefined, { protocol: protocolMock });

    const timeoutHookRequests: RadiusAccountingRequest[] = [];
    (retryClient as unknown as {
      onAccountingTimeout: (request: RadiusAccountingRequest) => Promise<void>;
    }).onAccountingTimeout = async (request: RadiusAccountingRequest): Promise<void> => {
      timeoutHookRequests.push(request);
    };

    accountingCalls = [];
    accountingResponseBySessionId = new Map([
      ['accounting-retry-success', [
        { ok: false, error: 'timeout' },
        { ok: true }
      ]]
    ]);

    const startedAt = Date.now();
    const result = await retryClient.sendAccounting({
      username: 'alice',
      sessionId: 'accounting-retry-success',
      statusType: 'Start'
    });
    const elapsedMs = Date.now() - startedAt;

    const userCalls = accountingCalls.filter((call) => call.request.sessionId === 'accounting-retry-success');

    expect(result.ok).toBe(true);
    expect(userCalls).toHaveLength(2);
    expect(elapsedMs).toBeGreaterThanOrEqual(25);
    expect(timeoutHookRequests).toHaveLength(0);

    retryClient.shutdown();
  });

  test('sendAccounting retries same-destination failures with a stable accounting request identifier', async () => {
    const retryClient = new RadiusClient({
      ...config,
      hosts: ['10.0.0.1'],
      healthCheckIntervalMs: 60000,
      retry: {
        maxAttempts: 2,
        initialDelayMs: 0,
        backoffMultiplier: 1,
        maxDelayMs: 0,
        jitterRatio: 0
      }
    }, undefined, { protocol: protocolMock });

    try {
      accountingCalls = [];
      accountingResponseBySessionId = new Map([
        ['accounting-stable-identifier', [
          { ok: false, error: 'timeout' },
          { ok: true }
        ]]
      ]);

      const result = await retryClient.sendAccounting({
        username: 'alice',
        sessionId: 'accounting-stable-identifier',
        statusType: 'Interim-Update'
      });

      const userCalls = accountingCalls.filter((call) => call.request.sessionId === 'accounting-stable-identifier');
      const identities = userCalls
        .map((call) => call.options.accountingRequestIdentity)
        .filter((identity): identity is NonNullable<typeof identity> => identity !== undefined);

      expect(result.ok).toBe(true);
      expect(userCalls).toHaveLength(2);
      expect(userCalls.map((call) => call.host)).toEqual(['10.0.0.1', '10.0.0.1']);
      expect(identities).toHaveLength(2);

      const firstIdentity = identities[0];
      if (!firstIdentity) {
        throw new Error('Expected first accounting retry identity to be defined');
      }

      for (const identity of identities.slice(1)) {
        expect(identity.identifier).toBe(firstIdentity.identifier);
      }
    } finally {
      retryClient.shutdown();
    }
  });

  for (const retryableError of ['malformed_response', 'identifier_mismatch', 'authenticator_mismatch', 'unknown_code'] as const) {
    test(`sendAccounting retries ${retryableError} failures when attempts remain`, async () => {
      const retryClient = new RadiusClient({
        ...config,
        hosts: ['10.0.0.1'],
        healthCheckIntervalMs: 60000,
        retry: {
          maxAttempts: 2,
          initialDelayMs: 0,
          backoffMultiplier: 1,
          maxDelayMs: 0,
          jitterRatio: 0
        }
      }, undefined, { protocol: protocolMock });

      try {
        const sessionId = `accounting-retry-${retryableError}`;

        responsiveAccountingHosts = new Set(['10.0.0.1']);
        accountingCalls = [];
        accountingResponseBySessionId = new Map([
          [sessionId, [
            { ok: false, error: retryableError },
            { ok: true }
          ]]
        ]);

        const result = await retryClient.sendAccounting({
          username: 'alice',
          sessionId,
          statusType: 'Interim-Update'
        });

        const userCalls = accountingCalls.filter((call) => call.request.sessionId === sessionId);

        expect(result.ok).toBe(true);
        expect(userCalls).toHaveLength(2);
        expect(userCalls.map((call) => call.host)).toEqual(['10.0.0.1', '10.0.0.1']);
      } finally {
        retryClient.shutdown();
      }
    });
  }

  test('sendAccounting invokes timeout handling only after final timeout attempt', async () => {
    const retryClient = new RadiusClient({
      ...config,
      hosts: ['10.0.0.1'],
      healthCheckIntervalMs: 60000,
      retry: {
        maxAttempts: 3,
        initialDelayMs: 1,
        backoffMultiplier: 1,
        maxDelayMs: 1,
        jitterRatio: 0
      }
    }, undefined, { protocol: protocolMock });

    const timeoutHookRequests: RadiusAccountingRequest[] = [];
    (retryClient as unknown as {
      onAccountingTimeout: (request: RadiusAccountingRequest) => Promise<void>;
    }).onAccountingTimeout = async (request: RadiusAccountingRequest): Promise<void> => {
      timeoutHookRequests.push(request);
    };

    accountingCalls = [];
    accountingResponseBySessionId = new Map([
      ['accounting-final-timeout', [
        { ok: false, error: 'timeout' },
        { ok: false, error: 'timeout' },
        { ok: false, error: 'timeout' }
      ]]
    ]);

    const result = await retryClient.sendAccounting({
      username: 'alice',
      sessionId: 'accounting-final-timeout',
      statusType: 'Start'
    });

    const userCalls = accountingCalls.filter((call) => call.request.sessionId === 'accounting-final-timeout');

    expect(result.ok).toBe(false);
    expect(result.error).toBe('timeout');
    expect(userCalls).toHaveLength(3);
    expect(timeoutHookRequests).toHaveLength(1);
    expect(timeoutHookRequests[0]?.sessionId).toBe('accounting-final-timeout');
    expect(timeoutHookRequests[0]?.statusType).toBe('Start');

    retryClient.shutdown();
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

  test('accounting timeout probe omits validateResponseSource forwarding', async () => {
    const probeClient = new RadiusClient({
      ...config,
      healthCheckIntervalMs: 60000,
      validateResponseSource: false
    }, undefined, { protocol: protocolMock });

    const internals = probeClient as unknown as {
      activeHost: string | null;
      onAccountingTimeout: (request: RadiusAccountingRequest) => Promise<void>;
    };

    internals.activeHost = '10.0.0.1';

    responsiveAccountingHosts = new Set(['10.0.0.1']);
    accountingCalls = [];

    await internals.onAccountingTimeout({
      username: 'alice',
      sessionId: 'accounting-timeout-omission',
      statusType: 'Interim-Update'
    });

    const accountingProbeCall = accountingCalls.find((call) => call.request.username === config.healthCheckUser);
    expect(accountingProbeCall).toBeDefined();

    if (!accountingProbeCall) {
      throw new Error('Expected accounting timeout probe call to validate option forwarding semantics');
    }

    expect(Object.prototype.hasOwnProperty.call(accountingProbeCall.options, 'validateResponseSource')).toBe(false);

    probeClient.shutdown();
  });

  test('accounting timeout probe omits responseLengthValidationPolicy forwarding and keeps strict defaults', async () => {
    const probeClient = new RadiusClient({
      ...config,
      healthCheckIntervalMs: 60000,
      responseLengthValidationPolicy: 'allow_trailing_bytes'
    }, undefined, { protocol: protocolMock });

    const internals = probeClient as unknown as {
      activeHost: string | null;
      onAccountingTimeout: (request: RadiusAccountingRequest) => Promise<void>;
    };

    internals.activeHost = '10.0.0.1';

    responsiveAccountingHosts = new Set(['10.0.0.1']);
    accountingCalls = [];

    await internals.onAccountingTimeout({
      username: 'alice',
      sessionId: 'accounting-timeout-length-policy-omission',
      statusType: 'Interim-Update'
    });

    const accountingProbeCall = accountingCalls.find((call) => call.request.username === config.healthCheckUser);
    expect(accountingProbeCall).toBeDefined();

    if (!accountingProbeCall) {
      throw new Error('Expected accounting timeout probe call to validate response length policy forwarding semantics');
    }

    expect(Object.prototype.hasOwnProperty.call(accountingProbeCall.options, 'responseLengthValidationPolicy')).toBe(false);

    probeClient.shutdown();
  });
});
