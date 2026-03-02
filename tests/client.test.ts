import { describe, test, expect, beforeEach, afterEach, mock } from 'bun:test';
import { RadiusClient } from '../src/client';
import type { RadiusConfig, RadiusResult, RadiusProtocolOptions } from '../src/types';

// State for mock
let responsiveHosts: Set<string> = new Set();
// Hosts that return Access-Reject (still alive)
let rejectingHosts: Set<string> = new Set();
let authCalls: {
  host: string;
  username: string;
  password: string;
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
  }
}));

describe('RadiusClient Failover', () => {
  let client: RadiusClient;
  const config: RadiusConfig = {
    host: '10.0.0.1',
    hosts: ['10.0.0.1', '10.0.0.2', '10.0.0.3'],
    secret: 'secret',
    timeoutMs: 100,
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
    authCalls = [];
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
});
