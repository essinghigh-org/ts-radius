import { describe, test, expect } from 'bun:test';
import * as publicApi from '../src/index';
import { RadiusClient } from '../src/client';
import { radiusAccounting, radiusAuthenticate, radiusCoa, radiusDisconnect } from '../src/protocol';
import { ConsoleLogger } from '../src/types';

describe('Public API compatibility contract', () => {
  test('exports the expected runtime surface from index', () => {
    expect(Object.keys(publicApi).sort()).toEqual([
      'ConsoleLogger',
      'RadiusClient',
      'radiusAccounting',
      'radiusAuthenticate',
      'radiusCoa',
      'radiusDisconnect'
    ]);
  });

  test('re-exports map to the canonical implementations', () => {
    expect(publicApi.RadiusClient).toBe(RadiusClient);
    expect(publicApi.radiusAccounting).toBe(radiusAccounting);
    expect(publicApi.radiusAuthenticate).toBe(radiusAuthenticate);
    expect(publicApi.radiusCoa).toBe(radiusCoa);
    expect(publicApi.radiusDisconnect).toBe(radiusDisconnect);
    expect(publicApi.ConsoleLogger).toBe(ConsoleLogger);
  });
});
