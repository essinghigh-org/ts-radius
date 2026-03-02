import { describe, test, expect } from 'bun:test';
import * as publicApi from '../src/index';
import { RadiusClient } from '../src/client';
import { radiusAuthenticate } from '../src/protocol';
import { ConsoleLogger } from '../src/types';

describe('Public API compatibility contract', () => {
  test('exports the expected runtime surface from index', () => {
    expect(Object.keys(publicApi).sort()).toEqual([
      'ConsoleLogger',
      'RadiusClient',
      'radiusAuthenticate'
    ]);
  });

  test('re-exports map to the canonical implementations', () => {
    expect(publicApi.RadiusClient).toBe(RadiusClient);
    expect(publicApi.radiusAuthenticate).toBe(radiusAuthenticate);
    expect(publicApi.ConsoleLogger).toBe(ConsoleLogger);
  });
});
