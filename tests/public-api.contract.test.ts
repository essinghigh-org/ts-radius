import { describe, test, expect } from 'bun:test';
import * as publicApi from '../src/index';
import {
  buildBufferAttribute,
  buildIntegerAttribute,
  buildStringAttribute,
  isRadiusAttributeIntegerValue,
  isRadiusAttributeType,
  validateRadiusAttributeIntegerValue,
  validateRadiusAttributeType,
  validateRadiusAttributeValueLength
} from '../src/attributes';
import { RadiusClient } from '../src/client';
import { radiusAccounting, radiusAuthenticate, radiusCoa, radiusDisconnect, radiusStatusServerProbe } from '../src/protocol';
import { ConsoleLogger } from '../src/types';

describe('Public API compatibility contract', () => {
  test('exports the expected runtime surface from index', () => {
    expect(Object.keys(publicApi).sort()).toEqual([
      'ConsoleLogger',
      'RadiusClient',
      'buildBufferAttribute',
      'buildIntegerAttribute',
      'buildStringAttribute',
      'isRadiusAttributeIntegerValue',
      'isRadiusAttributeType',
      'radiusAccounting',
      'radiusAuthenticate',
      'radiusCoa',
      'radiusDisconnect',
      'radiusStatusServerProbe',
      'validateRadiusAttributeIntegerValue',
      'validateRadiusAttributeType',
      'validateRadiusAttributeValueLength'
    ]);
  });

  test('re-exports map to the canonical implementations', () => {
    expect(publicApi.RadiusClient).toBe(RadiusClient);
    expect(publicApi.radiusAccounting).toBe(radiusAccounting);
    expect(publicApi.radiusAuthenticate).toBe(radiusAuthenticate);
    expect(publicApi.radiusCoa).toBe(radiusCoa);
    expect(publicApi.radiusDisconnect).toBe(radiusDisconnect);
    expect(publicApi.radiusStatusServerProbe).toBe(radiusStatusServerProbe);
    expect(publicApi.buildStringAttribute).toBe(buildStringAttribute);
    expect(publicApi.buildIntegerAttribute).toBe(buildIntegerAttribute);
    expect(publicApi.buildBufferAttribute).toBe(buildBufferAttribute);
    expect(publicApi.isRadiusAttributeType).toBe(isRadiusAttributeType);
    expect(publicApi.isRadiusAttributeIntegerValue).toBe(isRadiusAttributeIntegerValue);
    expect(publicApi.validateRadiusAttributeType).toBe(validateRadiusAttributeType);
    expect(publicApi.validateRadiusAttributeIntegerValue).toBe(validateRadiusAttributeIntegerValue);
    expect(publicApi.validateRadiusAttributeValueLength).toBe(validateRadiusAttributeValueLength);
    expect(publicApi.ConsoleLogger).toBe(ConsoleLogger);
  });
});
