import { describe, test, expect } from 'bun:test';
import { decodeAttribute } from '../src/helpers';

describe('Attribute Decoding', () => {
  test('decodes User-Name (string)', () => {
    const value = Buffer.from('alice', 'utf8');
    const result = decodeAttribute(1, value);
    expect(result).toEqual({
      id: 1,
      name: 'User-Name',
      value: 'alice',
      raw: value.toString('hex')
    });
  });

  test('decodes NAS-IP-Address (ipaddr)', () => {
    const value = Buffer.from([192, 168, 1, 1]);
    const result = decodeAttribute(4, value);
    expect(result).toEqual({
      id: 4,
      name: 'NAS-IP-Address',
      value: '192.168.1.1',
      raw: value.toString('hex')
    });
  });

  test('decodes NAS-Port (integer)', () => {
    const value = Buffer.alloc(4);
    value.writeUInt32BE(12345, 0);
    const result = decodeAttribute(5, value);
    expect(result).toEqual({
      id: 5,
      name: 'NAS-Port',
      value: 12345,
      raw: value.toString('hex')
    });
  });

  test('decodes Event-Timestamp (date)', () => {
    const now = Math.floor(Date.now() / 1000);
    const value = Buffer.alloc(4);
    value.writeUInt32BE(now, 0);
    const result = decodeAttribute(55, value);
    expect(result.id).toBe(55);
    expect(result.name).toBe('Event-Timestamp');
    expect(result.value).toBeInstanceOf(Date);
    expect((result.value as Date).getTime()).toBe(now * 1000);
  });

  test('decodes NAS-IPv6-Address (ipv6addr)', () => {
    // 2001:db8::1
    const value = Buffer.from([
      0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
    ]);
    const result = decodeAttribute(95, value);
    expect(result.value).toBe('2001:db8:0:0:0:0:0:1');
  });

  test('decodes Framed-IPv6-Prefix (ipv6prefix)', () => {
    // Reserved (1) + Prefix-Length (1) + Prefix (up to 16)
    // /64 prefix: 2001:db8::
    const value = Buffer.concat([
        Buffer.from([0, 64]),
        Buffer.from([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0])
    ]);
    // 97 is Framed-IPv6-Prefix
    const result = decodeAttribute(97, value);
    // Helper implementation pads with zeros
    expect(result.value).toBe('2001:db8:0:0:0:0:0:0/64');
  });

  test('decodes Unknown Attribute as hex', () => {
    const value = Buffer.from([0xde, 0xad, 0xbe, 0xef]);
    const result = decodeAttribute(254, value);
    expect(result).toEqual({
      id: 254,
      name: 'Unknown-Attribute-254',
      value: 'deadbeef',
      raw: 'deadbeef'
    });
  });

  test('decodes Vendor-Specific (Type 26)', () => {
    // Cisco (9)
    // VSA: Type=1, Length=4, Value='AB'
    const vendorId = Buffer.alloc(4);
    vendorId.writeUInt32BE(9, 0);

    // Sub-attribute: Type 1, Length 4, Value 0x4142
    const subAttr = Buffer.from([1, 4, 0x41, 0x42]);

    const value = Buffer.concat([vendorId, subAttr]);

    const result = decodeAttribute(26, value);

    expect(result.id).toBe(26);
    expect(result.name).toBe('Vendor-Specific');

    if (!('vendorId' in result)) {
      throw new Error('Expected Vendor-Specific attribute result');
    }

    expect(result.vendorId).toBe(9);
    expect(result.value).toEqual([
      { vendorType: 1, value: '4142' }
    ]);
  });

  test('decodes Malformed Vendor-Specific as raw hex', () => {
     const value = Buffer.from([0, 0, 0, 9, 1]); // Too short for sub-header
     const result = decodeAttribute(26, value);
     expect(result.name).toBe('Vendor-Specific');

     if (!('vendorId' in result)) {
      throw new Error('Expected Vendor-Specific attribute result');
    }

     expect(result.vendorId).toBe(9);
     expect(typeof result.value).toBe('string');
  });

  test('decodes RFC6929 extended attributes with structured metadata', () => {
    const value = Buffer.from([0x01, 0xde, 0xad, 0xbe, 0xef]);
    const result = decodeAttribute(241, value);

    expect(result).toEqual({
      id: 241,
      name: 'Extended-Attribute-241',
      value: {
        format: 'extended',
        extendedType: 1,
        data: 'deadbeef'
      },
      raw: '01deadbeef'
    });
  });

  test('decodes RFC6929 long-extended attributes with continuation flags', () => {
    const value = Buffer.from([0x09, 0x80, 0xca, 0xfe, 0xba, 0xbe]);
    const result = decodeAttribute(245, value);

    expect(result).toEqual({
      id: 245,
      name: 'Long-Extended-Attribute-245',
      value: {
        format: 'long-extended',
        extendedType: 9,
        flags: 0x80,
        hasMore: true,
        data: 'cafebabe'
      },
      raw: '0980cafebabe'
    });
  });

  test('handles malformed RFC6929 extended attributes without throwing', () => {
    const result = decodeAttribute(241, Buffer.alloc(0));

    expect(result).toEqual({
      id: 241,
      name: 'Extended-Attribute-241',
      value: {
        format: 'extended',
        extendedType: 0,
        data: '',
        malformed: true,
        reason: 'missing_extended_type'
      },
      raw: ''
    });
  });

  test('handles malformed RFC6929 long-extended attributes without throwing', () => {
    const result = decodeAttribute(245, Buffer.from([0x0f]));

    expect(result).toEqual({
      id: 245,
      name: 'Long-Extended-Attribute-245',
      value: {
        format: 'long-extended',
        extendedType: 15,
        flags: 0,
        hasMore: false,
        data: '',
        malformed: true,
        reason: 'missing_long_extended_flags'
      },
      raw: '0f'
    });
  });

  test('preserves raw bytes to keep extended decoding roundtrip-friendly', () => {
    const value = Buffer.from([0x02, 0x01, 0x23, 0x45, 0x67]);
    const result = decodeAttribute(242, value);

    expect(result.raw).toBe(value.toString('hex'));

    if (typeof result.value !== 'object' || result.value === null || !('data' in result.value)) {
      throw new Error('Expected extended attribute value metadata');
    }

    expect(result.value.data).toBe(value.subarray(1).toString('hex'));
  });
});
