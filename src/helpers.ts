import { RADIUS_ATTRIBUTES } from "./dictionary";
import type { ExtendedRadiusAttribute, ParsedRadiusAttribute, VendorSpecificAttribute } from "./types";

type DecodedAttributeValue = string | number | bigint | Date;
const EXTENDED_ATTRIBUTE_IDS = [241, 242, 243, 244] as const;
const LONG_EXTENDED_ATTRIBUTE_IDS = [245, 246] as const;

type ExtendedAttributeId = (typeof EXTENDED_ATTRIBUTE_IDS)[number];
type LongExtendedAttributeId = (typeof LONG_EXTENDED_ATTRIBUTE_IDS)[number];

function isExtendedAttributeId(id: number): id is ExtendedAttributeId {
  return EXTENDED_ATTRIBUTE_IDS.includes(id as ExtendedAttributeId);
}

function isLongExtendedAttributeId(id: number): id is LongExtendedAttributeId {
  return LONG_EXTENDED_ATTRIBUTE_IDS.includes(id as LongExtendedAttributeId);
}

function decodeExtendedAttribute(id: ExtendedAttributeId, value: Buffer): ExtendedRadiusAttribute {
  const raw = value.toString("hex");

  if (value.length < 1) {
    return {
      id,
      name: `Extended-Attribute-${String(id)}`,
      value: {
        format: "extended",
        extendedType: 0,
        data: "",
        malformed: true,
        reason: "missing_extended_type"
      },
      raw
    };
  }

  const extendedType = value.readUInt8(0);
  const data = value.subarray(1).toString("hex");

  return {
    id,
    name: `Extended-Attribute-${String(id)}`,
    value: {
      format: "extended",
      extendedType,
      data
    },
    raw
  };
}

function decodeLongExtendedAttribute(id: LongExtendedAttributeId, value: Buffer): ExtendedRadiusAttribute {
  const raw = value.toString("hex");

  if (value.length < 1) {
    return {
      id,
      name: `Long-Extended-Attribute-${String(id)}`,
      value: {
        format: "long-extended",
        extendedType: 0,
        flags: 0,
        hasMore: false,
        data: "",
        malformed: true,
        reason: "missing_long_extended_type"
      },
      raw
    };
  }

  const extendedType = value.readUInt8(0);

  if (value.length < 2) {
    return {
      id,
      name: `Long-Extended-Attribute-${String(id)}`,
      value: {
        format: "long-extended",
        extendedType,
        flags: 0,
        hasMore: false,
        data: "",
        malformed: true,
        reason: "missing_long_extended_flags"
      },
      raw
    };
  }

  const flags = value.readUInt8(1);
  const data = value.subarray(2).toString("hex");

  return {
    id,
    name: `Long-Extended-Attribute-${String(id)}`,
    value: {
      format: "long-extended",
      extendedType,
      flags,
      hasMore: (flags & 0x80) !== 0,
      data
    },
    raw
  };
}

export function decodeString(buffer: Buffer): string {
  return buffer.toString("utf8");
}

export function decodeInteger(buffer: Buffer): number {
  if (buffer.length !== 4) return 0;
  return buffer.readUInt32BE(0);
}

export function decodeInteger64(buffer: Buffer): bigint {
  if (buffer.length !== 8) return BigInt(0);
  return buffer.readBigUInt64BE(0);
}

export function decodeDate(buffer: Buffer): Date {
  if (buffer.length !== 4) return new Date(0);
  const seconds = buffer.readUInt32BE(0);
  return new Date(seconds * 1000);
}

export function decodeIpAddr(buffer: Buffer): string {
  if (buffer.length !== 4) return "0.0.0.0";

  return [
    buffer.readUInt8(0),
    buffer.readUInt8(1),
    buffer.readUInt8(2),
    buffer.readUInt8(3),
  ].join(".");
}

export function decodeIpv6Addr(buffer: Buffer): string {
  if (buffer.length !== 16) return "::";
  const parts: string[] = [];
  for (let i = 0; i < 16; i += 2) {
    parts.push(buffer.readUInt16BE(i).toString(16));
  }
  return parts.join(":");
}

export function decodeIpv6Prefix(buffer: Buffer): string {
  if (buffer.length < 2) return "";
  // buffer[0] is reserved
  const prefixLength = buffer.readUInt8(1);
  const prefixBuffer = buffer.subarray(2);

  const fullAddress = Buffer.alloc(16, 0);
  prefixBuffer.copy(fullAddress);

  const parts: string[] = [];
  for (let i = 0; i < 16; i += 2) {
    parts.push(fullAddress.readUInt16BE(i).toString(16));
  }
  return `${parts.join(":")}/${String(prefixLength)}`;
}

export function decodeIfId(buffer: Buffer): string {
  if (buffer.length !== 8) return buffer.toString("hex");
  const parts: string[] = [];
  for (let i = 0; i < 8; i++) {
    parts.push(buffer.readUInt8(i).toString(16).padStart(2, "0"));
  }
  return parts.join(":");
}

export function decodeVendorSpecific(value: Buffer): VendorSpecificAttribute {
  if (value.length < 4) {
    return {
      id: 26,
      name: "Vendor-Specific",
      vendorId: 0,
      value: value.toString("hex"),
      raw: value.toString("hex")
    };
  }

  const vendorId = value.readUInt32BE(0);
  const data = value.subarray(4);

  // Attempt to parse sub-attributes
  const subAttributes: { vendorType: number; value: string }[] = [];
  let offset = 0;
  let parsable = true;

  // Generic VSA parsing: Type (1 byte), Length (1 byte), Value (Length-2)
  while (offset < data.length) {
    if (offset + 2 > data.length) {
        parsable = false;
        break;
    }
    const t = data.readUInt8(offset);
    const l = data.readUInt8(offset + 1);

    if (l < 2 || offset + l > data.length) {
        parsable = false;
        break;
    }

    const val = data.subarray(offset + 2, offset + l);
    subAttributes.push({
        vendorType: t,
        value: val.toString("hex")
    });
    offset += l;
  }

  return {
    id: 26,
    name: "Vendor-Specific",
    vendorId,
    value: parsable && subAttributes.length > 0 ? subAttributes : data.toString("hex"),
    raw: value.toString("hex")
  };
}

export function decodeAttribute(id: number, value: Buffer): ParsedRadiusAttribute {
  if (id === 26) {
    return decodeVendorSpecific(value);
  }

  if (isExtendedAttributeId(id)) {
    return decodeExtendedAttribute(id, value);
  }

  if (isLongExtendedAttributeId(id)) {
    return decodeLongExtendedAttribute(id, value);
  }

  const def = RADIUS_ATTRIBUTES[id];

  if (!def) {
    return {
      id,
      name: `Unknown-Attribute-${String(id)}`,
      value: value.toString("hex"),
      raw: value.toString("hex")
    };
  }

  let decodedValue: DecodedAttributeValue;

  try {
    switch (def.type) {
      case "string":
        decodedValue = decodeString(value);
        break;
      case "integer":
        decodedValue = decodeInteger(value);
        break;
      case "integer64":
        decodedValue = decodeInteger64(value);
        break;
      case "date":
        decodedValue = decodeDate(value);
        break;
      case "ipaddr":
        decodedValue = decodeIpAddr(value);
        break;
      case "ipv6addr":
        decodedValue = decodeIpv6Addr(value);
        break;
      case "ipv6prefix":
        decodedValue = decodeIpv6Prefix(value);
        break;
      case "ifid":
        decodedValue = decodeIfId(value);
        break;
      default:
        decodedValue = value.toString("hex");
    }
  } catch {
    decodedValue = value.toString("hex");
  }

  return {
    id,
    name: def.name,
    value: decodedValue,
    raw: value.toString("hex")
  };
}
