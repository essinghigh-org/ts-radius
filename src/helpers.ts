import { RADIUS_ATTRIBUTES } from "./dictionary";
import type { ParsedRadiusAttribute, VendorSpecificAttribute } from "./types";

type DecodedAttributeValue = string | number | bigint | Date;

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
