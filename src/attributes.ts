import type { RadiusAttribute } from "./types";

const MIN_RADIUS_ATTRIBUTE_TYPE = 1;
const MAX_RADIUS_ATTRIBUTE_TYPE = 255;
const MAX_RADIUS_ATTRIBUTE_VALUE_LENGTH = 253;
const MAX_UINT32 = 0xffffffff;

export function isRadiusAttributeType(value: number): boolean {
  return Number.isInteger(value)
    && value >= MIN_RADIUS_ATTRIBUTE_TYPE
    && value <= MAX_RADIUS_ATTRIBUTE_TYPE;
}

export function isRadiusAttributeIntegerValue(value: number): boolean {
  return Number.isInteger(value) && value >= 0 && value <= MAX_UINT32;
}

export function validateRadiusAttributeType(type: number): void {
  if (!isRadiusAttributeType(type)) {
    throw new Error("[radius] attribute type must be an integer between 1 and 255");
  }
}

export function validateRadiusAttributeIntegerValue(type: number, value: number): void {
  validateRadiusAttributeType(type);

  if (!isRadiusAttributeIntegerValue(value)) {
    throw new Error(`[radius] attribute ${String(type)} must be uint32`);
  }
}

export function validateRadiusAttributeValueLength(type: number, value: Buffer): void {
  validateRadiusAttributeType(type);

  if (value.length > MAX_RADIUS_ATTRIBUTE_VALUE_LENGTH) {
    throw new Error(`[radius] attribute ${String(type)} value length must be <= 253 bytes`);
  }
}

export function buildStringAttribute(type: number, value: string): RadiusAttribute {
  validateRadiusAttributeType(type);
  validateRadiusAttributeValueLength(type, Buffer.from(value, "utf8"));

  return {
    type,
    value,
  };
}

export function buildIntegerAttribute(type: number, value: number): RadiusAttribute {
  validateRadiusAttributeIntegerValue(type, value);

  return {
    type,
    value,
  };
}

export function buildBufferAttribute(type: number, value: Buffer): RadiusAttribute {
  validateRadiusAttributeType(type);
  validateRadiusAttributeValueLength(type, value);

  return {
    type,
    value,
  };
}