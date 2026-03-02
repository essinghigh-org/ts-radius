import { describe, expect, test } from "bun:test";

import {
  buildBufferAttribute,
  buildIntegerAttribute,
  buildStringAttribute,
  isRadiusAttributeIntegerValue,
  isRadiusAttributeType,
  validateRadiusAttributeIntegerValue,
  validateRadiusAttributeType,
  validateRadiusAttributeValueLength,
} from "../src/index";

describe("public attribute builders", () => {
  test("buildStringAttribute creates a typed string attribute", () => {
    const attribute = buildStringAttribute(1, "alice");

    expect(attribute).toEqual({
      type: 1,
      value: "alice",
    });
  });

  test("buildIntegerAttribute creates a typed uint32 attribute", () => {
    const attribute = buildIntegerAttribute(5, 42);

    expect(attribute).toEqual({
      type: 5,
      value: 42,
    });
  });

  test("buildBufferAttribute creates a typed binary attribute", () => {
    const value = Buffer.from([0xde, 0xad, 0xbe, 0xef]);
    const attribute = buildBufferAttribute(26, value);

    expect(attribute).toEqual({
      type: 26,
      value,
    });
  });

  test("validators accept valid values", () => {
    expect(isRadiusAttributeType(255)).toBe(true);
    expect(isRadiusAttributeIntegerValue(0xffffffff)).toBe(true);
    validateRadiusAttributeType(1);
    validateRadiusAttributeIntegerValue(5, 0);
    validateRadiusAttributeValueLength(1, Buffer.alloc(253));
  });

  test("validators reject invalid values", () => {
    expect(isRadiusAttributeType(0)).toBe(false);
    expect(isRadiusAttributeIntegerValue(-1)).toBe(false);

    expect(() => {
      validateRadiusAttributeType(0);
    }).toThrow(
      "[radius] attribute type must be an integer between 1 and 255",
    );
    expect(() => {
      validateRadiusAttributeIntegerValue(5, -1);
    }).toThrow("[radius] attribute 5 must be uint32");
    expect(() => {
      validateRadiusAttributeValueLength(1, Buffer.alloc(254));
    }).toThrow(
      "[radius] attribute 1 value length must be <= 253 bytes",
    );
  });

  test("builders validate their inputs", () => {
    expect(() => {
      buildStringAttribute(0, "alice");
    }).toThrow(
      "[radius] attribute type must be an integer between 1 and 255",
    );

    expect(() => {
      buildIntegerAttribute(40, 0x1_0000_0000);
    }).toThrow("[radius] attribute 40 must be uint32");

    expect(() => {
      buildBufferAttribute(80, Buffer.alloc(254));
    }).toThrow(
      "[radius] attribute 80 value length must be <= 253 bytes",
    );
  });
});