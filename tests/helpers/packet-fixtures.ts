import { readFileSync } from "node:fs";
import path from "node:path";
import { inspect } from "node:util";
import { fileURLToPath } from "node:url";

import { decodeAttribute } from "../../src/helpers";
import type { ParsedRadiusAttribute } from "../../src/types";

export interface PacketAttributeExpectation {
    id: number;
    name: string;
    rawHex: string;
    decodedValue: unknown;
}

export interface RadiusPacketFixture {
    name: string;
    rfc: string;
    description: string;
    packetHex: string;
    expected: {
        code: number;
        identifier: number;
        length: number;
        authenticatorHexPattern: string;
        attributes: PacketAttributeExpectation[];
    };
}

export interface DecodedRadiusPacket {
    code: number;
    identifier: number;
    length: number;
    authenticator: Buffer;
    attributes: ParsedRadiusAttribute[];
    raw: Buffer;
}

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const FIXTURES_ROOT = path.resolve(__dirname, "..", "fixtures");

function isRecord(value: unknown): value is Record<string, unknown> {
    return typeof value === "object" && value !== null;
}

function isFiniteNumber(value: unknown): value is number {
    return typeof value === "number" && Number.isFinite(value);
}

function isString(value: unknown): value is string {
    return typeof value === "string";
}

function isPacketAttributeExpectation(value: unknown): value is PacketAttributeExpectation {
    if (!isRecord(value)) {
        return false;
    }

    return isFiniteNumber(value.id)
        && isString(value.name)
        && isString(value.rawHex)
        && "decodedValue" in value;
}

function isRadiusPacketFixture(value: unknown): value is RadiusPacketFixture {
    if (!isRecord(value)) {
        return false;
    }

    if (!isString(value.name) || !isString(value.rfc) || !isString(value.description) || !isString(value.packetHex)) {
        return false;
    }

    if (!isRecord(value.expected)) {
        return false;
    }

    const expected = value.expected;

    if (!isFiniteNumber(expected.code)
        || !isFiniteNumber(expected.identifier)
        || !isFiniteNumber(expected.length)
        || !isString(expected.authenticatorHexPattern)
        || !Array.isArray(expected.attributes)) {
        return false;
    }

    return expected.attributes.every(isPacketAttributeExpectation);
}

function normalizeHex(value: string): string {
    return value.replace(/[\s:_-]/g, "").toLowerCase();
}

function toDisplay(value: unknown): string {
    return inspect(value, { depth: null, breakLength: Infinity });
}

function decodedValuesMatch(actual: unknown, expected: unknown): boolean {
    if (actual instanceof Date) {
        if (typeof expected === "string") {
            return actual.toISOString() === expected;
        }

        if (expected instanceof Date) {
            return actual.getTime() === expected.getTime();
        }

        return false;
    }

    if (typeof actual === "bigint" && typeof expected === "string") {
        try {
            return actual === BigInt(expected);
        } catch {
            return false;
        }
    }

    if (typeof actual === "object" && actual !== null) {
        return JSON.stringify(actual) === JSON.stringify(expected);
    }

    return Object.is(actual, expected);
}

export function loadRadiusPacketFixture(relativePath: string): RadiusPacketFixture {
    const fixturePath = path.resolve(FIXTURES_ROOT, relativePath);
    const fixtureContent = readFileSync(fixturePath, "utf8");
    const parsed = JSON.parse(fixtureContent) as unknown;

    if (!isRadiusPacketFixture(parsed)) {
        throw new Error(`Invalid fixture format: ${relativePath}`);
    }

    return parsed;
}

export function hexToBuffer(hex: string): Buffer {
    const normalized = normalizeHex(hex);

    if (normalized.length % 2 !== 0) {
        throw new Error(`Hex input must have an even number of digits, received ${String(normalized.length)}`);
    }

    if (normalized.includes("?")) {
        throw new Error("Hex input cannot contain wildcard bytes (??)");
    }

    if (!/^[0-9a-f]*$/.test(normalized)) {
        throw new Error(`Hex input contains non-hex characters: ${hex}`);
    }

    return Buffer.from(normalized, "hex");
}

export function assertHexPatternMatch(actual: Buffer, expectedHexPattern: string): void {
    const normalizedPattern = normalizeHex(expectedHexPattern);

    if (normalizedPattern.length % 2 !== 0) {
        throw new Error(`Hex pattern must have an even number of digits, received ${String(normalizedPattern.length)}`);
    }

    if (!/^([0-9a-f]{2}|\?\?)*$/.test(normalizedPattern)) {
        throw new Error(`Invalid hex pattern: ${expectedHexPattern}`);
    }

    const actualHex = actual.toString("hex");

    if (actualHex.length !== normalizedPattern.length) {
        throw new Error(
            `Hex length mismatch. expected=${String(normalizedPattern.length / 2)} bytes actual=${String(actualHex.length / 2)} bytes`,
        );
    }

    for (let i = 0; i < normalizedPattern.length; i += 2) {
        const expectedByte = normalizedPattern.slice(i, i + 2);

        if (expectedByte === "??") {
            continue;
        }

        const actualByte = actualHex.slice(i, i + 2);
        if (actualByte !== expectedByte) {
            throw new Error(
                `Hex mismatch at byte ${String(i / 2)}: expected=${expectedByte}, actual=${actualByte}`,
            );
        }
    }
}

export function decodeRadiusPacket(packet: Buffer): DecodedRadiusPacket {
    if (packet.length < 20) {
        throw new Error(`RADIUS packet is too short: ${String(packet.length)} bytes`);
    }

    const length = packet.readUInt16BE(2);
    if (length !== packet.length) {
        throw new Error(`RADIUS length mismatch: header=${String(length)} actual=${String(packet.length)}`);
    }

    const attributes: ParsedRadiusAttribute[] = [];
    let offset = 20;

    while (offset < packet.length) {
        if (offset + 2 > packet.length) {
            throw new Error(`Attribute header truncated at offset ${String(offset)}`);
        }

        const type = packet.readUInt8(offset);
        const attrLength = packet.readUInt8(offset + 1);

        if (attrLength < 2) {
            throw new Error(`Attribute length < 2 at offset ${String(offset)}`);
        }

        const nextOffset = offset + attrLength;
        if (nextOffset > packet.length) {
            throw new Error(`Attribute at offset ${String(offset)} exceeds packet boundary`);
        }

        const value = packet.subarray(offset + 2, nextOffset);
        attributes.push(decodeAttribute(type, value));
        offset = nextOffset;
    }

    return {
        code: packet.readUInt8(0),
        identifier: packet.readUInt8(1),
        length,
        authenticator: packet.subarray(4, 20),
        attributes,
        raw: packet,
    };
}

export function assertPacketMatchesFixture(packet: Buffer, fixture: RadiusPacketFixture): DecodedRadiusPacket {
    const decoded = decodeRadiusPacket(packet);

    if (decoded.code !== fixture.expected.code) {
        throw new Error(`Unexpected code: expected=${String(fixture.expected.code)} actual=${String(decoded.code)}`);
    }

    if (decoded.identifier !== fixture.expected.identifier) {
        throw new Error(
            `Unexpected identifier: expected=${String(fixture.expected.identifier)} actual=${String(decoded.identifier)}`,
        );
    }

    if (decoded.length !== fixture.expected.length) {
        throw new Error(`Unexpected length: expected=${String(fixture.expected.length)} actual=${String(decoded.length)}`);
    }

    assertHexPatternMatch(decoded.authenticator, fixture.expected.authenticatorHexPattern);

    if (decoded.attributes.length !== fixture.expected.attributes.length) {
        throw new Error(
            `Unexpected attribute count: expected=${String(fixture.expected.attributes.length)} actual=${String(decoded.attributes.length)}`,
        );
    }

    for (const [index, expectedAttr] of fixture.expected.attributes.entries()) {
        const actualAttr = decoded.attributes[index];

        if (!actualAttr) {
            throw new Error(`Missing decoded attribute at index ${String(index)}`);
        }

        if (actualAttr.id !== expectedAttr.id) {
            throw new Error(
                `Attribute id mismatch at index ${String(index)}: expected=${String(expectedAttr.id)} actual=${String(actualAttr.id)}`,
            );
        }

        if (actualAttr.name !== expectedAttr.name) {
            throw new Error(
                `Attribute name mismatch at index ${String(index)}: expected=${expectedAttr.name} actual=${actualAttr.name}`,
            );
        }

        const expectedRaw = normalizeHex(expectedAttr.rawHex);
        if (actualAttr.raw !== expectedRaw) {
            throw new Error(
                `Attribute raw mismatch at index ${String(index)}: expected=${expectedRaw} actual=${actualAttr.raw}`,
            );
        }

        if (!decodedValuesMatch(actualAttr.value, expectedAttr.decodedValue)) {
            throw new Error(
                `Attribute value mismatch at index ${String(index)}: expected=${toDisplay(expectedAttr.decodedValue)} actual=${toDisplay(actualAttr.value)}`,
            );
        }
    }

    return decoded;
}