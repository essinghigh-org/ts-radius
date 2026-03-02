import { describe, expect, test } from "bun:test";
import { existsSync, readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { decodeRadiusPacket, hexToBuffer, loadRadiusPacketFixture } from "./helpers/packet-fixtures";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const FIXTURES_ROOT = path.resolve(__dirname, "fixtures");

function discoverPacketFixturePaths(relativeDirectory: string): string[] {
    const absoluteDirectory = path.resolve(FIXTURES_ROOT, relativeDirectory);
    if (!existsSync(absoluteDirectory)) {
        return [];
    }

    const entries = readdirSync(absoluteDirectory, { withFileTypes: true });

    return entries
        .filter((entry) => entry.isFile() && entry.name.endsWith(".json"))
        .map((entry) => path.posix.join(relativeDirectory, entry.name))
        .sort((a, b) => a.localeCompare(b));
}

const RFC2869_NEGATIVE_FIXTURES = discoverPacketFixturePaths("protocol/rfc2869/negative");
const RFC6929_NEGATIVE_FIXTURES = discoverPacketFixturePaths("protocol/rfc6929/negative");
const RFC5176_NEGATIVE_FIXTURES = discoverPacketFixturePaths("protocol/rfc5176/negative");

const REJECTION_EXPECTATIONS: Array<{ fixturePath: string; errorMessage: string }> = [
    {
        fixturePath: "protocol/rfc2869/negative/access-request.attribute-length-zero.json",
        errorMessage: "Attribute length < 2 at offset 20",
    },
    {
        fixturePath: "protocol/rfc2869/negative/access-request.message-authenticator.truncated-value.json",
        errorMessage: "Attribute at offset 20 exceeds packet boundary",
    },
    {
        fixturePath: "protocol/rfc6929/negative/access-accept.extended-attribute.length-overrun.json",
        errorMessage: "Attribute at offset 20 exceeds packet boundary",
    },
    {
        fixturePath: "protocol/rfc5176/negative/coa-ack.attribute-length-zero.json",
        errorMessage: "Attribute length < 2 at offset 20",
    },
    {
        fixturePath: "protocol/rfc5176/negative/coa-nak.error-cause.truncated-value.json",
        errorMessage: "Attribute at offset 20 exceeds packet boundary",
    },
    {
        fixturePath: "protocol/rfc5176/negative/disconnect-ack.declared-length-mismatch.json",
        errorMessage: "RADIUS length mismatch: header=26 actual=22",
    },
];

const MALFORMED_METADATA_EXPECTATIONS: Array<{
    fixturePath: string;
    reason: string;
}> = [
    {
        fixturePath: "protocol/rfc6929/negative/access-accept.extended-attribute.malformed-empty-value.json",
        reason: "missing_extended_type",
    },
    {
        fixturePath: "protocol/rfc6929/negative/access-accept.long-extended-attribute.malformed-missing-flags.json",
        reason: "missing_long_extended_flags",
    },
];

describe("Negative protocol fixture corpus", () => {
    test("discovers all expected RFC2869 negative fixtures", () => {
        expect(RFC2869_NEGATIVE_FIXTURES).toEqual([
            "protocol/rfc2869/negative/access-request.attribute-length-zero.json",
            "protocol/rfc2869/negative/access-request.message-authenticator.truncated-value.json",
        ]);
    });

    test("discovers all expected RFC6929 negative fixtures", () => {
        expect(RFC6929_NEGATIVE_FIXTURES).toEqual([
            "protocol/rfc6929/negative/access-accept.extended-attribute.length-overrun.json",
            "protocol/rfc6929/negative/access-accept.extended-attribute.malformed-empty-value.json",
            "protocol/rfc6929/negative/access-accept.long-extended-attribute.malformed-missing-flags.json",
        ]);
    });

    test("discovers all expected RFC5176 negative fixtures", () => {
        expect(RFC5176_NEGATIVE_FIXTURES).toEqual([
            "protocol/rfc5176/negative/coa-ack.attribute-length-zero.json",
            "protocol/rfc5176/negative/coa-nak.error-cause.truncated-value.json",
            "protocol/rfc5176/negative/disconnect-ack.declared-length-mismatch.json",
        ]);
    });

    for (const { fixturePath, errorMessage } of REJECTION_EXPECTATIONS) {
        test(`rejects malformed packet from fixture: ${fixturePath}`, () => {
            const fixture = loadRadiusPacketFixture(fixturePath);
            const packet = hexToBuffer(fixture.packetHex);

            expect(() => decodeRadiusPacket(packet)).toThrow(errorMessage);
        });
    }

    for (const { fixturePath, reason } of MALFORMED_METADATA_EXPECTATIONS) {
        test(`surfaces malformed RFC6929 metadata from fixture: ${fixturePath}`, () => {
            const fixture = loadRadiusPacketFixture(fixturePath);
            const packet = hexToBuffer(fixture.packetHex);
            const decoded = decodeRadiusPacket(packet);
            const attribute = decoded.attributes[0];

            if (!attribute || typeof attribute.value !== "object" || attribute.value === null) {
                throw new Error("Expected a structured RFC6929 attribute value");
            }

            expect(attribute.value).toMatchObject({
                malformed: true,
                reason,
            });
        });
    }
});