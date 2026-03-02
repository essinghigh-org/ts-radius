import { describe, expect, test } from "bun:test";
import { readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
    assertHexPatternMatch,
    assertPacketMatchesFixture,
    hexToBuffer,
    loadRadiusPacketFixture,
} from "./helpers/packet-fixtures";
import type { RadiusPacketFixture } from "./helpers/packet-fixtures";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const FIXTURES_ROOT = path.resolve(__dirname, "fixtures");

function discoverPacketFixturePaths(relativeDirectory: string): string[] {
    const absoluteDirectory = path.resolve(FIXTURES_ROOT, relativeDirectory);
    const entries = readdirSync(absoluteDirectory, { withFileTypes: true });

    return entries
        .filter((entry) => entry.isFile() && entry.name.endsWith(".json"))
        .map((entry) => path.posix.join(relativeDirectory, entry.name))
        .sort((a, b) => a.localeCompare(b));
}

const RFC2869_PACKET_FIXTURES = discoverPacketFixturePaths("protocol/rfc2869/packets");
const RFC6929_PACKET_FIXTURES = discoverPacketFixturePaths("protocol/rfc6929/packets");

function createVendorSpecificFixture(decodedValue: unknown): RadiusPacketFixture {
    return {
        name: "vendor-specific-deterministic",
        rfc: "RFC2865",
        description: "Access-Accept packet with a Vendor-Specific attribute for deep equality checks.",
        packetHex: "02 01 00 22 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 1a 0e 00 00 00 09 01 04 41 42 02 04 43 44",
        expected: {
            code: 2,
            identifier: 1,
            length: 34,
            authenticatorHexPattern: "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
            attributes: [
                {
                    id: 26,
                    name: "Vendor-Specific",
                    rawHex: "000000090104414202044344",
                    decodedValue,
                },
            ],
        },
    };
}

describe("Protocol fixture infrastructure", () => {
    test("discovers all expected RFC2869 packet fixtures", () => {
        expect(RFC2869_PACKET_FIXTURES).toEqual([
            "protocol/rfc2869/packets/access-request.eap-message.json",
            "protocol/rfc2869/packets/access-request.message-authenticator.json",
            "protocol/rfc2869/packets/accounting-request.acct-interim-interval.json",
            "protocol/rfc2869/packets/accounting-request.event-timestamp.json",
        ]);
    });

    test("discovers all expected RFC6929 packet fixtures", () => {
        expect(RFC6929_PACKET_FIXTURES).toEqual([
            "protocol/rfc6929/packets/access-accept.extended-attribute.json",
            "protocol/rfc6929/packets/access-accept.long-extended-attribute.json",
        ]);
    });

    for (const fixturePath of RFC2869_PACKET_FIXTURES) {
        test(`decodes RFC2869 fixture deterministically: ${fixturePath}`, () => {
            const fixture = loadRadiusPacketFixture(fixturePath);
            const packet = hexToBuffer(fixture.packetHex);

            assertHexPatternMatch(packet, fixture.packetHex);
            const decodedPacket = assertPacketMatchesFixture(packet, fixture);

            expect(decodedPacket.code).toBe(fixture.expected.code);
            expect(decodedPacket.identifier).toBe(fixture.expected.identifier);
            expect(decodedPacket.attributes).toHaveLength(fixture.expected.attributes.length);
        });
    }

    test("decodes RFC2865 Access-Accept fixture deterministically", () => {
        const fixture = loadRadiusPacketFixture("protocol/rfc2865/packets/access-accept.class.json");
        const packet = hexToBuffer(fixture.packetHex);

        assertHexPatternMatch(packet, fixture.packetHex);
        const decodedPacket = assertPacketMatchesFixture(packet, fixture);

        expect(decodedPacket.code).toBe(2);
        expect(decodedPacket.identifier).toBe(1);
        expect(decodedPacket.attributes).toHaveLength(1);
        expect(decodedPacket.attributes[0]?.name).toBe("Class");
        expect(decodedPacket.attributes[0]?.value).toBe("engineer");
    });

    test("supports wildcard pattern assertions for non-deterministic bytes", () => {
        const fixture = loadRadiusPacketFixture("protocol/rfc2865/packets/access-accept.class.json");
        const packet = hexToBuffer(fixture.packetHex);

        packet[1] = 0xfe;
        packet.fill(0xab, 4, 20);

        assertHexPatternMatch(
            packet,
            "02 ?? 00 1e ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 19 0a 65 6e 67 69 6e 65 65 72",
        );
    });

    test("decodes RFC5176 CoA-ACK fixture deterministically", () => {
        const fixture = loadRadiusPacketFixture("protocol/rfc5176/packets/coa-ack.json");
        const packet = hexToBuffer(fixture.packetHex);

        const decodedPacket = assertPacketMatchesFixture(packet, fixture);
        expect(decodedPacket.code).toBe(44);
        expect(decodedPacket.attributes[0]?.name).toBe("Reply-Message");
        expect(decodedPacket.attributes[0]?.value).toBe("ok");
    });

    test("decodes RFC5176 CoA-NAK fixture with Error-Cause", () => {
        const fixture = loadRadiusPacketFixture("protocol/rfc5176/packets/coa-nak.error-cause.json");
        const packet = hexToBuffer(fixture.packetHex);

        const decodedPacket = assertPacketMatchesFixture(packet, fixture);
        expect(decodedPacket.code).toBe(45);
        expect(decodedPacket.attributes[0]?.name).toBe("Error-Cause");
        expect(decodedPacket.attributes[0]?.value).toBe(503);
    });

    test("decodes RFC5176 Disconnect-ACK fixture deterministically", () => {
        const fixture = loadRadiusPacketFixture("protocol/rfc5176/packets/disconnect-ack.json");
        const packet = hexToBuffer(fixture.packetHex);

        const decodedPacket = assertPacketMatchesFixture(packet, fixture);
        expect(decodedPacket.code).toBe(41);
        expect(decodedPacket.attributes[0]?.name).toBe("Acct-Terminate-Cause");
        expect(decodedPacket.attributes[0]?.value).toBe(6);
    });

    test("decodes RFC5176 Disconnect-NAK fixture with Error-Cause", () => {
        const fixture = loadRadiusPacketFixture("protocol/rfc5176/packets/disconnect-nak.error-cause.json");
        const packet = hexToBuffer(fixture.packetHex);

        const decodedPacket = assertPacketMatchesFixture(packet, fixture);
        expect(decodedPacket.code).toBe(42);
        expect(decodedPacket.attributes[0]?.name).toBe("Error-Cause");
        expect(decodedPacket.attributes[0]?.value).toBe(504);
    });

    test("rejects fixture paths outside tests/fixtures", () => {
        expect(() => loadRadiusPacketFixture("../protocol.fixtures.test.ts")).toThrow(
            "Fixture path escapes tests/fixtures",
        );
        expect(() => loadRadiusPacketFixture("/etc/passwd")).toThrow(
            "Fixture path must be relative to tests/fixtures",
        );
    });

    test("matches decoded objects independent of object key order", () => {
        const fixture = createVendorSpecificFixture([
            { value: "4142", vendorType: 1 },
            { value: "4344", vendorType: 2 },
        ]);

        const packet = hexToBuffer(fixture.packetHex);
        const decodedPacket = assertPacketMatchesFixture(packet, fixture);

        expect(decodedPacket.attributes[0]?.id).toBe(26);
    });

    test("keeps decoded array comparisons order-sensitive", () => {
        const fixture = createVendorSpecificFixture([
            { value: "4344", vendorType: 2 },
            { value: "4142", vendorType: 1 },
        ]);

        const packet = hexToBuffer(fixture.packetHex);

        expect(() => assertPacketMatchesFixture(packet, fixture)).toThrow("Attribute value mismatch");
    });

    test("decodes RFC6929 extended attributes and preserves raw payload bytes", () => {
        const fixture = loadRadiusPacketFixture("protocol/rfc6929/packets/access-accept.extended-attribute.json");
        const packet = hexToBuffer(fixture.packetHex);
        const decodedPacket = assertPacketMatchesFixture(packet, fixture);

        expect(decodedPacket.attributes).toHaveLength(1);
        expect(decodedPacket.attributes[0]?.raw).toBe("01deadbeef");
    });

    test("decodes RFC6929 long-extended attributes and exposes continuation metadata", () => {
        const fixture = loadRadiusPacketFixture("protocol/rfc6929/packets/access-accept.long-extended-attribute.json");
        const packet = hexToBuffer(fixture.packetHex);
        const decodedPacket = assertPacketMatchesFixture(packet, fixture);

        expect(decodedPacket.attributes).toHaveLength(1);
        expect(decodedPacket.attributes[0]?.id).toBe(245);
    });
});