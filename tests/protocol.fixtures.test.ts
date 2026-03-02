import { describe, expect, test } from "bun:test";

import {
    assertHexPatternMatch,
    assertPacketMatchesFixture,
    hexToBuffer,
    loadRadiusPacketFixture,
} from "./helpers/packet-fixtures";
import type { RadiusPacketFixture } from "./helpers/packet-fixtures";

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
        const fixture: RadiusPacketFixture = {
            name: "rfc6929-extended-attribute",
            rfc: "RFC6929",
            description: "Access-Accept packet with one extended attribute (Type 241).",
            packetHex: "02 01 00 1b 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 f1 07 01 de ad be ef",
            expected: {
                code: 2,
                identifier: 1,
                length: 27,
                authenticatorHexPattern: "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
                attributes: [
                    {
                        id: 241,
                        name: "Extended-Attribute-241",
                        rawHex: "01deadbeef",
                        decodedValue: {
                            format: "extended",
                            extendedType: 1,
                            data: "deadbeef",
                        },
                    },
                ],
            },
        };

        const packet = hexToBuffer(fixture.packetHex);
        const decodedPacket = assertPacketMatchesFixture(packet, fixture);

        expect(decodedPacket.attributes).toHaveLength(1);
        expect(decodedPacket.attributes[0]?.raw).toBe("01deadbeef");
    });

    test("decodes RFC6929 long-extended attributes and exposes continuation metadata", () => {
        const fixture: RadiusPacketFixture = {
            name: "rfc6929-long-extended-attribute",
            rfc: "RFC6929",
            description: "Access-Accept packet with one long-extended attribute (Type 245).",
            packetHex: "02 01 00 1c 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 f5 08 05 80 ca fe ba be",
            expected: {
                code: 2,
                identifier: 1,
                length: 28,
                authenticatorHexPattern: "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
                attributes: [
                    {
                        id: 245,
                        name: "Long-Extended-Attribute-245",
                        rawHex: "0580cafebabe",
                        decodedValue: {
                            format: "long-extended",
                            extendedType: 5,
                            flags: 128,
                            hasMore: true,
                            data: "cafebabe",
                        },
                    },
                ],
            },
        };

        const packet = hexToBuffer(fixture.packetHex);
        const decodedPacket = assertPacketMatchesFixture(packet, fixture);

        expect(decodedPacket.attributes).toHaveLength(1);
        expect(decodedPacket.attributes[0]?.id).toBe(245);
    });
});