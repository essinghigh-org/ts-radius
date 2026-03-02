import { describe, expect, test } from "bun:test";

import {
    assertHexPatternMatch,
    assertPacketMatchesFixture,
    hexToBuffer,
    loadRadiusPacketFixture,
} from "./helpers/packet-fixtures";

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
});