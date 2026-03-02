import crypto from "crypto";
import dgram from "dgram";

import { describe, expect, test } from "bun:test";

import { radiusCoa, radiusDisconnect } from "../src/protocol";
import type { RadiusCoaRequest, RadiusDisconnectRequest } from "../src/types";

type DynamicAuthorizationResponseCode = 41 | 42 | 44 | 45;

function encodeStringAttribute(type: number, value: string): Buffer {
  const encodedValue = Buffer.from(value, "utf8");
  return Buffer.concat([Buffer.from([type, encodedValue.length + 2]), encodedValue]);
}

function encodeIntegerAttribute(type: number, value: number): Buffer {
  const encodedValue = Buffer.alloc(4);
  encodedValue.writeUInt32BE(value, 0);
  return Buffer.concat([Buffer.from([type, 6]), encodedValue]);
}

function parseAttributes(packet: Buffer): Map<number, Buffer[]> {
  const attributes = new Map<number, Buffer[]>();
  let offset = 20;

  while (offset < packet.length) {
    if (offset + 2 > packet.length) {
      throw new Error(`Attribute header truncated at offset ${String(offset)}`);
    }

    const type = packet.readUInt8(offset);
    const length = packet.readUInt8(offset + 1);

    if (length < 2) {
      throw new Error(`Invalid attribute length ${String(length)} at offset ${String(offset)}`);
    }

    if (offset + length > packet.length) {
      throw new Error(`Attribute overruns packet at offset ${String(offset)}`);
    }

    const value = packet.subarray(offset + 2, offset + length);
    const existing = attributes.get(type) ?? [];
    existing.push(value);
    attributes.set(type, existing);
    offset += length;
  }

  return attributes;
}

function readStringAttribute(attributes: Map<number, Buffer[]>, type: number): string {
  const value = attributes.get(type)?.[0];
  if (!value) {
    throw new Error(`Missing expected attribute ${String(type)}`);
  }

  return value.toString("utf8");
}

function buildDynamicAuthorizationResponse(
  requestPacket: Buffer,
  secret: string,
  responseCode: DynamicAuthorizationResponseCode,
  attributes: Buffer[] = []
): Buffer {
  const identifier = requestPacket.readUInt8(1);
  const attributeBuffer = Buffer.concat(attributes);

  const response = Buffer.alloc(20 + attributeBuffer.length);
  response.writeUInt8(responseCode, 0);
  response.writeUInt8(identifier, 1);
  response.writeUInt16BE(response.length, 2);
  attributeBuffer.copy(response, 20);

  const hashInput = Buffer.concat([
    Buffer.from([response.readUInt8(0)]),
    Buffer.from([response.readUInt8(1)]),
    response.subarray(2, 4),
    requestPacket.subarray(4, 20),
    attributeBuffer,
    Buffer.from(secret, "utf8")
  ]);

  const authenticator = crypto.createHash("md5").update(hashInput).digest();
  authenticator.copy(response, 4);

  return response;
}

function closeSocket(server: dgram.Socket): Promise<void> {
  return new Promise((resolve) => {
    server.close(() => {
      resolve();
    });
  });
}

async function bindServer(): Promise<dgram.Socket> {
  const server = dgram.createSocket("udp4");

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.bind(0, "127.0.0.1", () => {
      server.removeListener("error", reject);
      resolve();
    });
  });

  return server;
}

function getServerPort(server: dgram.Socket): number {
  const address = server.address();
  if (typeof address === "string") {
    throw new Error("Expected UDP address information from bound socket");
  }

  return address.port;
}

describe("CoA/Disconnect protocol", () => {
  const sharedSecret = "super-secret";

  test("sends CoA-Request and handles CoA-ACK", async () => {
    const server = await bindServer();
    const receivedPackets: Buffer[] = [];

    server.on("message", (msg, rinfo) => {
      receivedPackets.push(Buffer.from(msg));
      const response = buildDynamicAuthorizationResponse(msg, sharedSecret, 44, [
        encodeStringAttribute(18, "updated")
      ]);
      server.send(response, rinfo.port, rinfo.address);
    });

    try {
      const request: RadiusCoaRequest = {
        username: "alice",
        sessionId: "session-001",
        attributes: [{ type: 11, value: "filter-prod" }]
      };

      const result = await radiusCoa("127.0.0.1", request, {
        secret: sharedSecret,
        port: getServerPort(server),
        timeoutMs: 500
      });

      expect(result.ok).toBe(true);
      expect(result.acknowledged).toBe(true);
      expect(receivedPackets).toHaveLength(1);

      const requestPacket = receivedPackets[0];
      if (!requestPacket) {
        throw new Error("Expected a captured CoA request packet");
      }

      expect(requestPacket.readUInt8(0)).toBe(43);
      expect(requestPacket.subarray(4, 20).equals(Buffer.alloc(16, 0))).toBe(false);

      const attributes = parseAttributes(requestPacket);
      expect(readStringAttribute(attributes, 1)).toBe("alice");
      expect(readStringAttribute(attributes, 44)).toBe("session-001");
      expect(readStringAttribute(attributes, 11)).toBe("filter-prod");
    } finally {
      await closeSocket(server);
    }
  });

  test("extracts Error-Cause from CoA-NAK responses", async () => {
    const server = await bindServer();

    server.on("message", (msg, rinfo) => {
      const response = buildDynamicAuthorizationResponse(msg, sharedSecret, 45, [
        encodeIntegerAttribute(101, 503)
      ]);
      server.send(response, rinfo.port, rinfo.address);
    });

    try {
      const result = await radiusCoa(
        "127.0.0.1",
        {
          username: "alice",
          sessionId: "session-002"
        },
        {
          secret: sharedSecret,
          port: getServerPort(server),
          timeoutMs: 500
        }
      );

      expect(result.ok).toBe(false);
      expect(result.acknowledged).toBe(false);
      expect(result.error).toBe("coa_nak");
      expect(result.errorCause).toBe(503);
      expect(result.attributes?.find((attribute) => attribute.id === 101)?.value).toBe(503);
    } finally {
      await closeSocket(server);
    }
  });

  test("sends Disconnect-Request and handles Disconnect-ACK", async () => {
    const server = await bindServer();
    const receivedPackets: Buffer[] = [];

    server.on("message", (msg, rinfo) => {
      receivedPackets.push(Buffer.from(msg));
      const response = buildDynamicAuthorizationResponse(msg, sharedSecret, 41, [
        encodeIntegerAttribute(49, 6)
      ]);
      server.send(response, rinfo.port, rinfo.address);
    });

    try {
      const request: RadiusDisconnectRequest = {
        username: "alice",
        sessionId: "session-003"
      };

      const result = await radiusDisconnect("127.0.0.1", request, {
        secret: sharedSecret,
        port: getServerPort(server),
        timeoutMs: 500
      });

      expect(result.ok).toBe(true);
      expect(result.acknowledged).toBe(true);
      expect(receivedPackets).toHaveLength(1);

      const requestPacket = receivedPackets[0];
      if (!requestPacket) {
        throw new Error("Expected a captured Disconnect request packet");
      }

      expect(requestPacket.readUInt8(0)).toBe(40);
      const attributes = parseAttributes(requestPacket);
      expect(readStringAttribute(attributes, 1)).toBe("alice");
      expect(readStringAttribute(attributes, 44)).toBe("session-003");
    } finally {
      await closeSocket(server);
    }
  });

  test("extracts Error-Cause from Disconnect-NAK responses", async () => {
    const server = await bindServer();

    server.on("message", (msg, rinfo) => {
      const response = buildDynamicAuthorizationResponse(msg, sharedSecret, 42, [
        encodeIntegerAttribute(101, 504)
      ]);
      server.send(response, rinfo.port, rinfo.address);
    });

    try {
      const result = await radiusDisconnect(
        "127.0.0.1",
        {
          username: "alice",
          sessionId: "session-004"
        },
        {
          secret: sharedSecret,
          port: getServerPort(server),
          timeoutMs: 500
        }
      );

      expect(result.ok).toBe(false);
      expect(result.acknowledged).toBe(false);
      expect(result.error).toBe("disconnect_nak");
      expect(result.errorCause).toBe(504);
      expect(result.attributes?.find((attribute) => attribute.id === 101)?.value).toBe(504);
    } finally {
      await closeSocket(server);
    }
  });
});