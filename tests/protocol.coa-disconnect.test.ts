import crypto from "crypto";
import dgram from "dgram";

import { describe, expect, test } from "bun:test";

import { radiusCoa, radiusDisconnect } from "../src/protocol";
import type { RadiusCoaRequest, RadiusDisconnectRequest } from "../src/types";

type DynamicAuthorizationResponseCode = number;

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

  test("honors caller-provided dynamic authorization request identity", async () => {
    const server = await bindServer();
    const receivedPackets: Buffer[] = [];
    const fixedIdentifier = 0x4f;
    const fixedAuthenticator = Buffer.from([
      0x01, 0x02, 0x03, 0x04,
      0x05, 0x06, 0x07, 0x08,
      0x09, 0x0a, 0x0b, 0x0c,
      0x0d, 0x0e, 0x0f, 0x10
    ]);

    server.on("message", (msg, rinfo) => {
      receivedPackets.push(Buffer.from(msg));
      const response = buildDynamicAuthorizationResponse(msg, sharedSecret, 44);
      server.send(response, rinfo.port, rinfo.address);
    });

    try {
      const result = await radiusCoa(
        "127.0.0.1",
        {
          username: "alice",
          sessionId: "session-identity-override"
        },
        {
          secret: sharedSecret,
          port: getServerPort(server),
          timeoutMs: 500,
          dynamicAuthorizationRequestIdentity: {
            identifier: fixedIdentifier,
            requestAuthenticator: fixedAuthenticator
          }
        }
      );

      expect(result.ok).toBe(true);
      expect(result.acknowledged).toBe(true);
      expect(receivedPackets).toHaveLength(1);

      const requestPacket = receivedPackets[0];
      if (!requestPacket) {
        throw new Error("Expected a captured CoA request packet");
      }

      expect(requestPacket.readUInt8(1)).toBe(fixedIdentifier);
      expect(requestPacket.subarray(4, 20).equals(fixedAuthenticator)).toBe(true);
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
      expect(result.errorCauseSymbol).toBe("session_context_not_found");
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
      expect(result.errorCauseSymbol).toBe("session_context_not_removable");
      expect(result.attributes?.find((attribute) => attribute.id === 101)?.value).toBe(504);
    } finally {
      await closeSocket(server);
    }
  });

  test("keeps unknown Error-Cause numeric and leaves symbol undefined", async () => {
    const server = await bindServer();

    server.on("message", (msg, rinfo) => {
      const response = buildDynamicAuthorizationResponse(msg, sharedSecret, 45, [
        encodeIntegerAttribute(101, 3999)
      ]);
      server.send(response, rinfo.port, rinfo.address);
    });

    try {
      const result = await radiusCoa(
        "127.0.0.1",
        {
          username: "alice",
          sessionId: "session-unknown-error-cause"
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
      expect(result.errorCause).toBe(3999);
      expect(result.errorCauseSymbol).toBeUndefined();
    } finally {
      await closeSocket(server);
    }
  });

  test("rejects CoA responses with identifier mismatch", async () => {
    const server = await bindServer();

    server.on("message", (msg, rinfo) => {
      const response = buildDynamicAuthorizationResponse(msg, sharedSecret, 44);
      response.writeUInt8((response.readUInt8(1) + 1) % 256, 1);
      server.send(response, rinfo.port, rinfo.address);
    });

    try {
      const result = await radiusCoa(
        "127.0.0.1",
        {
          username: "alice",
          sessionId: "session-id-mismatch"
        },
        {
          secret: sharedSecret,
          port: getServerPort(server),
          timeoutMs: 500
        }
      );

      expect(result.ok).toBe(false);
      expect(result.acknowledged).toBe(false);
      expect(result.error).toBe("identifier_mismatch");
    } finally {
      await closeSocket(server);
    }
  });

  test("ignores CoA responses from unexpected source port by default", async () => {
    const server = await bindServer();
    const alternate = await bindServer();

    server.on("message", (msg, rinfo) => {
      const response = buildDynamicAuthorizationResponse(msg, sharedSecret, 44);
      alternate.send(response, rinfo.port, rinfo.address);
    });

    try {
      const result = await radiusCoa(
        "127.0.0.1",
        {
          username: "alice",
          sessionId: "session-source-mismatch"
        },
        {
          secret: sharedSecret,
          port: getServerPort(server),
          timeoutMs: 200
        }
      );

      expect(result.ok).toBe(false);
      expect(result.acknowledged).toBe(false);
      expect(result.error).toBe("timeout");
    } finally {
      await closeSocket(server);
      await closeSocket(alternate);
    }
  });

  test("validates oversized dynamic authorization packet before socket allocation", async () => {
    const originalCreateSocket = dgram.createSocket;
    let createSocketCalls = 0;

    const createSocketSpy = ((...args: Parameters<typeof dgram.createSocket>) => {
      createSocketCalls += 1;
      return originalCreateSocket(...args);
    }) as typeof dgram.createSocket;

    (dgram as unknown as { createSocket: typeof dgram.createSocket }).createSocket = createSocketSpy;

    const oversizedAttributes = Array.from({ length: 260 }, (_, index) => ({
      type: (index % 255) + 1,
      value: "x".repeat(253)
    }));

    try {
      const oversizedRequest = radiusCoa(
        "127.0.0.1",
        {
          username: "alice",
          attributes: oversizedAttributes
        },
        {
          secret: sharedSecret,
          port: 3799,
          timeoutMs: 200
        }
      );

      let capturedError: unknown;
      try {
        await oversizedRequest;
      } catch (error: unknown) {
        capturedError = error;
      }

      expect(capturedError).toBeInstanceOf(Error);
      expect((capturedError as Error).message).toBe(
        "[radius] dynamic authorization packet exceeds maximum RADIUS length"
      );

      expect(createSocketCalls).toBe(0);
    } finally {
      (dgram as unknown as { createSocket: typeof dgram.createSocket }).createSocket = originalCreateSocket;
    }
  });

  test("rejects Disconnect responses with authenticator mismatch", async () => {
    const server = await bindServer();

    server.on("message", (msg, rinfo) => {
      const response = buildDynamicAuthorizationResponse(msg, sharedSecret, 41);
      response.writeUInt8(response.readUInt8(4) ^ 0xff, 4);
      server.send(response, rinfo.port, rinfo.address);
    });

    try {
      const result = await radiusDisconnect(
        "127.0.0.1",
        {
          username: "alice",
          sessionId: "session-auth-mismatch"
        },
        {
          secret: sharedSecret,
          port: getServerPort(server),
          timeoutMs: 500
        }
      );

      expect(result.ok).toBe(false);
      expect(result.acknowledged).toBe(false);
      expect(result.error).toBe("authenticator_mismatch");
    } finally {
      await closeSocket(server);
    }
  });

  test("returns malformed_response for short CoA responses", async () => {
    const server = await bindServer();

    server.on("message", (_, rinfo) => {
      server.send(Buffer.from([44, 1, 0, 20]), rinfo.port, rinfo.address);
    });

    try {
      const result = await radiusCoa(
        "127.0.0.1",
        {
          username: "alice",
          sessionId: "session-short-response"
        },
        {
          secret: sharedSecret,
          port: getServerPort(server),
          timeoutMs: 500
        }
      );

      expect(result.ok).toBe(false);
      expect(result.acknowledged).toBe(false);
      expect(result.error).toBe("malformed_response");
    } finally {
      await closeSocket(server);
    }
  });

  test("returns malformed_response for Disconnect length mismatch responses", async () => {
    const server = await bindServer();

    server.on("message", (msg, rinfo) => {
      const response = buildDynamicAuthorizationResponse(msg, sharedSecret, 41);
      response.writeUInt16BE(response.length + 1, 2);
      server.send(response, rinfo.port, rinfo.address);
    });

    try {
      const result = await radiusDisconnect(
        "127.0.0.1",
        {
          username: "alice",
          sessionId: "session-length-mismatch"
        },
        {
          secret: sharedSecret,
          port: getServerPort(server),
          timeoutMs: 500
        }
      );

      expect(result.ok).toBe(false);
      expect(result.acknowledged).toBe(false);
      expect(result.error).toBe("malformed_response");
    } finally {
      await closeSocket(server);
    }
  });

  test("returns unknown_code for CoA responses with unexpected response code", async () => {
    const server = await bindServer();

    server.on("message", (msg, rinfo) => {
      const response = buildDynamicAuthorizationResponse(msg, sharedSecret, 60, [
        encodeStringAttribute(18, "unexpected")
      ]);
      server.send(response, rinfo.port, rinfo.address);
    });

    try {
      const result = await radiusCoa(
        "127.0.0.1",
        {
          username: "alice",
          sessionId: "session-unknown-code"
        },
        {
          secret: sharedSecret,
          port: getServerPort(server),
          timeoutMs: 500
        }
      );

      expect(result.ok).toBe(false);
      expect(result.acknowledged).toBe(false);
      expect(result.error).toBe("unknown_code");
    } finally {
      await closeSocket(server);
    }
  });
});