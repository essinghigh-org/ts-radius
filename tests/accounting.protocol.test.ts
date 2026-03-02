import crypto from "crypto";
import dgram from "dgram";

import { describe, expect, test } from "bun:test";

import { radiusAccounting } from "../src/protocol";
import type { RadiusAccountingRequest } from "../src/types";

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

function readIntegerAttribute(attributes: Map<number, Buffer[]>, type: number): number {
  const value = attributes.get(type)?.[0];
  if (!value) {
    throw new Error(`Missing expected attribute ${String(type)}`);
  }
  if (value.length !== 4) {
    throw new Error(`Expected integer attribute ${String(type)} to be 4 bytes`);
  }
  return value.readUInt32BE(0);
}

function buildAccountingResponsePacket(
  requestPacket: Buffer,
  secret: string,
  responseCode = 5,
  tamperAuthenticator = false,
  responseIdentifier?: number
): Buffer {
  const identifier = responseIdentifier ?? requestPacket.readUInt8(1);
  const attributes = Buffer.alloc(0);

  const response = Buffer.alloc(20 + attributes.length);
  response.writeUInt8(responseCode, 0);
  response.writeUInt8(identifier, 1);
  response.writeUInt16BE(response.length, 2);
  attributes.copy(response, 20);

  const hashInput = Buffer.concat([
    response.subarray(0, 4),
    requestPacket.subarray(4, 20),
    attributes,
    Buffer.from(secret, "utf8")
  ]);

  const authenticator = crypto.createHash("md5").update(hashInput).digest();
  if (!tamperAuthenticator) {
    authenticator.copy(response, 4);
  }

  return response;
}

function appendTrailingBytes(packet: Buffer): Buffer {
  return Buffer.concat([packet, Buffer.from([0xde, 0xad, 0xbe, 0xef])]);
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

describe("Accounting protocol", () => {
  const sharedSecret = "super-secret";

  test("builds Accounting-Request packet for Start and validates Accounting-Response", async () => {
    const server = await bindServer();
    const receivedPackets: Buffer[] = [];

    server.on("message", (msg, rinfo) => {
      receivedPackets.push(Buffer.from(msg));
      const response = buildAccountingResponsePacket(msg, sharedSecret, 5);
      server.send(response, rinfo.port, rinfo.address);
    });

    try {
      const request: RadiusAccountingRequest = {
        username: "alice",
        sessionId: "session-001",
        statusType: "Start"
      };

      const result = await radiusAccounting("127.0.0.1", request, {
        secret: sharedSecret,
        port: getServerPort(server),
        timeoutMs: 500
      });

      expect(result.ok).toBe(true);
      expect(receivedPackets).toHaveLength(1);

      const requestPacket = receivedPackets[0];
      expect(requestPacket?.readUInt8(0)).toBe(4);

      if (!requestPacket) {
        throw new Error("Expected a captured request packet");
      }

      const attributes = parseAttributes(requestPacket);
      expect(readStringAttribute(attributes, 1)).toBe("alice");
      expect(readIntegerAttribute(attributes, 40)).toBe(1);
      expect(readStringAttribute(attributes, 44)).toBe("session-001");
    } finally {
      await closeSocket(server);
    }
  });

  test("encodes Accounting-On and Accounting-Off status values without requiring session identifiers", async () => {
    const server = await bindServer();
    const receivedPackets: Buffer[] = [];

    server.on("message", (msg, rinfo) => {
      receivedPackets.push(Buffer.from(msg));
      const response = buildAccountingResponsePacket(msg, sharedSecret, 5);
      server.send(response, rinfo.port, rinfo.address);
    });

    try {
      const accountingOnResult = await radiusAccounting(
        "127.0.0.1",
        {
          statusType: "Accounting-On"
        },
        {
          secret: sharedSecret,
          port: getServerPort(server),
          timeoutMs: 500
        }
      );

      const accountingOffResult = await radiusAccounting(
        "127.0.0.1",
        {
          statusType: "Accounting-Off"
        },
        {
          secret: sharedSecret,
          port: getServerPort(server),
          timeoutMs: 500
        }
      );

      expect(accountingOnResult.ok).toBe(true);
      expect(accountingOffResult.ok).toBe(true);
      expect(receivedPackets).toHaveLength(2);

      const accountingOnPacket = receivedPackets[0];
      const accountingOffPacket = receivedPackets[1];

      if (!accountingOnPacket || !accountingOffPacket) {
        throw new Error("Expected captured request packets for Accounting-On and Accounting-Off");
      }

      const accountingOnAttributes = parseAttributes(accountingOnPacket);
      const accountingOffAttributes = parseAttributes(accountingOffPacket);

      expect(readIntegerAttribute(accountingOnAttributes, 40)).toBe(7);
      expect(readIntegerAttribute(accountingOffAttributes, 40)).toBe(8);

      expect(accountingOnAttributes.has(1)).toBe(false);
      expect(accountingOnAttributes.has(44)).toBe(false);
      expect(accountingOffAttributes.has(1)).toBe(false);
      expect(accountingOffAttributes.has(44)).toBe(false);
    } finally {
      await closeSocket(server);
    }
  });

  test("supports generic accounting send with additional custom attributes", async () => {
    const server = await bindServer();
    const receivedPackets: Buffer[] = [];

    server.on("message", (msg, rinfo) => {
      receivedPackets.push(Buffer.from(msg));
      const response = buildAccountingResponsePacket(msg, sharedSecret, 5);
      server.send(response, rinfo.port, rinfo.address);
    });

    try {
      const request: RadiusAccountingRequest = {
        username: "alice",
        sessionId: "session-002",
        statusType: "Interim-Update",
        sessionTime: 60,
        attributes: [
          { type: 87, value: "nas-port-7" },
          { type: 46, value: 60 }
        ]
      };

      const result = await radiusAccounting("127.0.0.1", request, {
        secret: sharedSecret,
        port: getServerPort(server),
        timeoutMs: 500
      });

      expect(result.ok).toBe(true);
      expect(receivedPackets).toHaveLength(1);

      const requestPacket = receivedPackets[0];
      if (!requestPacket) {
        throw new Error("Expected a captured request packet");
      }

      const attributes = parseAttributes(requestPacket);
      expect(readIntegerAttribute(attributes, 40)).toBe(3);
      expect(readStringAttribute(attributes, 87)).toBe("nas-port-7");
      expect(readIntegerAttribute(attributes, 46)).toBe(60);
    } finally {
      await closeSocket(server);
    }
  });

  test("returns authenticator_mismatch for tampered Accounting-Response packets", async () => {
    const server = await bindServer();

    server.on("message", (msg, rinfo) => {
      const response = buildAccountingResponsePacket(msg, sharedSecret, 5, true);
      server.send(response, rinfo.port, rinfo.address);
    });

    try {
      const result = await radiusAccounting(
        "127.0.0.1",
        {
          username: "alice",
          sessionId: "session-003",
          statusType: "Stop"
        },
        {
          secret: sharedSecret,
          port: getServerPort(server),
          timeoutMs: 500
        }
      );

      expect(result.ok).toBe(false);
      expect(result.error).toBe("authenticator_mismatch");
    } finally {
      await closeSocket(server);
    }
  });

  test("returns identifier_mismatch when Accounting-Response identifier differs from request", async () => {
    const server = await bindServer();

    server.on("message", (msg, rinfo) => {
      const mismatchedIdentifier = (msg.readUInt8(1) + 1) & 0xff;
      const response = buildAccountingResponsePacket(msg, sharedSecret, 5, false, mismatchedIdentifier);
      server.send(response, rinfo.port, rinfo.address);
    });

    try {
      const result = await radiusAccounting(
        "127.0.0.1",
        {
          username: "alice",
          sessionId: "session-identifier-mismatch",
          statusType: "Stop"
        },
        {
          secret: sharedSecret,
          port: getServerPort(server),
          timeoutMs: 500
        }
      );

      expect(result.ok).toBe(false);
      expect(result.error).toBe("identifier_mismatch");
    } finally {
      await closeSocket(server);
    }
  });

  test("rejects responses from unexpected source port by default", async () => {
    const server = await bindServer();
    const alternate = await bindServer();

    server.on("message", (msg, rinfo) => {
      const response = buildAccountingResponsePacket(msg, sharedSecret, 5);
      alternate.send(response, rinfo.port, rinfo.address);
    });

    try {
      const result = await radiusAccounting(
        "127.0.0.1",
        {
          username: "alice",
          sessionId: "session-source-validation",
          statusType: "Interim-Update"
        },
        {
          secret: sharedSecret,
          port: getServerPort(server),
          timeoutMs: 500
        }
      );

      expect(result.ok).toBe(false);
      expect(result.error).toBe("malformed_response");
    } finally {
      await closeSocket(server);
      await closeSocket(alternate);
    }
  });

  test("allows source mismatch when response source validation is disabled", async () => {
    const server = await bindServer();
    const alternate = await bindServer();

    server.on("message", (msg, rinfo) => {
      const response = buildAccountingResponsePacket(msg, sharedSecret, 5);
      alternate.send(response, rinfo.port, rinfo.address);
    });

    try {
      const result = await radiusAccounting(
        "127.0.0.1",
        {
          username: "alice",
          sessionId: "session-source-validation-disabled",
          statusType: "Interim-Update"
        },
        {
          secret: sharedSecret,
          port: getServerPort(server),
          timeoutMs: 500,
          validateResponseSource: false
        }
      );

      expect(result.ok).toBe(true);
      expect(result.error).toBeUndefined();
    } finally {
      await closeSocket(server);
      await closeSocket(alternate);
    }
  });

  test("returns unknown_code when server responds with non-Accounting-Response code", async () => {
    const server = await bindServer();

    server.on("message", (msg, rinfo) => {
      const response = buildAccountingResponsePacket(msg, sharedSecret, 2);
      server.send(response, rinfo.port, rinfo.address);
    });

    try {
      const result = await radiusAccounting(
        "127.0.0.1",
        {
          username: "alice",
          sessionId: "session-unknown-code",
          statusType: "Interim-Update"
        },
        {
          secret: sharedSecret,
          port: getServerPort(server),
          timeoutMs: 500
        }
      );

      expect(result.ok).toBe(false);
      expect(result.error).toBe("unknown_code");
    } finally {
      await closeSocket(server);
    }
  });

  test("returns malformed_response when Accounting-Response declared length is invalid", async () => {
    const server = await bindServer();

    server.on("message", (msg, rinfo) => {
      const response = buildAccountingResponsePacket(msg, sharedSecret, 5);
      response.writeUInt16BE(response.length - 1, 2);
      server.send(response, rinfo.port, rinfo.address);
    });

    try {
      const result = await radiusAccounting(
        "127.0.0.1",
        {
          username: "alice",
          sessionId: "session-malformed-length",
          statusType: "Start"
        },
        {
          secret: sharedSecret,
          port: getServerPort(server),
          timeoutMs: 500
        }
      );

      expect(result.ok).toBe(false);
      expect(result.error).toBe("malformed_response");
    } finally {
      await closeSocket(server);
    }
  });

  test("rejects Accounting-Response trailing bytes by default strict length policy", async () => {
    const server = await bindServer();

    server.on("message", (msg, rinfo) => {
      const response = appendTrailingBytes(buildAccountingResponsePacket(msg, sharedSecret, 5));
      server.send(response, rinfo.port, rinfo.address);
    });

    try {
      const result = await radiusAccounting(
        "127.0.0.1",
        {
          username: "alice",
          sessionId: "session-strict-length",
          statusType: "Start"
        },
        {
          secret: sharedSecret,
          port: getServerPort(server),
          timeoutMs: 500
        }
      );

      expect(result.ok).toBe(false);
      expect(result.error).toBe("malformed_response");
    } finally {
      await closeSocket(server);
    }
  });

  test("accepts Accounting-Response trailing bytes in allow_trailing_bytes mode", async () => {
    const server = await bindServer();

    server.on("message", (msg, rinfo) => {
      const response = appendTrailingBytes(buildAccountingResponsePacket(msg, sharedSecret, 5));
      server.send(response, rinfo.port, rinfo.address);
    });

    try {
      const result = await radiusAccounting(
        "127.0.0.1",
        {
          username: "alice",
          sessionId: "session-compat-length",
          statusType: "Stop"
        },
        {
          secret: sharedSecret,
          port: getServerPort(server),
          timeoutMs: 500,
          responseLengthValidationPolicy: "allow_trailing_bytes"
        }
      );

      expect(result.ok).toBe(true);
      expect(result.error).toBeUndefined();
    } finally {
      await closeSocket(server);
    }
  });

  test("returns timeout when accounting server does not respond", async () => {
    const server = await bindServer();

    server.on("message", () => {
      // Intentionally do not respond.
    });

    try {
      const result = await radiusAccounting(
        "127.0.0.1",
        {
          username: "alice",
          sessionId: "session-004",
          statusType: "Start"
        },
        {
          secret: sharedSecret,
          port: getServerPort(server),
          timeoutMs: 50
        }
      );

      expect(result.ok).toBe(false);
      expect(result.error).toBe("timeout");
    } finally {
      await closeSocket(server);
    }
  });
});
