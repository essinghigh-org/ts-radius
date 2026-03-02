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
  responseIdentifier?: number,
  attributes: Buffer[] = []
): Buffer {
  const identifier = responseIdentifier ?? requestPacket.readUInt8(1);
  const attributeBuffer = Buffer.concat(attributes);

  const response = Buffer.alloc(20 + attributeBuffer.length);
  response.writeUInt8(responseCode, 0);
  response.writeUInt8(identifier, 1);
  response.writeUInt16BE(response.length, 2);
  attributeBuffer.copy(response, 20);

  const hashInput = Buffer.concat([
    response.subarray(0, 4),
    requestPacket.subarray(4, 20),
    attributeBuffer,
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

  async function captureAccountingRequestAttributes(request: RadiusAccountingRequest): Promise<Map<number, Buffer[]>> {
    const server = await bindServer();
    let capturedPacket: Buffer | undefined;

    server.on("message", (msg, rinfo) => {
      capturedPacket = Buffer.from(msg);
      const response = buildAccountingResponsePacket(msg, sharedSecret, 5);
      server.send(response, rinfo.port, rinfo.address);
    });

    try {
      const result = await radiusAccounting("127.0.0.1", request, {
        secret: sharedSecret,
        port: getServerPort(server),
        timeoutMs: 500
      });

      expect(result.ok).toBe(true);

      if (!capturedPacket) {
        throw new Error("Expected a captured request packet");
      }

      return parseAttributes(capturedPacket);
    } finally {
      await closeSocket(server);
    }
  }

  async function expectAccountingRequestRejection(
    request: RadiusAccountingRequest,
    expectedMessage: string
  ): Promise<void> {
    try {
      await radiusAccounting("127.0.0.1", request, {
        secret: sharedSecret,
        timeoutMs: 10
      });

      throw new Error("Expected radiusAccounting to reject");
    } catch (error: unknown) {
      if (!(error instanceof Error)) {
        throw error;
      }

      expect(error.message).toBe(expectedMessage);
    }
  }

  const forbiddenAccountingCustomAttributesError =
    "[radius] invalid_request: accounting request customAttributes cannot include User-Password (2), CHAP-Password (3), Reply-Message (18), or State (24)";
  const duplicateCoreAccountingCustomAttributesError =
    "[radius] invalid_request: accounting request customAttributes cannot include Acct-Status-Type (40) or Acct-Session-Id (44) because core accounting fields are set exactly once";

  describe("Accounting-Request customAttributes RFC2866 validation", () => {
    const forbiddenAttributeCases: Array<{ type: number; name: string }> = [
      { type: 2, name: "User-Password" },
      { type: 3, name: "CHAP-Password" },
      { type: 18, name: "Reply-Message" },
      { type: 24, name: "State" }
    ];

    for (const testCase of forbiddenAttributeCases) {
      test(`rejects forbidden ${testCase.name} (${String(testCase.type)}) in accounting request customAttributes`, async () => {
        await expectAccountingRequestRejection(
          {
            username: "alice",
            sessionId: "session-forbidden-attribute",
            statusType: "Start",
            attributes: [{ type: testCase.type, value: "forbidden" }]
          },
          forbiddenAccountingCustomAttributesError
        );
      });
    }

    test("rejects Acct-Status-Type (40) in accounting request customAttributes", async () => {
      await expectAccountingRequestRejection(
        {
          username: "alice",
          sessionId: "session-duplicate-status",
          statusType: "Start",
          attributes: [{ type: 40, value: 1 }]
        },
        duplicateCoreAccountingCustomAttributesError
      );
    });

    test("rejects Acct-Session-Id (44) in accounting request customAttributes", async () => {
      await expectAccountingRequestRejection(
        {
          username: "alice",
          sessionId: "session-duplicate-session",
          statusType: "Start",
          attributes: [{ type: 44, value: "other-session" }]
        },
        duplicateCoreAccountingCustomAttributesError
      );
    });
  });

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

      const nasIpAddress = attributes.get(4)?.[0];
      expect(nasIpAddress?.equals(Buffer.from([127, 0, 0, 1]))).toBe(true);
    } finally {
      await closeSocket(server);
    }
  });

  test("encodes Accounting-On and Accounting-Off status values with generated Acct-Session-Id and NAS-IP-Address", async () => {
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
      expect(readStringAttribute(accountingOnAttributes, 44).length).toBeGreaterThan(0);
      expect(accountingOffAttributes.has(1)).toBe(false);
      expect(readStringAttribute(accountingOffAttributes, 44).length).toBeGreaterThan(0);

      const accountingOnNasIp = accountingOnAttributes.get(4)?.[0];
      const accountingOffNasIp = accountingOffAttributes.get(4)?.[0];

      expect(accountingOnNasIp?.equals(Buffer.from([127, 0, 0, 1]))).toBe(true);
      expect(accountingOffNasIp?.equals(Buffer.from([127, 0, 0, 1]))).toBe(true);
    } finally {
      await closeSocket(server);
    }
  });

  test("uses caller-provided NAS-Identifier and skips NAS-IP-Address fallback", async () => {
    const attributes = await captureAccountingRequestAttributes({
      username: "alice",
      sessionId: "session-nas-identifier",
      statusType: "Start",
      attributes: [{ type: 32, value: "edge-nas-01" }]
    } as RadiusAccountingRequest);

    expect(readStringAttribute(attributes, 32)).toBe("edge-nas-01");
    expect(attributes.has(4)).toBe(false);
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

  describe("64-bit accounting octet counter ergonomics", () => {
    const uint64EncodingCases: Array<{ label: string; value: bigint; expectedLow: number; expectedHigh: number }> = [
      {
        label: "zero",
        value: 0n,
        expectedLow: 0,
        expectedHigh: 0
      },
      {
        label: "2^32-1",
        value: 0xffff_ffffn,
        expectedLow: 0xffff_ffff,
        expectedHigh: 0
      },
      {
        label: "2^32",
        value: 0x1_0000_0000n,
        expectedLow: 0,
        expectedHigh: 1
      },
      {
        label: "large value",
        value: 0x1234_5678_9abc_def0n,
        expectedLow: 0x9abc_def0,
        expectedHigh: 0x1234_5678
      }
    ];

    for (const testCase of uint64EncodingCases) {
      test(`encodes input/output 64-bit octets for ${testCase.label}`, async () => {
        const attributes = await captureAccountingRequestAttributes({
          username: "alice",
          sessionId: `session-64-${testCase.label}`,
          statusType: "Interim-Update",
          inputOctets64: testCase.value,
          outputOctets64: testCase.value
        } as RadiusAccountingRequest);

        expect(readIntegerAttribute(attributes, 42)).toBe(testCase.expectedLow);
        expect(readIntegerAttribute(attributes, 52)).toBe(testCase.expectedHigh);
        expect(readIntegerAttribute(attributes, 43)).toBe(testCase.expectedLow);
        expect(readIntegerAttribute(attributes, 53)).toBe(testCase.expectedHigh);
      });
    }

    test("prefers 64-bit octet counters when both legacy and 64-bit fields are provided", async () => {
      const attributes = await captureAccountingRequestAttributes({
        username: "alice",
        sessionId: "session-64-precedence",
        statusType: "Interim-Update",
        inputOctets: 777,
        outputOctets: 888,
        inputOctets64: 0x1_0000_0002n,
        outputOctets64: 0x2_0000_0003n
      } as RadiusAccountingRequest);

      expect(readIntegerAttribute(attributes, 42)).toBe(2);
      expect(readIntegerAttribute(attributes, 52)).toBe(1);
      expect(readIntegerAttribute(attributes, 43)).toBe(3);
      expect(readIntegerAttribute(attributes, 53)).toBe(2);
    });

    test("rejects negative 64-bit octet counters", async () => {
      await expectAccountingRequestRejection(
        {
          username: "alice",
          sessionId: "session-64-negative",
          statusType: "Interim-Update",
          inputOctets64: -1n
        } as RadiusAccountingRequest,
        "[radius] accounting request.inputOctets64 must be uint64"
      );
    });

    test("rejects 64-bit octet counters above uint64", async () => {
      await expectAccountingRequestRejection(
        {
          username: "alice",
          sessionId: "session-64-overflow",
          statusType: "Interim-Update",
          outputOctets64: 0x1_0000_0000_0000_0000n
        } as RadiusAccountingRequest,
        "[radius] accounting request.outputOctets64 must be uint64"
      );
    });

    test("rejects conflicting custom octet/gigawords attributes when inputOctets64 is provided", async () => {
      await expectAccountingRequestRejection(
        {
          username: "alice",
          sessionId: "session-64-conflict-input",
          statusType: "Interim-Update",
          inputOctets64: 9n,
          attributes: [{ type: 52, value: 1 }]
        } as RadiusAccountingRequest,
        "[radius] accounting request.attributes cannot include Acct-Input-Octets (42) or Acct-Input-Gigawords (52) when inputOctets64 is provided"
      );
    });

    test("rejects conflicting custom octet/gigawords attributes when outputOctets64 is provided", async () => {
      await expectAccountingRequestRejection(
        {
          username: "alice",
          sessionId: "session-64-conflict-output",
          statusType: "Interim-Update",
          outputOctets64: 9n,
          attributes: [{ type: 53, value: 1 }]
        } as RadiusAccountingRequest,
        "[radius] accounting request.attributes cannot include Acct-Output-Octets (43) or Acct-Output-Gigawords (53) when outputOctets64 is provided"
      );
    });
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

  test("reuses provided accounting request identity and keeps packet/authenticator deterministic across repeated sends", async () => {
    const server = await bindServer();
    const receivedPackets: Buffer[] = [];
    const sourcePorts: number[] = [];
    const requestIdentity: { identifier: number; sourcePort?: number } = { identifier: 77 };

    server.on("message", (msg, rinfo) => {
      receivedPackets.push(Buffer.from(msg));
      sourcePorts.push(rinfo.port);
      const response = buildAccountingResponsePacket(msg, sharedSecret, 5);
      server.send(response, rinfo.port, rinfo.address);
    });

    try {
      const request: RadiusAccountingRequest = {
        username: "alice",
        sessionId: "session-retry-identity",
        statusType: "Interim-Update"
      };

      const options = {
        secret: sharedSecret,
        port: getServerPort(server),
        timeoutMs: 500,
        accountingRequestIdentity: requestIdentity
      };

      const firstResult = await radiusAccounting("127.0.0.1", request, options);
      const secondResult = await radiusAccounting("127.0.0.1", request, options);

      expect(firstResult.ok).toBe(true);
      expect(secondResult.ok).toBe(true);
      expect(receivedPackets).toHaveLength(2);

      const firstPacket = receivedPackets[0];
      const secondPacket = receivedPackets[1];
      if (!firstPacket || !secondPacket) {
        throw new Error("Expected captured request packets for repeated identity validation");
      }

      expect(firstPacket.readUInt8(1)).toBe(requestIdentity.identifier);
      expect(secondPacket.readUInt8(1)).toBe(requestIdentity.identifier);
      expect(secondPacket.equals(firstPacket)).toBe(true);

      expect(sourcePorts).toHaveLength(2);
      expect(sourcePorts[1]).toBe(sourcePorts[0]);
      expect(requestIdentity.sourcePort).toBe(sourcePorts[0]);
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

  test("returns malformed_response when Accounting-Response has attribute length below minimum", async () => {
    const server = await bindServer();

    server.on("message", (msg, rinfo) => {
      const response = buildAccountingResponsePacket(
        msg,
        sharedSecret,
        5,
        false,
        undefined,
        [Buffer.from([18, 1])]
      );
      server.send(response, rinfo.port, rinfo.address);
    });

    try {
      const result = await radiusAccounting(
        "127.0.0.1",
        {
          username: "alice",
          sessionId: "session-malformed-attr-length",
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

  test("returns malformed_response when Accounting-Response attribute overruns packet", async () => {
    const server = await bindServer();

    server.on("message", (msg, rinfo) => {
      const response = buildAccountingResponsePacket(
        msg,
        sharedSecret,
        5,
        false,
        undefined,
        [Buffer.from([18, 10, 0x6f])]
      );
      server.send(response, rinfo.port, rinfo.address);
    });

    try {
      const result = await radiusAccounting(
        "127.0.0.1",
        {
          username: "alice",
          sessionId: "session-malformed-attr-overrun",
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

  test("accepts Accounting-Response trailing bytes by default for RFC padding compatibility", async () => {
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
          sessionId: "session-default-compat-length",
          statusType: "Start"
        },
        {
          secret: sharedSecret,
          port: getServerPort(server),
          timeoutMs: 500
        }
      );

      expect(result.ok).toBe(true);
      expect(result.error).toBeUndefined();
    } finally {
      await closeSocket(server);
    }
  });

  test("rejects Accounting-Response trailing bytes when strict length policy is explicitly requested", async () => {
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
          timeoutMs: 500,
          responseLengthValidationPolicy: "strict"
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

  test("rejects Accounting-Request packets above RFC maximum length of 4095 bytes", async () => {
    const oversizedAttributes = Array.from({ length: 16 }, (_, index) => ({
      type: ((index + 59) % 255) + 1,
      value: "x".repeat(253)
    }));

    await expectAccountingRequestRejection(
      {
        username: "alice",
        sessionId: "session-oversized-accounting",
        statusType: "Start",
        attributes: oversizedAttributes
      },
      "[radius] accounting packet exceeds RFC maximum length (4095 bytes)"
    );
  });
});
