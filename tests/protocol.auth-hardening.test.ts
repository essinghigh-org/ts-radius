import dgram, { type RemoteInfo, type Socket } from "node:dgram";
import crypto from "node:crypto";

import { describe, expect, test } from "bun:test";

import { radiusAuthenticate } from "../src/protocol";
import type { RadiusProtocolOptions } from "../src/types";

const TEST_HOST = "127.0.0.1";
const TEST_SECRET = "shared-secret";

function createClassAttribute(value: string): Buffer {
  const valueBuffer = Buffer.from(value, "utf8");
  return Buffer.concat([Buffer.from([25, valueBuffer.length + 2]), valueBuffer]);
}

function createMessageAuthenticatorAttribute(fillByte: number): Buffer {
  return Buffer.concat([Buffer.from([80, 18]), Buffer.alloc(16, fillByte)]);
}

function createMessageAuthenticatorAttributeWithLength(length: number, fillByte: number): Buffer {
  const valueLength = Math.max(length - 2, 0);
  return Buffer.concat([Buffer.from([80, length]), Buffer.alloc(valueLength, fillByte)]);
}

function buildAccessAcceptResponse(options: {
  request: Buffer;
  responseIdentifier?: number;
  attributes?: Buffer[];
}): Buffer {
  const request = options.request;
  const responseIdentifier = options.responseIdentifier ?? request.readUInt8(1);
  const requestAuthenticator = request.subarray(4, 20);
  const attributes = options.attributes ?? [createClassAttribute("engineering")];
  const attributeBuffer = Buffer.concat(attributes);

  const length = 20 + attributeBuffer.length;
  const packet = Buffer.alloc(length);

  packet.writeUInt8(2, 0); // Access-Accept
  packet.writeUInt8(responseIdentifier, 1);
  packet.writeUInt16BE(length, 2);
  attributeBuffer.copy(packet, 20);

  const lengthBuffer = Buffer.alloc(2);
  lengthBuffer.writeUInt16BE(length, 0);

  const responseAuthenticator = crypto
    .createHash("md5")
    .update(
      Buffer.concat([
        Buffer.from([2, responseIdentifier]),
        lengthBuffer,
        requestAuthenticator,
        attributeBuffer,
        Buffer.from(TEST_SECRET, "utf8"),
      ]),
    )
    .digest();

  responseAuthenticator.copy(packet, 4);
  return packet;
}

function writeResponseAuthenticator(packet: Buffer, requestAuthenticator: Buffer): void {
  const responseIdentifier = packet.readUInt8(1);
  const length = packet.readUInt16BE(2);
  const attributes = packet.subarray(20, length);

  const lengthBuffer = Buffer.alloc(2);
  lengthBuffer.writeUInt16BE(length, 0);

  const responseAuthenticator = crypto
    .createHash("md5")
    .update(
      Buffer.concat([
        Buffer.from([2, responseIdentifier]),
        lengthBuffer,
        requestAuthenticator,
        attributes,
        Buffer.from(TEST_SECRET, "utf8"),
      ]),
    )
    .digest();

  responseAuthenticator.copy(packet, 4);
}

function writeResponseMessageAuthenticator(packet: Buffer, requestAuthenticator: Buffer): void {
  let messageAuthenticatorOffset: number | null = null;
  let offset = 20;

  while (offset + 2 <= packet.length) {
    const type = packet.readUInt8(offset);
    const length = packet.readUInt8(offset + 1);

    if (length < 2 || offset + length > packet.length) {
      throw new Error("Invalid response attribute layout in test packet");
    }

    if (type === 80 && length === 18) {
      messageAuthenticatorOffset = offset;
      break;
    }

    offset += length;
  }

  if (messageAuthenticatorOffset === null) {
    throw new Error("Message-Authenticator attribute missing in test packet");
  }

  const verificationPacket = Buffer.from(packet);
  verificationPacket.fill(0, messageAuthenticatorOffset + 2, messageAuthenticatorOffset + 18);
  requestAuthenticator.copy(verificationPacket, 4, 0, 16);

  const messageAuthenticator = crypto
    .createHmac("md5", Buffer.from(TEST_SECRET, "utf8"))
    .update(verificationPacket)
    .digest();

  messageAuthenticator.copy(packet, messageAuthenticatorOffset + 2);
}

function buildAccessAcceptResponseWithValidMessageAuthenticator(options: {
  request: Buffer;
  responseIdentifier?: number;
}): Buffer {
  const request = options.request;
  const responseIdentifier = options.responseIdentifier ?? request.readUInt8(1);
  const requestAuthenticator = request.subarray(4, 20);

  const packet = buildAccessAcceptResponse({
    request,
    responseIdentifier,
    attributes: [createClassAttribute("engineering"), createMessageAuthenticatorAttribute(0x00)],
  });

  writeResponseMessageAuthenticator(packet, requestAuthenticator);
  writeResponseAuthenticator(packet, requestAuthenticator);

  return packet;
}

async function bindSocket(socket: Socket): Promise<number> {
  return await new Promise<number>((resolve, reject) => {
    const onError = (error: Error) => {
      socket.off("error", onError);
      reject(error);
    };

    socket.once("error", onError);
    socket.bind(0, TEST_HOST, () => {
      socket.off("error", onError);
      const address = socket.address();
      if (typeof address === "string") {
        reject(new Error("Expected UDP address information"));
        return;
      }
      resolve(address.port);
    });
  });
}

async function closeSocket(socket: Socket): Promise<void> {
  await new Promise<void>((resolve) => {
    socket.close(() => {
      resolve();
    });
  });
}

async function runAuthScenario(options: {
  sendFromAlternatePort?: boolean;
  protocolOptions?: Partial<RadiusProtocolOptions>;
  responseBuilder: (request: Buffer, requestInfo: RemoteInfo) => Buffer;
}): Promise<Awaited<ReturnType<typeof radiusAuthenticate>>> {
  const server = dgram.createSocket("udp4");
  const alternate = options.sendFromAlternatePort ? dgram.createSocket("udp4") : null;

  try {
    const serverPort = await bindSocket(server);
    if (alternate) {
      await bindSocket(alternate);
    }

    server.once("message", (request, requestInfo) => {
      const response = options.responseBuilder(request, requestInfo);
      const sender = alternate ?? server;
      sender.send(response, requestInfo.port, requestInfo.address);
    });

    const protocolOptions: RadiusProtocolOptions = {
      secret: TEST_SECRET,
      port: serverPort,
      timeoutMs: 500,
      ...options.protocolOptions,
    };

    return await radiusAuthenticate(TEST_HOST, "alice", "password", protocolOptions);
  } finally {
    await closeSocket(server);
    if (alternate) {
      await closeSocket(alternate);
    }
  }
}

describe("radiusAuthenticate response hardening", () => {
  test("accepts a valid Access-Accept response", async () => {
    const result = await runAuthScenario({
      responseBuilder: (request) => buildAccessAcceptResponse({ request }),
    });

    expect(result.ok).toBe(true);
    expect(result.class).toBe("engineering");
  });

  test("rejects responses with mismatched RADIUS header length", async () => {
    const result = await runAuthScenario({
      responseBuilder: (request) => {
        const response = buildAccessAcceptResponse({ request });
        response.writeUInt16BE(response.length - 1, 2);
        return response;
      },
    });

    expect(result.ok).toBe(false);
    expect(result.error).toBe("malformed_response");
  });

  test("rejects responses with mismatched identifier", async () => {
    const result = await runAuthScenario({
      responseBuilder: (request) => {
        const identifier = (request.readUInt8(1) + 1) & 0xff;
        return buildAccessAcceptResponse({ request, responseIdentifier: identifier });
      },
    });

    expect(result.ok).toBe(false);
    expect(result.error).toBe("malformed_response");
  });

  test("rejects responses from an unexpected source port by default", async () => {
    const result = await runAuthScenario({
      sendFromAlternatePort: true,
      responseBuilder: (request) => buildAccessAcceptResponse({ request }),
    });

    expect(result.ok).toBe(false);
    expect(result.error).toBe("malformed_response");
  });

  test("allows source mismatch when response source validation is disabled", async () => {
    const result = await runAuthScenario({
      sendFromAlternatePort: true,
      protocolOptions: { validateResponseSource: false },
      responseBuilder: (request) => buildAccessAcceptResponse({ request }),
    });

    expect(result.ok).toBe(true);
    expect(result.class).toBe("engineering");
  });

  test("rejects invalid Message-Authenticator in strict policy", async () => {
    const result = await runAuthScenario({
      protocolOptions: { responseMessageAuthenticatorPolicy: "strict" },
      responseBuilder: (request) =>
        buildAccessAcceptResponse({
          request,
          attributes: [createClassAttribute("engineering"), createMessageAuthenticatorAttribute(0x6a)],
        }),
    });

    expect(result.ok).toBe(false);
    expect(result.error).toBe("malformed_response");
  });

  test("rejects duplicate Message-Authenticator in strict policy", async () => {
    const result = await runAuthScenario({
      protocolOptions: { responseMessageAuthenticatorPolicy: "strict" },
      responseBuilder: (request) =>
        buildAccessAcceptResponse({
          request,
          attributes: [
            createClassAttribute("engineering"),
            createMessageAuthenticatorAttribute(0x00),
            createMessageAuthenticatorAttribute(0x11),
          ],
        }),
    });

    expect(result.ok).toBe(false);
    expect(result.error).toBe("malformed_response");
  });

  test("rejects invalid Message-Authenticator length in strict policy", async () => {
    const result = await runAuthScenario({
      protocolOptions: { responseMessageAuthenticatorPolicy: "strict" },
      responseBuilder: (request) =>
        buildAccessAcceptResponse({
          request,
          attributes: [
            createClassAttribute("engineering"),
            createMessageAuthenticatorAttributeWithLength(17, 0x5a),
          ],
        }),
    });

    expect(result.ok).toBe(false);
    expect(result.error).toBe("malformed_response");
  });

  test("rejects malformed/overrun attribute length interactions deterministically in strict policy", async () => {
    const malformedBeforeMessageAuthenticator = await runAuthScenario({
      protocolOptions: { responseMessageAuthenticatorPolicy: "strict" },
      responseBuilder: (request) =>
        buildAccessAcceptResponse({
          request,
          attributes: [Buffer.from([25, 0xff, 0x61]), createMessageAuthenticatorAttribute(0x00)],
        }),
    });

    expect(malformedBeforeMessageAuthenticator.ok).toBe(false);
    expect(malformedBeforeMessageAuthenticator.error).toBe("malformed_response");

    const malformedAfterMessageAuthenticator = await runAuthScenario({
      protocolOptions: { responseMessageAuthenticatorPolicy: "strict" },
      responseBuilder: (request) => {
        const requestAuthenticator = request.subarray(4, 20);
        const response = buildAccessAcceptResponse({
          request,
          attributes: [createMessageAuthenticatorAttribute(0x00), Buffer.from([25, 0xff, 0x61])],
        });

        writeResponseMessageAuthenticator(response, requestAuthenticator);
        writeResponseAuthenticator(response, requestAuthenticator);
        return response;
      },
    });

    expect(malformedAfterMessageAuthenticator.ok).toBe(false);
    expect(malformedAfterMessageAuthenticator.error).toBe("malformed_response");
  });

  test("rejects missing Message-Authenticator in strict policy", async () => {
    const result = await runAuthScenario({
      protocolOptions: { responseMessageAuthenticatorPolicy: "strict" },
      responseBuilder: (request) => buildAccessAcceptResponse({ request }),
    });

    expect(result.ok).toBe(false);
    expect(result.error).toBe("malformed_response");
  });

  test("accepts a valid response Message-Authenticator in strict policy", async () => {
    const result = await runAuthScenario({
      protocolOptions: { responseMessageAuthenticatorPolicy: "strict" },
      responseBuilder: (request) =>
        buildAccessAcceptResponseWithValidMessageAuthenticator({
          request,
        }),
    });

    expect(result.ok).toBe(true);
    expect(result.class).toBe("engineering");
  });

  test("rejects malformed declared packet length with strict length policy in strict Message-Authenticator mode", async () => {
    const declaredLengthTooSmall = await runAuthScenario({
      protocolOptions: {
        responseLengthValidationPolicy: "strict",
        responseMessageAuthenticatorPolicy: "strict",
      },
      responseBuilder: (request) => {
        const response = buildAccessAcceptResponseWithValidMessageAuthenticator({ request });
        response.writeUInt16BE(response.length - 1, 2);
        return response;
      },
    });

    expect(declaredLengthTooSmall.ok).toBe(false);
    expect(declaredLengthTooSmall.error).toBe("malformed_response");

    const declaredLengthTooLarge = await runAuthScenario({
      protocolOptions: {
        responseLengthValidationPolicy: "strict",
        responseMessageAuthenticatorPolicy: "strict",
      },
      responseBuilder: (request) => {
        const response = buildAccessAcceptResponseWithValidMessageAuthenticator({ request });
        response.writeUInt16BE(response.length + 1, 2);
        return response;
      },
    });

    expect(declaredLengthTooLarge.ok).toBe(false);
    expect(declaredLengthTooLarge.error).toBe("malformed_response");
  });

  test("keeps compatibility mode for invalid Message-Authenticator when present", async () => {
    const result = await runAuthScenario({
      protocolOptions: { responseMessageAuthenticatorPolicy: "compatibility" },
      responseBuilder: (request) =>
        buildAccessAcceptResponse({
          request,
          attributes: [createClassAttribute("engineering"), createMessageAuthenticatorAttribute(0x6a)],
        }),
    });

    expect(result.ok).toBe(true);
    expect(result.class).toBe("engineering");
  });
});
