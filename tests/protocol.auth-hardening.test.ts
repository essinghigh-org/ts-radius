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
