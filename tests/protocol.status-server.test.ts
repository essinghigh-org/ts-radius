import crypto from "crypto";
import dgram, { type RemoteInfo, type Socket } from "dgram";

import { describe, expect, test } from "bun:test";

import { radiusStatusServerProbe } from "../src/protocol";
import type { RadiusProtocolOptions } from "../src/types";

const TEST_HOST = "127.0.0.1";
const TEST_SECRET = "shared-secret";

function buildStatusServerResponsePacket(options: {
  requestPacket: Buffer;
  responseCode?: number;
  responseIdentifier?: number;
  attributes?: Buffer[];
  tamperAuthenticator?: boolean;
}): Buffer {
  const {
    requestPacket,
    responseCode = 5,
    responseIdentifier = requestPacket.readUInt8(1),
    attributes = [],
    tamperAuthenticator = false,
  } = options;

  const attributeBuffer = Buffer.concat(attributes);

  const response = Buffer.alloc(20 + attributeBuffer.length);
  response.writeUInt8(responseCode, 0);
  response.writeUInt8(responseIdentifier, 1);
  response.writeUInt16BE(response.length, 2);
  attributeBuffer.copy(response, 20);

  const hashInput = Buffer.concat([
    Buffer.from([responseCode, responseIdentifier]),
    response.subarray(2, 4),
    requestPacket.subarray(4, 20),
    attributeBuffer,
    Buffer.from(TEST_SECRET, "utf8")
  ]);

  const authenticator = crypto.createHash("md5").update(hashInput).digest();
  authenticator.copy(response, 4);

  if (tamperAuthenticator) {
    response.writeUInt8(response.readUInt8(4) ^ 0xff, 4);
  }

  return response;
}

function appendTrailingBytes(packet: Buffer): Buffer {
  return Buffer.concat([packet, Buffer.from([0xde, 0xad, 0xbe, 0xef])]);
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

async function runStatusProbeScenario(options: {
  sendFromAlternatePort?: boolean;
  protocolOptions?: Partial<RadiusProtocolOptions>;
  responseBuilder?: (requestPacket: Buffer, requestInfo: RemoteInfo) => Buffer;
}): Promise<Awaited<ReturnType<typeof radiusStatusServerProbe>>> {
  const server = dgram.createSocket("udp4");
  const alternate = options.sendFromAlternatePort ? dgram.createSocket("udp4") : null;

  try {
    const serverPort = await bindSocket(server);
    if (alternate) {
      await bindSocket(alternate);
    }

    server.once("message", (requestPacket, requestInfo) => {
      if (!options.responseBuilder) {
        return;
      }

      const response = options.responseBuilder(requestPacket, requestInfo);
      const sender = alternate ?? server;
      sender.send(response, requestInfo.port, requestInfo.address);
    });

    const protocolOptions: RadiusProtocolOptions = {
      secret: TEST_SECRET,
      port: serverPort,
      timeoutMs: 500,
      ...options.protocolOptions,
    };

    return await radiusStatusServerProbe(TEST_HOST, protocolOptions);
  } finally {
    await closeSocket(server);
    if (alternate) {
      await closeSocket(alternate);
    }
  }
}

describe("radiusStatusServerProbe hardening", () => {
  test("returns timeout when status-server does not respond", async () => {
    const result = await runStatusProbeScenario({
      protocolOptions: { timeoutMs: 50 },
    });

    expect(result.ok).toBe(false);
    expect(result.error).toBe("timeout");
  });

  test("returns malformed_response when Status-Server response declared length exceeds datagram length", async () => {
    const result = await runStatusProbeScenario({
      responseBuilder: (requestPacket) => {
        const response = buildStatusServerResponsePacket({ requestPacket });
        response.writeUInt16BE(response.length + 1, 2);
        return response;
      },
    });

    expect(result.ok).toBe(false);
    expect(result.error).toBe("malformed_response");
  });

  test("rejects responses from unexpected source port by default", async () => {
    const result = await runStatusProbeScenario({
      sendFromAlternatePort: true,
      responseBuilder: (requestPacket) => buildStatusServerResponsePacket({ requestPacket }),
    });

    expect(result.ok).toBe(false);
    expect(result.error).toBe("malformed_response");
  });

  test("allows source mismatch when response source validation is disabled", async () => {
    const result = await runStatusProbeScenario({
      sendFromAlternatePort: true,
      protocolOptions: { validateResponseSource: false },
      responseBuilder: (requestPacket) => buildStatusServerResponsePacket({ requestPacket }),
    });

    expect(result.ok).toBe(true);
    expect(result.error).toBeUndefined();
  });

  test("returns authenticator_mismatch for tampered Status-Server response authenticator", async () => {
    const result = await runStatusProbeScenario({
      responseBuilder: (requestPacket) =>
        buildStatusServerResponsePacket({
          requestPacket,
          tamperAuthenticator: true,
        }),
    });

    expect(result.ok).toBe(false);
    expect(result.error).toBe("authenticator_mismatch");
  });

  test("returns identifier_mismatch when Status-Server response identifier differs from request", async () => {
    const result = await runStatusProbeScenario({
      responseBuilder: (requestPacket) =>
        buildStatusServerResponsePacket({
          requestPacket,
          responseIdentifier: (requestPacket.readUInt8(1) + 1) & 0xff,
        }),
    });

    expect(result.ok).toBe(false);
    expect(result.error).toBe("identifier_mismatch");
  });

  test("returns unknown_code for unexpected Status-Server response code", async () => {
    const result = await runStatusProbeScenario({
      responseBuilder: (requestPacket) =>
        buildStatusServerResponsePacket({
          requestPacket,
          responseCode: 60,
        }),
    });

    expect(result.ok).toBe(false);
    expect(result.error).toBe("unknown_code");
  });

  test("rejects trailing bytes by default strict length policy", async () => {
    const result = await runStatusProbeScenario({
      responseBuilder: (requestPacket) =>
        appendTrailingBytes(buildStatusServerResponsePacket({ requestPacket })),
    });

    expect(result.ok).toBe(false);
    expect(result.error).toBe("malformed_response");
  });

  test("accepts trailing bytes in allow_trailing_bytes mode", async () => {
    const result = await runStatusProbeScenario({
      protocolOptions: {
        responseLengthValidationPolicy: "allow_trailing_bytes",
      },
      responseBuilder: (requestPacket) =>
        appendTrailingBytes(buildStatusServerResponsePacket({ requestPacket })),
    });

    expect(result.ok).toBe(true);
    expect(result.error).toBeUndefined();
  });
});
