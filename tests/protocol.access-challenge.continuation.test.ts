import dgram, { type RemoteInfo, type Socket } from "node:dgram";
import crypto from "node:crypto";

import { describe, expect, test } from "bun:test";

import {
  radiusAuthenticateWithContinuation,
  radiusContinueAuthenticate,
} from "../src/protocol";
import type {
  RadiusChallengeContext,
  RadiusProtocolOptions,
} from "../src/types";

const TEST_HOST = "127.0.0.1";
const TEST_SECRET = "shared-secret";

interface ParsedAttribute {
  type: number;
  value: Buffer;
}

function encodeAttribute(type: number, value: Buffer): Buffer {
  return Buffer.concat([Buffer.from([type, value.length + 2]), value]);
}

function encodeStringAttribute(type: number, value: string): Buffer {
  return encodeAttribute(type, Buffer.from(value, "utf8"));
}

function parseAttributes(packet: Buffer): ParsedAttribute[] {
  const attributes: ParsedAttribute[] = [];
  let offset = 20;

  while (offset + 2 <= packet.length) {
    const type = packet.readUInt8(offset);
    const length = packet.readUInt8(offset + 1);

    if (length < 2 || offset + length > packet.length) {
      break;
    }

    attributes.push({
      type,
      value: packet.subarray(offset + 2, offset + length),
    });

    offset += length;
  }

  return attributes;
}

function buildAccessResponse(options: {
  code: number;
  request: Buffer;
  responseIdentifier?: number;
  attributes?: Buffer[];
}): Buffer {
  const request = options.request;
  const code = options.code;
  const responseIdentifier = options.responseIdentifier ?? request.readUInt8(1);
  const requestAuthenticator = request.subarray(4, 20);
  const attributes = options.attributes ?? [];
  const attributeBuffer = Buffer.concat(attributes);

  const length = 20 + attributeBuffer.length;
  const packet = Buffer.alloc(length);

  packet.writeUInt8(code, 0);
  packet.writeUInt8(responseIdentifier, 1);
  packet.writeUInt16BE(length, 2);
  attributeBuffer.copy(packet, 20);

  const lengthBuffer = Buffer.alloc(2);
  lengthBuffer.writeUInt16BE(length, 0);

  const responseAuthenticator = crypto
    .createHash("md5")
    .update(
      Buffer.concat([
        Buffer.from([code, responseIdentifier]),
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
    const onError = (error: Error): void => {
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

describe("Access-Challenge continuation API", () => {
  test("challenge -> continue -> accept preserves State/Proxy-State round-trip", async () => {
    const server = dgram.createSocket("udp4");
    const stateHex = "01020304aabbccdd";
    const proxyStateHex: [string, string] = ["112233", "deadbeef"];

    let requestCount = 0;
    const observedContinuationState: string[] = [];
    const observedContinuationProxyState: string[] = [];

    try {
      const serverPort = await bindSocket(server);

      server.on("message", (request: Buffer, requestInfo: RemoteInfo) => {
        requestCount += 1;

        if (requestCount === 1) {
          const response = buildAccessResponse({
            code: 11,
            request,
            attributes: [
              encodeStringAttribute(18, "Enter OTP"),
              encodeAttribute(24, Buffer.from(stateHex, "hex")),
              encodeAttribute(33, Buffer.from(proxyStateHex[0], "hex")),
              encodeAttribute(33, Buffer.from(proxyStateHex[1], "hex")),
            ],
          });
          server.send(response, requestInfo.port, requestInfo.address);
          return;
        }

        const attributes = parseAttributes(request);
        const stateAttribute = attributes.find((attribute) => attribute.type === 24);
        const proxyAttributes = attributes
          .filter((attribute) => attribute.type === 33)
          .map((attribute) => attribute.value.toString("hex"));

        if (stateAttribute) {
          observedContinuationState.push(stateAttribute.value.toString("hex"));
        }
        observedContinuationProxyState.push(...proxyAttributes);

        const response = buildAccessResponse({
          code: 2,
          request,
          attributes: [encodeStringAttribute(25, "engineering")],
        });
        server.send(response, requestInfo.port, requestInfo.address);
      });

      const protocolOptions: RadiusProtocolOptions = {
        secret: TEST_SECRET,
        port: serverPort,
        timeoutMs: 500,
      };

      const challengeResult = await radiusAuthenticateWithContinuation(
        TEST_HOST,
        "alice",
        "password",
        protocolOptions,
      );

      expect(challengeResult.ok).toBe(false);
      expect(challengeResult.error).toBe("access_challenge");
      expect(challengeResult.challenge).toEqual({
        username: "alice",
        round: 1,
        maxRounds: 3,
        state: stateHex,
        proxyState: proxyStateHex,
      });

      if (!challengeResult.challenge) {
        throw new Error("Expected challenge context");
      }

      const continueResult = await radiusContinueAuthenticate(
        TEST_HOST,
        "123456",
        challengeResult.challenge,
        protocolOptions,
      );

      expect(continueResult.ok).toBe(true);
      expect(continueResult.error).toBeUndefined();
      expect(continueResult.class).toBe("engineering");

      expect(observedContinuationState).toEqual([stateHex]);
      expect(observedContinuationProxyState).toEqual(proxyStateHex);
    } finally {
      await closeSocket(server);
    }
  });

  test("challenge -> continue -> reject returns access_reject", async () => {
    const server = dgram.createSocket("udp4");
    let requestCount = 0;

    try {
      const serverPort = await bindSocket(server);

      server.on("message", (request: Buffer, requestInfo: RemoteInfo) => {
        requestCount += 1;

        if (requestCount === 1) {
          const response = buildAccessResponse({
            code: 11,
            request,
            attributes: [
              encodeAttribute(24, Buffer.from("cafebabe", "hex")),
            ],
          });
          server.send(response, requestInfo.port, requestInfo.address);
          return;
        }

        const rejectResponse = buildAccessResponse({
          code: 3,
          request,
        });
        server.send(rejectResponse, requestInfo.port, requestInfo.address);
      });

      const protocolOptions: RadiusProtocolOptions = {
        secret: TEST_SECRET,
        port: serverPort,
        timeoutMs: 500,
      };

      const firstStep = await radiusAuthenticateWithContinuation(
        TEST_HOST,
        "alice",
        "password",
        protocolOptions,
      );

      if (!firstStep.challenge) {
        throw new Error("Expected challenge context");
      }

      const secondStep = await radiusContinueAuthenticate(
        TEST_HOST,
        "bad-otp",
        firstStep.challenge,
        protocolOptions,
      );

      expect(secondStep.ok).toBe(false);
      expect(secondStep.error).toBe("access_reject");
      expect(secondStep.challenge).toBeUndefined();
    } finally {
      await closeSocket(server);
    }
  });

  test("returns malformed_challenge_context when challenge response does not include State", async () => {
    const server = dgram.createSocket("udp4");

    try {
      const serverPort = await bindSocket(server);

      server.once("message", (request: Buffer, requestInfo: RemoteInfo) => {
        const response = buildAccessResponse({
          code: 11,
          request,
          attributes: [encodeStringAttribute(18, "Missing state")],
        });
        server.send(response, requestInfo.port, requestInfo.address);
      });

      const protocolOptions: RadiusProtocolOptions = {
        secret: TEST_SECRET,
        port: serverPort,
        timeoutMs: 500,
      };

      const result = await radiusAuthenticateWithContinuation(
        TEST_HOST,
        "alice",
        "password",
        protocolOptions,
      );

      expect(result.ok).toBe(false);
      expect(result.error).toBe("malformed_challenge_context");
      expect(result.challenge).toBeUndefined();
    } finally {
      await closeSocket(server);
    }
  });

  test("rejects malformed continuation context input", async () => {
    const malformedContext: RadiusChallengeContext = {
      username: "alice",
      round: 1,
      maxRounds: 3,
      state: "zz",
      proxyState: [],
    };

    const result = await radiusContinueAuthenticate(
      TEST_HOST,
      "123456",
      malformedContext,
      {
        secret: TEST_SECRET,
        port: 65000,
        timeoutMs: 250,
      },
    );

    expect(result.ok).toBe(false);
    expect(result.error).toBe("malformed_challenge_context");
  });

  test("enforces max challenge rounds safeguard", async () => {
    const server = dgram.createSocket("udp4");
    let requestCount = 0;

    try {
      const serverPort = await bindSocket(server);

      server.on("message", (request: Buffer, requestInfo: RemoteInfo) => {
        requestCount += 1;

        const response = buildAccessResponse({
          code: 11,
          request,
          attributes: [
            encodeAttribute(
              24,
              Buffer.from(requestCount === 1 ? "11111111" : "22222222", "hex"),
            ),
          ],
        });
        server.send(response, requestInfo.port, requestInfo.address);
      });

      const protocolOptions: RadiusProtocolOptions = {
        secret: TEST_SECRET,
        port: serverPort,
        timeoutMs: 500,
      };

      const firstStep = await radiusAuthenticateWithContinuation(
        TEST_HOST,
        "alice",
        "password",
        protocolOptions,
        undefined,
        { maxChallengeRounds: 1 },
      );

      if (!firstStep.challenge) {
        throw new Error("Expected challenge context");
      }

      const secondStep = await radiusContinueAuthenticate(
        TEST_HOST,
        "123456",
        firstStep.challenge,
        protocolOptions,
      );

      expect(secondStep.ok).toBe(false);
      expect(secondStep.error).toBe("challenge_round_limit_exceeded");
      expect(secondStep.challenge).toBeUndefined();
    } finally {
      await closeSocket(server);
    }
  });
});