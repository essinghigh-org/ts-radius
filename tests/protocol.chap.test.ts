import crypto from "node:crypto";
import dgram from "node:dgram";

import { describe, expect, test } from "bun:test";

import { radiusAuthenticate } from "../src/protocol";

const TEST_HOST = "127.0.0.1";
const TEST_SECRET = "chap-shared-secret";

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

function encodeStringAttribute(type: number, value: string): Buffer {
  const valueBuffer = Buffer.from(value, "utf8");
  return Buffer.concat([Buffer.from([type, valueBuffer.length + 2]), valueBuffer]);
}

function buildAccessAcceptResponsePacket(requestPacket: Buffer, secret: string): Buffer {
  const identifier = requestPacket.readUInt8(1);
  const requestAuthenticator = requestPacket.subarray(4, 20);
  const attributeBuffer = encodeStringAttribute(25, "engineering");

  const response = Buffer.alloc(20 + attributeBuffer.length);
  response.writeUInt8(2, 0);
  response.writeUInt8(identifier, 1);
  response.writeUInt16BE(response.length, 2);
  attributeBuffer.copy(response, 20);

  const hashInput = Buffer.concat([
    response.subarray(0, 4),
    requestAuthenticator,
    attributeBuffer,
    Buffer.from(secret, "utf8")
  ]);

  const authenticator = crypto.createHash("md5").update(hashInput).digest();
  authenticator.copy(response, 4);

  return response;
}

async function bindServer(): Promise<dgram.Socket> {
  const server = dgram.createSocket("udp4");

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.bind(0, TEST_HOST, () => {
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

async function closeServer(server: dgram.Socket): Promise<void> {
  await new Promise<void>((resolve) => {
    server.close(() => {
      resolve();
    });
  });
}

describe("radiusAuthenticate CHAP mode", () => {
  test("keeps PAP as the default auth method", async () => {
    const server = await bindServer();
    let requestPacket: Buffer | undefined;

    server.on("message", (message, remoteInfo) => {
      requestPacket = Buffer.from(message);
      const response = buildAccessAcceptResponsePacket(message, TEST_SECRET);
      server.send(response, remoteInfo.port, remoteInfo.address);
    });

    try {
      const result = await radiusAuthenticate(
        TEST_HOST,
        "alice",
        "password",
        {
          secret: TEST_SECRET,
          port: getServerPort(server),
          timeoutMs: 500,
        },
      );

      expect(result.ok).toBe(true);

      if (!requestPacket) {
        throw new Error("Expected an Access-Request packet");
      }

      const attributes = parseAttributes(requestPacket);
      expect(attributes.has(2)).toBe(true);
      expect(attributes.has(3)).toBe(false);
      expect(attributes.has(60)).toBe(false);
    } finally {
      await closeServer(server);
    }
  });

  test("encodes CHAP-Password and CHAP-Challenge while omitting User-Password when CHAP mode is selected", async () => {
    const server = await bindServer();
    let requestPacket: Buffer | undefined;

    const chapId = 0x42;
    const chapChallenge = Buffer.from("00112233445566778899aabbccddeeff", "hex");
    const password = "p@ssw0rd!";

    server.on("message", (message, remoteInfo) => {
      requestPacket = Buffer.from(message);
      const response = buildAccessAcceptResponsePacket(message, TEST_SECRET);
      server.send(response, remoteInfo.port, remoteInfo.address);
    });

    try {
      const result = await radiusAuthenticate(
        TEST_HOST,
        "alice",
        password,
        {
          secret: TEST_SECRET,
          port: getServerPort(server),
          timeoutMs: 500,
          authMethod: "chap",
          chapId,
          chapChallenge,
        } as unknown as Parameters<typeof radiusAuthenticate>[3],
      );

      expect(result.ok).toBe(true);

      if (!requestPacket) {
        throw new Error("Expected an Access-Request packet");
      }

      const attributes = parseAttributes(requestPacket);
      expect(attributes.has(2)).toBe(false);

      const chapPassword = attributes.get(3)?.[0];
      const challengeAttribute = attributes.get(60)?.[0];

      if (!chapPassword) {
        throw new Error("Expected CHAP-Password attribute (type 3)");
      }

      if (!challengeAttribute) {
        throw new Error("Expected CHAP-Challenge attribute (type 60)");
      }

      expect(chapPassword.length).toBe(17);
      expect(chapPassword.readUInt8(0)).toBe(chapId);
      expect(challengeAttribute.equals(chapChallenge)).toBe(true);

      const expectedDigest = crypto
        .createHash("md5")
        .update(Buffer.concat([Buffer.from([chapId]), Buffer.from(password, "utf8"), chapChallenge]))
        .digest();

      expect(chapPassword.subarray(1).equals(expectedDigest)).toBe(true);
    } finally {
      await closeServer(server);
    }
  });

  test("uses generated CHAP id/challenge consistently when deterministic overrides are not provided", async () => {
    const server = await bindServer();
    let requestPacket: Buffer | undefined;

    const password = "dynamic-secret";

    server.on("message", (message, remoteInfo) => {
      requestPacket = Buffer.from(message);
      const response = buildAccessAcceptResponsePacket(message, TEST_SECRET);
      server.send(response, remoteInfo.port, remoteInfo.address);
    });

    try {
      const result = await radiusAuthenticate(
        TEST_HOST,
        "alice",
        password,
        {
          secret: TEST_SECRET,
          port: getServerPort(server),
          timeoutMs: 500,
          authMethod: "chap",
        } as unknown as Parameters<typeof radiusAuthenticate>[3],
      );

      expect(result.ok).toBe(true);

      if (!requestPacket) {
        throw new Error("Expected an Access-Request packet");
      }

      const attributes = parseAttributes(requestPacket);
      expect(attributes.has(2)).toBe(false);

      const chapPassword = attributes.get(3)?.[0];
      const challengeAttribute = attributes.get(60)?.[0];

      if (!chapPassword) {
        throw new Error("Expected CHAP-Password attribute (type 3)");
      }

      if (!challengeAttribute) {
        throw new Error("Expected CHAP-Challenge attribute (type 60)");
      }

      expect(chapPassword.length).toBe(17);
      expect(challengeAttribute.length).toBe(16);

      const generatedChapId = chapPassword.readUInt8(0);
      const expectedDigest = crypto
        .createHash("md5")
        .update(Buffer.concat([Buffer.from([generatedChapId]), Buffer.from(password, "utf8"), challengeAttribute]))
        .digest();

      expect(chapPassword.subarray(1).equals(expectedDigest)).toBe(true);
    } finally {
      await closeServer(server);
    }
  });
});