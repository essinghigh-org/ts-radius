import crypto from "node:crypto";
import dgram from "node:dgram";

import { describe, expect, test } from "bun:test";

import { RadiusClient } from "../src/client";
import type { RadiusConfig } from "../src/types";

const COA_ACK_CODE = 44;

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

function readStringAttribute(attributes: Map<number, Buffer[]>, type: number): string | undefined {
  const value = attributes.get(type)?.[0];
  if (!value) {
    return undefined;
  }

  return value.toString("utf8");
}

function buildDynamicAuthorizationResponse(
  requestPacket: Buffer,
  secret: string,
  responseCode: number,
): Buffer {
  const identifier = requestPacket.readUInt8(1);
  const response = Buffer.alloc(20);

  response.writeUInt8(responseCode, 0);
  response.writeUInt8(identifier, 1);
  response.writeUInt16BE(response.length, 2);

  const hashInput = Buffer.concat([
    Buffer.from([response.readUInt8(0)]),
    Buffer.from([response.readUInt8(1)]),
    response.subarray(2, 4),
    requestPacket.subarray(4, 20),
    response.subarray(20),
    Buffer.from(secret, "utf8"),
  ]);

  crypto.createHash("md5").update(hashInput).digest().copy(response, 4);
  return response;
}

function computeAccountingStyleRequestAuthenticator(requestPacket: Buffer, secret: string): Buffer {
  const packetForDigest = Buffer.from(requestPacket);
  packetForDigest.fill(0, 4, 20);

  return crypto
    .createHash("md5")
    .update(Buffer.concat([packetForDigest, Buffer.from(secret, "utf8")]))
    .digest();
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

function closeSocket(server: dgram.Socket): Promise<void> {
  return new Promise((resolve) => {
    server.close(() => {
      resolve();
    });
  });
}

async function waitForHealthOperationIdle(client: RadiusClient, timeoutMs = 1000): Promise<void> {
  const internals = client as unknown as { inProgress: boolean };
  const deadline = Date.now() + timeoutMs;

  while (Date.now() <= deadline) {
    if (!internals.inProgress) {
      return;
    }
    await Bun.sleep(5);
  }

  throw new Error("Timed out waiting for RadiusClient health operation lock to become idle");
}

describe("RadiusClient dynamic authorization stable retry authenticator integration", () => {
  test("stable same-host retry keeps identifier and uses computed accounting-style request authenticator", async () => {
    const sharedSecret = "stable-retry-shared-secret";
    const sessionId = "stable-same-host-session";
    const healthCheckUser = "health-user";
    const capturedUserPackets: Buffer[] = [];
    const server = await bindServer();

    server.on("message", (msg, rinfo) => {
      const requestPacket = Buffer.from(msg);
      const attributes = parseAttributes(requestPacket);
      const packetSessionId = readStringAttribute(attributes, 44);
      const packetUsername = readStringAttribute(attributes, 1);

      if (packetSessionId === sessionId) {
        capturedUserPackets.push(requestPacket);

        const response = buildDynamicAuthorizationResponse(requestPacket, sharedSecret, COA_ACK_CODE);
        if (capturedUserPackets.length === 1) {
          response.writeUInt8((response.readUInt8(1) + 1) % 256, 1);
        }

        server.send(response, rinfo.port, rinfo.address);
        return;
      }

      if (packetUsername === healthCheckUser) {
        const probeResponse = buildDynamicAuthorizationResponse(requestPacket, sharedSecret, COA_ACK_CODE);
        server.send(probeResponse, rinfo.port, rinfo.address);
      }
    });

    const clientConfig: RadiusConfig = {
      host: "127.0.0.1",
      hosts: ["127.0.0.1"],
      secret: sharedSecret,
      dynamicAuthorizationPort: getServerPort(server),
      timeoutMs: 250,
      healthCheckIntervalMs: 60_000,
      healthCheckTimeoutMs: 25,
      healthCheckUser,
      healthCheckPassword: "health-password",
      dynamicAuthorizationRetryIdentityMode: "stable",
      retry: {
        maxAttempts: 2,
        initialDelayMs: 0,
        backoffMultiplier: 1,
        maxDelayMs: 0,
        jitterRatio: 0,
      },
    };

    const client = new RadiusClient(clientConfig);
    const clientInternals = client as unknown as {
      createDynamicAuthorizationRequestIdentifier: () => number;
    };
    clientInternals.createDynamicAuthorizationRequestIdentifier = (): number => 0x2a;

    try {
      await waitForHealthOperationIdle(client);

      const result = await client.sendCoa({
        username: "alice",
        sessionId,
      });

      expect(result.ok).toBe(true);
      expect(result.acknowledged).toBe(true);
      expect(capturedUserPackets).toHaveLength(2);

      const firstRequest = capturedUserPackets[0];
      const secondRequest = capturedUserPackets[1];
      if (!firstRequest || !secondRequest) {
        throw new Error("Expected two captured same-host CoA request packets");
      }

      expect(firstRequest.readUInt8(1)).toBe(secondRequest.readUInt8(1));

      const firstExpectedAuthenticator = computeAccountingStyleRequestAuthenticator(firstRequest, sharedSecret);
      const secondExpectedAuthenticator = computeAccountingStyleRequestAuthenticator(secondRequest, sharedSecret);

      expect(firstRequest.subarray(4, 20).equals(firstExpectedAuthenticator)).toBe(true);
      expect(secondRequest.subarray(4, 20).equals(secondExpectedAuthenticator)).toBe(true);
      expect(secondRequest.subarray(4, 20).equals(firstRequest.subarray(4, 20))).toBe(true);
    } finally {
      client.shutdown();
      await closeSocket(server);
    }
  });

  test("stable failover-host retry rotates identifier while keeping accounting-style request authenticator formula", async () => {
    const sharedSecret = "stable-retry-shared-secret";
    const sessionId = "stable-failover-host-session";
    const healthCheckUser = "health-user";
    const capturedUserPackets: Buffer[] = [];
    let probePackets = 0;
    const server = await bindServer();

    server.on("message", (msg, rinfo) => {
      const requestPacket = Buffer.from(msg);
      const attributes = parseAttributes(requestPacket);
      const packetSessionId = readStringAttribute(attributes, 44);
      const packetUsername = readStringAttribute(attributes, 1);

      if (packetSessionId === sessionId) {
        capturedUserPackets.push(requestPacket);

        const response = buildDynamicAuthorizationResponse(requestPacket, sharedSecret, COA_ACK_CODE);
        if (capturedUserPackets.length === 1) {
          response.writeUInt8((response.readUInt8(1) + 1) % 256, 1);
        }

        server.send(response, rinfo.port, rinfo.address);
        return;
      }

      if (packetUsername === healthCheckUser) {
        probePackets += 1;
        const probeResponse = buildDynamicAuthorizationResponse(requestPacket, sharedSecret, COA_ACK_CODE);
        server.send(probeResponse, rinfo.port, rinfo.address);
      }
    });

    const clientConfig: RadiusConfig = {
      host: "127.0.0.1",
      hosts: ["127.0.0.1", "localhost"],
      secret: sharedSecret,
      dynamicAuthorizationPort: getServerPort(server),
      timeoutMs: 250,
      healthCheckIntervalMs: 60_000,
      healthCheckTimeoutMs: 25,
      healthCheckUser,
      healthCheckPassword: "health-password",
      dynamicAuthorizationRetryIdentityMode: "stable",
      retry: {
        maxAttempts: 2,
        initialDelayMs: 0,
        backoffMultiplier: 1,
        maxDelayMs: 0,
        jitterRatio: 0,
      },
    };

    const client = new RadiusClient(clientConfig);
    const clientInternals = client as unknown as {
      createDynamicAuthorizationRequestIdentifier: () => number;
      activeHost: string | null;
    };
    const deterministicIdentifiers = [0x1a, 0x7b];
    clientInternals.createDynamicAuthorizationRequestIdentifier = (): number => {
      const nextIdentifier = deterministicIdentifiers.shift();
      if (nextIdentifier === undefined) {
        throw new Error("Expected deterministic identifier sequence to contain two values");
      }
      return nextIdentifier;
    };

    try {
      await waitForHealthOperationIdle(client);
      clientInternals.activeHost = "127.0.0.1";

      const result = await client.sendCoa({
        username: "alice",
        sessionId,
      });

      expect(result.ok).toBe(true);
      expect(result.acknowledged).toBe(true);
      expect(capturedUserPackets).toHaveLength(2);
      expect(probePackets).toBeGreaterThan(0);
      expect(client.getActiveHost()).toBe("localhost");

      const firstRequest = capturedUserPackets[0];
      const secondRequest = capturedUserPackets[1];
      if (!firstRequest || !secondRequest) {
        throw new Error("Expected two captured failover CoA request packets");
      }

      expect(firstRequest.readUInt8(1)).not.toBe(secondRequest.readUInt8(1));

      const firstExpectedAuthenticator = computeAccountingStyleRequestAuthenticator(firstRequest, sharedSecret);
      const secondExpectedAuthenticator = computeAccountingStyleRequestAuthenticator(secondRequest, sharedSecret);

      expect(firstRequest.subarray(4, 20).equals(firstExpectedAuthenticator)).toBe(true);
      expect(secondRequest.subarray(4, 20).equals(secondExpectedAuthenticator)).toBe(true);
      expect(secondRequest.subarray(4, 20).equals(firstRequest.subarray(4, 20))).toBe(false);
    } finally {
      client.shutdown();
      await closeSocket(server);
    }
  });
});
