import crypto from "node:crypto";
import dgram from "node:dgram";

import { describe, expect, test } from "bun:test";

import { radiusAuthenticate } from "../src/protocol";
import type { RadiusProtocolOptions, RadiusResult } from "../src/types";

const TEST_HOST = "127.0.0.1";
const TEST_SECRET = "stream-d-shared-secret";

function encodeStringAttribute(type: number, value: string): Buffer {
  const valueBuffer = Buffer.from(value, "utf8");
  return Buffer.concat([Buffer.from([type, valueBuffer.length + 2]), valueBuffer]);
}

function encodeVendorSpecificAttribute(vendorId: number, vendorType: number, value: string): Buffer {
  const vendorValue = Buffer.from(value, "utf8");
  const vendorLength = vendorValue.length + 2;

  const attributeValue = Buffer.alloc(6 + vendorValue.length);
  attributeValue.writeUInt32BE(vendorId, 0);
  attributeValue.writeUInt8(vendorType, 4);
  attributeValue.writeUInt8(vendorLength, 5);
  vendorValue.copy(attributeValue, 6);

  return Buffer.concat([Buffer.from([26, attributeValue.length + 2]), attributeValue]);
}

function buildAccessAcceptResponse(request: Buffer, attributes: Buffer[]): Buffer {
  const identifier = request.readUInt8(1);
  const requestAuthenticator = request.subarray(4, 20);
  const attributeBuffer = Buffer.concat(attributes);

  const response = Buffer.alloc(20 + attributeBuffer.length);
  response.writeUInt8(2, 0);
  response.writeUInt8(identifier, 1);
  response.writeUInt16BE(response.length, 2);
  attributeBuffer.copy(response, 20);

  const hashInput = Buffer.concat([
    response.subarray(0, 4),
    requestAuthenticator,
    attributeBuffer,
    Buffer.from(TEST_SECRET, "utf8")
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

async function runAuthScenario(
  attributes: Buffer[],
  options: Partial<RadiusProtocolOptions> = {}
): Promise<RadiusResult> {
  const server = await bindServer();

  server.on("message", (request, requestInfo) => {
    const response = buildAccessAcceptResponse(request, attributes);
    server.send(response, requestInfo.port, requestInfo.address);
  });

  try {
    return await radiusAuthenticate(TEST_HOST, "alice", "password", {
      secret: TEST_SECRET,
      port: getServerPort(server),
      timeoutMs: 500,
      ...options
    });
  } finally {
    await closeServer(server);
  }
}

describe("radiusAuthenticate attribute extraction", () => {
  test("extracts class from custom assignmentAttributeId", async () => {
    const result = await runAuthScenario([
      encodeStringAttribute(18, "engineering")
    ], {
      assignmentAttributeId: 18
    });

    expect(result.ok).toBe(true);
    expect(result.class).toBe("engineering");
  });

  test("extracts value from vendor-specific assignment attribute when vendor selectors match", async () => {
    const result = await runAuthScenario([
      encodeVendorSpecificAttribute(4242, 7, "tier=premium")
    ], {
      assignmentAttributeId: 26,
      vendorId: 4242,
      vendorType: 7
    });

    expect(result.ok).toBe(true);
    expect(result.class).toBe("tier=premium");
  });

  test("does not extract vendor-specific value when vendor selectors do not match", async () => {
    const result = await runAuthScenario([
      encodeVendorSpecificAttribute(4242, 7, "tier=premium")
    ], {
      assignmentAttributeId: 26,
      vendorId: 9999,
      vendorType: 7
    });

    expect(result.ok).toBe(true);
    expect(result.class).toBeUndefined();
  });

  test("extracts capture group from valuePattern on regular attributes", async () => {
    const result = await runAuthScenario([
      encodeStringAttribute(25, "group=ops;region=eu")
    ], {
      valuePattern: "group=([^;]+)"
    });

    expect(result.ok).toBe(true);
    expect(result.class).toBe("ops");
  });

  test("falls back to full regex match when valuePattern has no capture group", async () => {
    const result = await runAuthScenario([
      encodeStringAttribute(25, "group=ops;region=eu")
    ], {
      valuePattern: "group=[^;]+"
    });

    expect(result.ok).toBe(true);
    expect(result.class).toBe("group=ops");
  });

  test("does not extract value when valuePattern does not match", async () => {
    const result = await runAuthScenario([
      encodeStringAttribute(25, "group=ops;region=eu")
    ], {
      valuePattern: "tier=([^;]+)"
    });

    expect(result.ok).toBe(true);
    expect(result.class).toBeUndefined();
  });

  test("extracts capture group from valuePattern on vendor-specific attributes", async () => {
    const result = await runAuthScenario([
      encodeVendorSpecificAttribute(9, 1, "plan=gold|id=42")
    ], {
      assignmentAttributeId: 26,
      vendorId: 9,
      vendorType: 1,
      valuePattern: "plan=([^|]+)"
    });

    expect(result.ok).toBe(true);
    expect(result.class).toBe("gold");
  });

  test("handles malformed valuePattern safely without throwing and falls back to full attribute value", async () => {
    const result = await runAuthScenario([
      encodeStringAttribute(25, "engineering")
    ], {
      valuePattern: "(["
    });

    expect(result.ok).toBe(true);
    expect(result.class).toBe("engineering");
  });
});