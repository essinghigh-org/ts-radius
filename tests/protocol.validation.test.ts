/* eslint-disable @typescript-eslint/no-confusing-void-expression */

import { describe, expect, test } from "bun:test";

import {
  radiusAccounting,
  radiusAuthenticate,
  radiusCoa,
  radiusDisconnect
} from "../src/protocol";

describe("protocol request/options validation", () => {
  test("rejects invalid assignmentAttributeId bounds", async () => {
    const assignmentLowerBoundRejection = (
      expect(
        radiusAuthenticate("127.0.0.1", "alice", "password", {
          secret: "secret",
          assignmentAttributeId: 0,
          timeoutMs: 10
        })
      ).rejects.toThrow("[radius] assignmentAttributeId must be an integer between 1 and 255")
    ) as unknown as Promise<void>;
    await assignmentLowerBoundRejection;

    const assignmentUpperBoundRejection = (
      expect(
        radiusAuthenticate("127.0.0.1", "alice", "password", {
          secret: "secret",
          assignmentAttributeId: 256,
          timeoutMs: 10
        })
      ).rejects.toThrow("[radius] assignmentAttributeId must be an integer between 1 and 255")
    ) as unknown as Promise<void>;
    await assignmentUpperBoundRejection;
  });

  test("requires vendorId and vendorType together for Vendor-Specific assignment extraction", async () => {
    const missingVendorTypeRejection = (
      expect(
        radiusAuthenticate("127.0.0.1", "alice", "password", {
          secret: "secret",
          assignmentAttributeId: 26,
          vendorId: 9,
          timeoutMs: 10
        })
      ).rejects.toThrow("[radius] vendorId and vendorType are both required when assignmentAttributeId is 26")
    ) as unknown as Promise<void>;
    await missingVendorTypeRejection;

    const missingVendorIdRejection = (
      expect(
        radiusAuthenticate("127.0.0.1", "alice", "password", {
          secret: "secret",
          assignmentAttributeId: 26,
          vendorType: 1,
          timeoutMs: 10
        })
      ).rejects.toThrow("[radius] vendorId and vendorType are both required when assignmentAttributeId is 26")
    ) as unknown as Promise<void>;
    await missingVendorIdRejection;
  });

  test("rejects invalid vendorId/vendorType bounds", async () => {
    const negativeVendorIdRejection = expect(
      radiusAuthenticate("127.0.0.1", "alice", "password", {
        secret: "secret",
        assignmentAttributeId: 26,
        vendorId: -1,
        vendorType: 1,
        timeoutMs: 10
      })
    ).rejects.toThrow("[radius] vendorId must be a uint32") as unknown as Promise<void>;
    await negativeVendorIdRejection;

    const largeVendorIdRejection = expect(
      radiusAuthenticate("127.0.0.1", "alice", "password", {
        secret: "secret",
        assignmentAttributeId: 26,
        vendorId: 0x1_0000_0000,
        vendorType: 1,
        timeoutMs: 10
      })
    ).rejects.toThrow("[radius] vendorId must be a uint32") as unknown as Promise<void>;
    await largeVendorIdRejection;

    const invalidVendorTypeRejection = (
      expect(
        radiusAuthenticate("127.0.0.1", "alice", "password", {
          secret: "secret",
          assignmentAttributeId: 26,
          vendorId: 9,
          vendorType: 256,
          timeoutMs: 10
        })
      ).rejects.toThrow("[radius] vendorType must be an integer between 0 and 255")
    ) as unknown as Promise<void>;
    await invalidVendorTypeRejection;
  });

  test("rejects invalid accounting request fields and bounds", async () => {
    const missingUsernameRejection = expect(
      radiusAccounting(
        "127.0.0.1",
        {
          username: "",
          sessionId: "s-1",
          statusType: "Start"
        },
        {
          secret: "secret",
          timeoutMs: 10
        }
      )
    ).rejects.toThrow("[radius] accounting request.username is required") as unknown as Promise<void>;
    await missingUsernameRejection;

    const invalidSessionTimeRejection = expect(
      radiusAccounting(
        "127.0.0.1",
        {
          username: "alice",
          sessionId: "s-1",
          statusType: "Start",
          sessionTime: -1
        },
        {
          secret: "secret",
          timeoutMs: 10
        }
      )
    ).rejects.toThrow("[radius] accounting request.sessionTime must be uint32") as unknown as Promise<void>;
    await invalidSessionTimeRejection;
  });

  test("rejects invalid dynamic authorization request fields and bounds", async () => {
    const emptyUsernameRejection = expect(
      radiusCoa(
        "127.0.0.1",
        {
          username: ""
        },
        {
          secret: "secret",
          timeoutMs: 10
        }
      )
    ).rejects.toThrow("[radius] dynamic authorization request.username cannot be empty") as unknown as Promise<void>;
    await emptyUsernameRejection;

    const invalidDynamicAttributeRejection = (
      expect(
        radiusDisconnect(
          "127.0.0.1",
          {
            username: "alice",
            attributes: [{ type: 26, value: 0x1_0000_0000 }]
          },
          {
            secret: "secret",
            timeoutMs: 10
          }
        )
      ).rejects.toThrow("[radius] dynamic authorization attribute 26 number values must be uint32")
    ) as unknown as Promise<void>;
    await invalidDynamicAttributeRejection;

    const missingDynamicIdentifiersRejection = (
      expect(
        radiusCoa(
          "127.0.0.1",
          {},
          {
            secret: "secret",
            timeoutMs: 10
          }
        )
      ).rejects.toThrow("[radius] dynamic authorization request must include username, sessionId, or at least one attribute")
    ) as unknown as Promise<void>;
    await missingDynamicIdentifiersRejection;
  });
});