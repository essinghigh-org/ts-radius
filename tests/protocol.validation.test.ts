import { describe, expect, test } from "bun:test";

import {
  radiusAccounting,
  radiusAuthenticate,
  radiusCoa,
  radiusDisconnect
} from "../src/protocol";

async function expectRejectMessage(action: () => Promise<unknown>, expectedMessage: string): Promise<void> {
  let caughtError: unknown;

  try {
    await action();
  } catch (error: unknown) {
    caughtError = error;
  }

  expect(caughtError).toBeDefined();
  if (!(caughtError instanceof Error)) {
    throw new Error("Expected an Error instance to be thrown");
  }

  expect(caughtError.message).toBe(expectedMessage);
}

describe("protocol request/options validation", () => {
  test("rejects invalid assignmentAttributeId bounds", async () => {
    await expectRejectMessage(
      () => radiusAuthenticate("127.0.0.1", "alice", "password", {
        secret: "secret",
        assignmentAttributeId: 0,
        timeoutMs: 10
      }),
      "[radius] assignmentAttributeId must be an integer between 1 and 255"
    );

    await expectRejectMessage(
      () => radiusAuthenticate("127.0.0.1", "alice", "password", {
        secret: "secret",
        assignmentAttributeId: 256,
        timeoutMs: 10
      }),
      "[radius] assignmentAttributeId must be an integer between 1 and 255"
    );
  });

  test("requires vendorId and vendorType together for Vendor-Specific assignment extraction", async () => {
    await expectRejectMessage(
      () => radiusAuthenticate("127.0.0.1", "alice", "password", {
        secret: "secret",
        assignmentAttributeId: 26,
        vendorId: 9,
        timeoutMs: 10
      }),
      "[radius] vendorId and vendorType are both required when assignmentAttributeId is 26"
    );

    await expectRejectMessage(
      () => radiusAuthenticate("127.0.0.1", "alice", "password", {
        secret: "secret",
        assignmentAttributeId: 26,
        vendorType: 1,
        timeoutMs: 10
      }),
      "[radius] vendorId and vendorType are both required when assignmentAttributeId is 26"
    );
  });

  test("rejects invalid vendorId/vendorType bounds", async () => {
    await expectRejectMessage(
      () => radiusAuthenticate("127.0.0.1", "alice", "password", {
        secret: "secret",
        assignmentAttributeId: 26,
        vendorId: -1,
        vendorType: 1,
        timeoutMs: 10
      }),
      "[radius] vendorId must be a uint32"
    );

    await expectRejectMessage(
      () => radiusAuthenticate("127.0.0.1", "alice", "password", {
        secret: "secret",
        assignmentAttributeId: 26,
        vendorId: 9,
        vendorType: 256,
        timeoutMs: 10
      }),
      "[radius] vendorType must be an integer between 0 and 255"
    );
  });

  test("rejects invalid accounting request fields and bounds", async () => {
    await expectRejectMessage(
      () => radiusAccounting(
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
      ),
      "[radius] accounting request.username is required"
    );

    await expectRejectMessage(
      () => radiusAccounting(
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
      ),
      "[radius] accounting request.sessionTime must be uint32"
    );
  });

  test("rejects invalid dynamic authorization request fields and bounds", async () => {
    await expectRejectMessage(
      () => radiusCoa(
        "127.0.0.1",
        {
          username: ""
        },
        {
          secret: "secret",
          timeoutMs: 10
        }
      ),
      "[radius] dynamic authorization request.username cannot be empty"
    );

    await expectRejectMessage(
      () => radiusDisconnect(
        "127.0.0.1",
        {
          username: "alice",
          attributes: [{ type: 26, value: 0x1_0000_0000 }]
        },
        {
          secret: "secret",
          timeoutMs: 10
        }
      ),
      "[radius] dynamic authorization attribute 26 number values must be uint32"
    );

    await expectRejectMessage(
      () => radiusCoa(
        "127.0.0.1",
        {},
        {
          secret: "secret",
          timeoutMs: 10
        }
      ),
      "[radius] dynamic authorization request must include username, sessionId, or at least one attribute"
    );
  });
});