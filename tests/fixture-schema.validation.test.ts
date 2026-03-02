import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, test } from "bun:test";

import { loadRadiusPacketFixture } from "./helpers/packet-fixtures";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const FIXTURES_ROOT = path.resolve(__dirname, "fixtures");

function createTempFixturePath(fileName: string, payload: unknown): {
    relativePath: string;
    cleanup: () => void;
} {
    const tempDir = mkdtempSync(path.join(FIXTURES_ROOT, "tmp-schema-"));
    const fixturePath = path.join(tempDir, fileName);

    writeFileSync(fixturePath, `${JSON.stringify(payload, null, 2)}\n`, "utf8");

    const relativePath = path.relative(FIXTURES_ROOT, fixturePath).split(path.sep).join("/");

    return {
        relativePath,
        cleanup: () => {
            rmSync(tempDir, { recursive: true, force: true });
        },
    };
}

describe("Fixture schema validation", () => {
    test("rejects fixture files with unexpected top-level properties", () => {
        const { relativePath, cleanup } = createTempFixturePath("invalid.extra-top-level.json", {
            name: "invalid-extra-top-level",
            rfc: "RFC2865",
            description: "Fixture with unexpected top-level property.",
            packetHex: "02 01 00 1e 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 19 0a 65 6e 67 69 6e 65 65 72",
            expected: {
                code: 2,
                identifier: 1,
                length: 30,
                authenticatorHexPattern: "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
                attributes: [
                    {
                        id: 25,
                        name: "Class",
                        rawHex: "656e67696e656572",
                        decodedValue: "engineer",
                    },
                ],
            },
            unexpectedTopLevel: true,
        });

        try {
            expect(() => loadRadiusPacketFixture(relativePath)).toThrow("Fixture schema validation failed");
        } finally {
            cleanup();
        }
    });

    test("rejects fixture attributes with unexpected properties", () => {
        const { relativePath, cleanup } = createTempFixturePath("invalid.extra-attribute-field.json", {
            name: "invalid-extra-attribute-field",
            rfc: "RFC2865",
            description: "Fixture with unexpected property inside expected.attributes entry.",
            packetHex: "02 01 00 1e 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 19 0a 65 6e 67 69 6e 65 65 72",
            expected: {
                code: 2,
                identifier: 1,
                length: 30,
                authenticatorHexPattern: "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
                attributes: [
                    {
                        id: 25,
                        name: "Class",
                        rawHex: "656e67696e656572",
                        decodedValue: "engineer",
                        unexpectedAttributeField: "should-fail",
                    },
                ],
            },
        });

        try {
            expect(() => loadRadiusPacketFixture(relativePath)).toThrow("Fixture schema validation failed");
        } finally {
            cleanup();
        }
    });
});