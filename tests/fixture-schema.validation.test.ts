import { copyFileSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, test } from "bun:test";

import { loadRadiusPacketFixture } from "./helpers/packet-fixtures";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const FIXTURES_ROOT = path.resolve(__dirname, "fixtures");
const FIXTURE_SCHEMA_PATH = path.join(FIXTURES_ROOT, "schema", "radius-packet-fixture.schema.json");

function createTempFixturePath(fileName: string, payload: unknown): {
    relativePath: string;
    fixturesRoot: string;
    cleanup: () => void;
} {
    const fixturesRoot = mkdtempSync(path.join(tmpdir(), "ts-radius-fixtures-"));
    const protocolDir = path.join(fixturesRoot, "protocol", "tmp-schema");
    const schemaDir = path.join(fixturesRoot, "schema");
    const fixturePath = path.join(protocolDir, fileName);

    mkdirSync(protocolDir, { recursive: true });
    mkdirSync(schemaDir, { recursive: true });
    copyFileSync(FIXTURE_SCHEMA_PATH, path.join(schemaDir, "radius-packet-fixture.schema.json"));

    writeFileSync(fixturePath, `${JSON.stringify(payload, null, 2)}\n`, "utf8");

    const relativePath = path.posix.join("protocol", "tmp-schema", fileName);

    return {
        relativePath,
        fixturesRoot,
        cleanup: () => {
            rmSync(fixturesRoot, { recursive: true, force: true });
        },
    };
}

describe("Fixture schema validation", () => {
    test("accepts fixture files with optional top-level $schema", () => {
        const { relativePath, fixturesRoot, cleanup } = createTempFixturePath("valid.optional-schema.json", {
            $schema: "./schema/radius-packet-fixture.schema.json",
            name: "valid-optional-schema",
            rfc: "RFC2865",
            description: "Fixture with optional top-level $schema reference.",
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
        });

        try {
            const fixture = loadRadiusPacketFixture(relativePath, { fixturesRoot });

            expect(fixture.name).toBe("valid-optional-schema");
        } finally {
            cleanup();
        }
    });

    test("rejects fixture files with unexpected top-level properties", () => {
        const { relativePath, fixturesRoot, cleanup } = createTempFixturePath("invalid.extra-top-level.json", {
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
            expect(() => loadRadiusPacketFixture(relativePath, { fixturesRoot })).toThrow(
                "Fixture schema validation failed",
            );
        } finally {
            cleanup();
        }
    });

    test("rejects fixture attributes with unexpected properties", () => {
        const { relativePath, fixturesRoot, cleanup } = createTempFixturePath("invalid.extra-attribute-field.json", {
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
            expect(() => loadRadiusPacketFixture(relativePath, { fixturesRoot })).toThrow(
                "Fixture schema validation failed",
            );
        } finally {
            cleanup();
        }
    });

    test("rejects fixtures whose packetHex is not full hex byte pairs", () => {
        const { relativePath, fixturesRoot, cleanup } = createTempFixturePath("invalid.packet-hex.odd.json", {
            name: "invalid-packet-hex-odd",
            rfc: "RFC2865",
            description: "Fixture with an odd-length packetHex nibble sequence.",
            packetHex: "02 01 00 1e 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 19 0a 65 6e 67 69 6e 65 65 7",
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
        });

        try {
            expect(() => loadRadiusPacketFixture(relativePath, { fixturesRoot })).toThrow(
                "Fixture schema validation failed",
            );
        } finally {
            cleanup();
        }
    });

    test("rejects fixtures whose expected attribute rawHex is not full hex byte pairs", () => {
        const { relativePath, fixturesRoot, cleanup } = createTempFixturePath("invalid.raw-hex.odd.json", {
            name: "invalid-raw-hex-odd",
            rfc: "RFC2865",
            description: "Fixture with an odd-length rawHex nibble sequence.",
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
                        rawHex: "656e67696e65657",
                        decodedValue: "engineer",
                    },
                ],
            },
        });

        try {
            expect(() => loadRadiusPacketFixture(relativePath, { fixturesRoot })).toThrow(
                "Fixture schema validation failed",
            );
        } finally {
            cleanup();
        }
    });
});