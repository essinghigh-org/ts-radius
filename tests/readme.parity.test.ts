import { describe, expect, test } from "bun:test";

function readReadme(): Promise<string> {
  return Bun.file(new URL("../README.md", import.meta.url)).text();
}

function getTopLevelSection(markdown: string, headingPattern: RegExp): string {
  const lines = markdown.replaceAll("\r\n", "\n").split("\n");
  const startIndex = lines.findIndex((line) => headingPattern.test(line.trim()));

  expect(startIndex).toBeGreaterThanOrEqual(0);

  let endIndex = lines.length;
  for (let i = startIndex + 1; i < lines.length; i++) {
    if (/^##\s+/.test(lines[i]?.trim() ?? "")) {
      endIndex = i;
      break;
    }
  }

  return lines.slice(startIndex + 1, endIndex).join("\n");
}

function getFirstMarkdownTableRows(sectionBody: string): string[] {
  const lines = sectionBody.split("\n").map((line) => line.trim());

  const rows: string[] = [];
  let inTable = false;

  for (const line of lines) {
    if (line.startsWith("|") && line.endsWith("|")) {
      inTable = true;
      rows.push(line);
      continue;
    }

    if (inTable) {
      break;
    }
  }

  return rows;
}

describe("README docs parity", () => {
  test("includes advanced-options operation matrix and feature key coverage", async () => {
    const readme = await readReadme();

    const advancedSection = getTopLevelSection(
      readme,
      /^##\s+advanced options parity matrix$/i
    );

    const tableRows = getFirstMarkdownTableRows(advancedSection);
    expect(tableRows.length).toBeGreaterThanOrEqual(7);

    const headerRow = tableRows[0]?.toLowerCase() ?? "";
    expect(headerRow).toContain("operation");
    expect(headerRow).toContain("retry");

    const dataRows = tableRows.slice(2).join("\n").toLowerCase();

    for (const operationKey of [
      /authenticate/,
      /sendaccounting/,
      /sendcoa/,
      /senddisconnect/,
      /health\s*probes?/
    ]) {
      expect(operationKey.test(dataRows)).toBe(true);
    }

    for (const apiKey of [
      "radiusAuthenticateWithContinuation",
      "radiusContinueAuthenticate",
      "authMethod",
      "chapId",
      "chapChallenge",
      "accountingOn",
      "accountingOff",
      "dynamicAuthorizationRetryIdentityMode",
    ]) {
      expect(readme).toContain(apiKey);
    }
  });
});