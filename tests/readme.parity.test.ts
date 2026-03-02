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

function getHeadingSection(markdown: string, headingPattern: RegExp): string {
  const lines = markdown.replaceAll("\r\n", "\n").split("\n");
  const startIndex = lines.findIndex((line) => headingPattern.test(line.trim()));

  expect(startIndex).toBeGreaterThanOrEqual(0);

  const headingLine = lines[startIndex]?.trim() ?? "";
  const headingMatch = headingLine.match(/^(#+)\s+/);

  expect(headingMatch).not.toBeNull();

  const headingHashes = headingMatch?.[1];
  const headingLevel = headingHashes ? headingHashes.length : 1;
  let endIndex = lines.length;

  for (let i = startIndex + 1; i < lines.length; i++) {
    const candidate = lines[i]?.trim() ?? "";
    const candidateMatch = candidate.match(/^(#+)\s+/);
    const candidateHashes = candidateMatch?.[1];
    if (candidateHashes && candidateHashes.length <= headingLevel) {
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

    const healthProbeRow = tableRows
      .slice(2)
      .find((row) => /health\s*probes?/i.test(row));

    expect(healthProbeRow).toBeDefined();

    const normalizedHealthProbeRow = (healthProbeRow ?? "").toLowerCase();
    expect(normalizedHealthProbeRow).toContain("validateresponsesource");
    expect(/auth/.test(normalizedHealthProbeRow)).toBe(true);
    expect(/accounting|coa|disconnect/.test(normalizedHealthProbeRow)).toBe(true);

    const validationNotes = getHeadingSection(
      readme,
      /^###\s+validation policy notes$/i
    );
    const normalizedValidationNotes = validationNotes.toLowerCase();

    expect(normalizedValidationNotes).toContain("validateresponsesource");
    expect(/auth[^\n]*probe/.test(normalizedValidationNotes)).toBe(true);
    expect(/accounting|coa|disconnect/.test(normalizedValidationNotes)).toBe(true);
    expect(
      /do(?:es)?\s+not\s+forward|not\s+forwarded|strict\s+source\s+validation|effectively\s+`?true`?|always\s+`?true`?/.test(
        normalizedValidationNotes
      )
    ).toBe(true);

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