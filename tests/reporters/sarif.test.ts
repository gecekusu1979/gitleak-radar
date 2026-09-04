import { describe, it, expect } from "vitest";
import { generateSarifReport, mapSeverityToSarifLevel } from "../../src/reporters/sarif.js";
import { ScanResult } from "../../src/types/index.js";

describe("SARIF v2.1.0 Reporter", () => {
  it("maps severity levels according to SARIF specification", () => {
    expect(mapSeverityToSarifLevel("critical")).toBe("error");
    expect(mapSeverityToSarifLevel("high")).toBe("error");
    expect(mapSeverityToSarifLevel("medium")).toBe("warning");
    expect(mapSeverityToSarifLevel("low")).toBe("note");
  });

  it("generates a valid SARIF structure matching schema", () => {
    const mockResult: ScanResult = {
      summary: {
        filesScanned: 5,
        linesScanned: 200,
        findings: 1,
        score: 40,
        tier: "Warning",
        durationMs: 42
      },
      findings: [
        {
          ruleId: "aws-access-key",
          ruleName: "AWS Access Key",
          severity: "critical",
          file: "src/config.ts",
          line: 12,
          column: 5,
          maskedValue: "AK****************XE",
          commit: "a".repeat(40),
          commitAuthor: "Lead Dev",
          commitDate: "2026-03-31T00:00:00Z"
        }
      ]
    };

    const sarif = generateSarifReport(mockResult, "1.2.0");

    expect(sarif.version).toBe("2.1.0");
    expect(sarif.$schema).toContain("sarif-schema-2.1.0.json");
    expect(sarif.runs.length).toBe(1);

    const run = sarif.runs[0]!;
    expect(run.tool.driver.name).toBe("GitLeak Radar");
    expect(run.tool.driver.version).toBe("1.2.0");
    expect(run.tool.driver.rules.length).toBeGreaterThan(10);

    expect(run.results.length).toBe(1);
    const findingResult = run.results[0]!;
    expect(findingResult.ruleId).toBe("aws-access-key");
    expect(findingResult.level).toBe("error");
    expect(findingResult.locations[0]?.physicalLocation.artifactLocation.uri).toBe("src/config.ts");
    expect(findingResult.locations[0]?.physicalLocation.region.startLine).toBe(12);
    expect(findingResult.partialFingerprints?.commitHash).toBe("a".repeat(40));
    expect(findingResult.properties?.commitAuthor).toBe("Lead Dev");
  });
});
