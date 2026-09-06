import { describe, it, expect } from "vitest";
import { generateSarifReport } from "../../src/reporters/sarif.js";
import { ScanResult, Finding } from "../../src/types/index.js";

describe("SARIF Reporter with Fingerprints", () => {
  const mockFinding: Finding = {
    ruleId: "aws-access-key",
    ruleName: "AWS Access Key",
    severity: "critical",
    file: "src/aws.ts",
    line: 10,
    column: 5,
    maskedValue: "AKIA****************",
    secretHash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  };

  const mockScanResult: ScanResult = {
    findings: [mockFinding],
    summary: {
      totalFiles: 1,
      scannedFiles: 1,
      totalFindings: 1,
      suppressedFindings: 0,
      score: 65,
      rating: "Warning",
      scanDurationMs: 100
    }
  };

  it("includes secretHash inside partialFingerprints for GitHub Code Scanning tracking", () => {
    const report: any = generateSarifReport(mockScanResult);
    const result = report.runs[0].results[0];

    expect(result.partialFingerprints).toBeDefined();
    expect(result.partialFingerprints.secretHash).toBe(mockFinding.secretHash);
  });
});
