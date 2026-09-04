import { describe, it, expect } from "vitest";
import { calculateSecurityScore } from "../../src/scoring/scorer.js";
import { Finding } from "../../src/types/index.js";

describe("Security Scorer", () => {
  it("calculates 100 score for empty findings", () => {
    const report = calculateSecurityScore([]);
    expect(report.score).toBe(100);
    expect(report.tier).toBe("Excellent");
    expect(report.counts.critical).toBe(0);
  });

  it("applies penalty 1x for 5 duplicate findings of same ruleId and file", () => {
    const findings: Finding[] = Array.from({ length: 5 }).map((_, idx) => ({
      ruleId: "aws-access-key",
      ruleName: "AWS Access Key",
      severity: "critical",
      file: "src/aws.ts",
      line: idx + 1,
      column: 1,
      maskedValue: "AKIA********"
    }));

    const report = calculateSecurityScore(findings);
    // critical penalty = 35. 100 - 35 = 65
    expect(report.score).toBe(65);
    expect(report.counts.critical).toBe(5);
  });

  it("applies separate penalties for same ruleId in different files", () => {
    const findings: Finding[] = [
      {
        ruleId: "aws-access-key",
        ruleName: "AWS Access Key",
        severity: "critical",
        file: "src/file1.ts",
        line: 1,
        column: 1,
        maskedValue: "AKIA********"
      },
      {
        ruleId: "aws-access-key",
        ruleName: "AWS Access Key",
        severity: "critical",
        file: "src/file2.ts",
        line: 1,
        column: 1,
        maskedValue: "AKIA********"
      }
    ];

    const report = calculateSecurityScore(findings);
    // 2 * 35 = 70 penalty. 100 - 70 = 30
    expect(report.score).toBe(30);
    expect(report.counts.critical).toBe(2);
  });

  it("applies separate penalties for different rules in the same file", () => {
    const findings: Finding[] = [
      {
        ruleId: "aws-access-key",
        ruleName: "AWS Access Key",
        severity: "critical",
        file: "src/auth.ts",
        line: 1,
        column: 1,
        maskedValue: "AKIA********"
      },
      {
        ruleId: "generic-password",
        ruleName: "Generic Password",
        severity: "medium",
        file: "src/auth.ts",
        line: 2,
        column: 1,
        maskedValue: "pass********"
      }
    ];

    const report = calculateSecurityScore(findings);
    // critical (35) + medium (10) = 45 penalty. 100 - 45 = 55
    expect(report.score).toBe(55);
    expect(report.counts.critical).toBe(1);
    expect(report.counts.medium).toBe(1);
  });
});
