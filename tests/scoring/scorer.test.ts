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

  it("applies cumulative penalties for distinct secrets on different lines of the same file", () => {
    // Aynı dosyada 3 farklı satırda 3 ayrı AWS anahtarı sızmışsa her biri ceza öder
    const findings: Finding[] = Array.from({ length: 3 }).map((_, idx) => ({
      ruleId: "aws-access-key",
      ruleName: "AWS Access Key",
      severity: "critical",
      file: "src/aws.ts",
      line: idx + 1,
      column: 1,
      maskedValue: "AKIA********"
    }));

    const report = calculateSecurityScore(findings);
    // 3 * 35 = 105 penalty -> Math.max(0, 100 - 105) = 0
    expect(report.score).toBe(0);
    expect(report.tier).toBe("Critical");
    expect(report.counts.critical).toBe(3);
  });

  it("deduplicates exact same physical location (same file, line, col)", () => {
    // Aynı koordinatta raporlanan mükerrer bulgular tekilleştirilir
    const findings: Finding[] = [
      {
        ruleId: "aws-access-key",
        ruleName: "AWS Access Key",
        severity: "critical",
        file: "src/aws.ts",
        line: 10,
        column: 4,
        maskedValue: "AKIA********"
      },
      {
        ruleId: "aws-access-key",
        ruleName: "AWS Access Key (Duplicate)",
        severity: "critical",
        file: "src/aws.ts",
        line: 10,
        column: 4,
        maskedValue: "AKIA********"
      }
    ];

    const report = calculateSecurityScore(findings);
    // Tekilleştirilerek 1x ceza (35) kesilmeli -> 100 - 35 = 65
    expect(report.score).toBe(65);
    expect(report.counts.critical).toBe(1);
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
    // 2 * 35 = 70 penalty -> 100 - 70 = 30
    expect(report.score).toBe(30);
    expect(report.counts.critical).toBe(2);
  });

  it("deduplicates findings at the exact same location keeping the higher severity", () => {
    const findings: Finding[] = [
      {
        ruleId: "generic-api-key",
        ruleName: "Generic API Key",
        severity: "medium",
        file: "src/api.ts",
        line: 10,
        column: 5,
        maskedValue: "tok_********"
      },
      {
        ruleId: "custom-corp-key",
        ruleName: "Corporate Key",
        severity: "critical",
        file: "src/api.ts",
        line: 10,
        column: 5,
        maskedValue: "tok_********"
      }
    ];

    const report = calculateSecurityScore(findings);
    // Critical (35) seçilir, medium elenir -> 100 - 35 = 65
    expect(report.score).toBe(65);
    expect(report.counts.critical).toBe(1);
    expect(report.counts.medium).toBe(0);
  });
});
