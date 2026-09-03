import { describe, it, expect } from "vitest";
import { calculateSecurityScore } from "../../src/scoring/scorer.js";
import { Finding } from "../../src/types/index.js";

describe("Security Scorer", () => {
  it("returns 100 with Excellent tier when findings list is empty", () => {
    const result = calculateSecurityScore([]);
    expect(result.score).toBe(100);
    expect(result.tier).toBe("Excellent");
  });

  it("deducts correctly for low severity findings", () => {
    const findings: Finding[] = [
      { ruleId: "r1", ruleName: "R1", severity: "low", file: "a.ts", line: 1, column: 1, maskedValue: "***" }
    ];
    const result = calculateSecurityScore(findings);
    expect(result.score).toBe(95);
  });

  it("deducts correctly for critical findings and drops tier", () => {
    const findings: Finding[] = [
      { ruleId: "crit1", ruleName: "Crit", severity: "critical", file: "a.env", line: 1, column: 1, maskedValue: "***" },
      { ruleId: "crit2", ruleName: "Crit", severity: "critical", file: "b.env", line: 1, column: 1, maskedValue: "***" }
    ];
    const result = calculateSecurityScore(findings);
    expect(result.score).toBe(30);
    expect(result.tier).toBe("Critical");
  });

  it("never goes below zero even with extreme findings", () => {
    const findings: Finding[] = Array.from({ length: 10 }, (_, i) => ({
      ruleId: `crit-${i}`,
      ruleName: "Crit",
      severity: "critical",
      file: "secret.env",
      line: i,
      column: 1,
      maskedValue: "***"
    }));
    const result = calculateSecurityScore(findings);
    expect(result.score).toBe(0);
    expect(result.tier).toBe("Critical");
  });
});
