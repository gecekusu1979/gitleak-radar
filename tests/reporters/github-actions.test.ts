import { describe, it, expect, vi } from "vitest";
import { formatFindingAnnotation, renderGitHubActionsReport } from "../../src/reporters/github-actions.js";
import { type Finding, type ScanResult } from "../../src/types/index.js";

describe("GitHub Actions Reporter", () => {
  it("formats high/critical findings as ::error with line and column", () => {
    const finding: Finding = {
      ruleId: "aws-access-key",
      ruleName: "AWS Access Key",
      severity: "critical",
      file: "src/config.ts",
      line: 12,
      column: 5,
      maskedValue: "AKIA****************"
    };

    const annotation = formatFindingAnnotation(finding);
    expect(annotation).toBe(
      "::error file=src/config.ts,line=12,col=5,title=GitLeak Radar%3A AWS Access Key [CRITICAL]::Secret detected: AKIA**************** (aws-access-key). Remove credential and revoke immediately."
    );
  });

  it("formats medium/low findings as ::warning", () => {
    const finding: Finding = {
      ruleId: "generic-api-key",
      ruleName: "Generic API Key",
      severity: "medium",
      file: "app.env",
      line: 3,
      column: 1,
      maskedValue: "pr****************ef"
    };

    const annotation = formatFindingAnnotation(finding);
    expect(annotation.startsWith("::warning ")).toBe(true);
    expect(annotation).toContain("file=app.env,line=3,col=1");
  });

  it("renders annotations for all findings in ScanResult", () => {
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    const dummyResult: ScanResult = {
      summary: {
        filesScanned: 1,
        linesScanned: 10,
        findings: 1,
        score: 80,
        tier: "Good",
        durationMs: 5
      },
      findings: [
        {
          ruleId: "github-pat",
          ruleName: "GitHub PAT",
          severity: "high",
          file: "index.js",
          line: 1,
          column: 1,
          maskedValue: "gh******************"
        }
      ]
    };

    renderGitHubActionsReport(dummyResult);
    expect(logSpy).toHaveBeenCalledTimes(1);
    expect(logSpy.mock.calls[0]![0]).toContain("::error file=index.js,line=1,col=1");
    logSpy.mockRestore();
  });
});
