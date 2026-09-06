import { describe, it, expect } from "vitest";
import { generateGitLabReport, renderGitLabReport } from "../../src/reporters/gitlab.js";
import { type ScanResult } from "../../src/types/index.js";
import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";

describe("GitLab Code Quality Reporter", () => {
  it("maps findings into valid GitLab Code Quality issues", () => {
    const result: ScanResult = {
      summary: {
        filesScanned: 1,
        linesScanned: 25,
        findings: 2,
        score: 20,
        tier: "Critical",
        durationMs: 12
      },
      findings: [
        {
          ruleId: "stripe-api-key",
          ruleName: "Stripe API Key",
          severity: "critical",
          file: "src/billing.ts",
          line: 10,
          column: 5,
          maskedValue: "sk_live_************"
        },
        {
          ruleId: "generic-api-key",
          ruleName: "Generic API Key",
          severity: "medium",
          file: "config.env",
          line: 2,
          column: 1,
          maskedValue: "pr****************ef"
        }
      ]
    };

    const issues = generateGitLabReport(result);
    expect(issues).toHaveLength(2);

    // Critical -> blocker
    expect(issues[0]?.severity).toBe("blocker");
    expect(issues[0]?.check_name).toBe("stripe-api-key");
    expect(issues[0]?.location.path).toBe("src/billing.ts");
    expect(issues[0]?.location.lines.begin).toBe(10);
    expect(issues[0]?.fingerprint).toHaveLength(64); // SHA-256 hash

    // Medium -> major
    expect(issues[1]?.severity).toBe("major");
    expect(issues[1]?.check_name).toBe("generic-api-key");
    expect(issues[1]?.location.path).toBe("config.env");
    expect(issues[1]?.location.lines.begin).toBe(2);
  });

  it("writes GitLab JSON to disk when outputPath is provided", async () => {
    const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "gitleak-gitlab-"));
    const reportFile = path.join(tempDir, "gl-code-quality-report.json");

    const result: ScanResult = {
      summary: { filesScanned: 1, linesScanned: 10, findings: 0, score: 100, tier: "Excellent", durationMs: 5 },
      findings: []
    };

    renderGitLabReport(result, reportFile);
    const content = await fs.readFile(reportFile, "utf-8");
    expect(JSON.parse(content)).toEqual([]);

    await fs.rm(tempDir, { recursive: true, force: true });
  });
});
