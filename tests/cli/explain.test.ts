import { describe, it, expect, vi } from "vitest";
import { explainRule } from "../../src/commands/explain.js";

describe("Rule Explainer (gitleak-radar explain)", () => {
  it("prints explanation and remediation steps for a built-in rule without throwing", async () => {
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => { });
    await explainRule("aws-access-key");

    expect(logSpy).toHaveBeenCalled();
    const calls = logSpy.mock.calls.map((c) => c.join(" ")).join("\n");
    expect(calls).toContain("AWS Access Key");
    expect(calls).toContain("Remediation Guidance");
    logSpy.mockRestore();
  });

  it("exits with status code 2 for nonexistent rule", async () => {
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => { });

    // Store original exit code to restore later to prevent test suite exit code contamination
    const originalExitCode = process.exitCode;

    await explainRule("nonexistent-rule-id-12345");
    expect(process.exitCode).toBe(2);

    process.exitCode = originalExitCode;
    errSpy.mockRestore();
  });
});
