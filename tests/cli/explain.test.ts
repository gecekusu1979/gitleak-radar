import { describe, it, expect, vi } from "vitest";
import { explainRule } from "../../src/commands/explain.js";

describe("Rule Explainer (gitleak-radar explain)", () => {
  it("prints explanation and remediation steps for a built-in rule without throwing", async () => {
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    await explainRule("aws-access-key");
    
    expect(logSpy).toHaveBeenCalled();
    const calls = logSpy.mock.calls.map((c) => c.join(" ")).join("\n");
    expect(calls).toContain("AWS Access Key");
    expect(calls).toContain("Remediation Guidance");
    logSpy.mockRestore();
  });

  it("exits with status code 2 for nonexistent rule", async () => {
    const exitSpy = vi.spyOn(process, "exit").mockImplementation((() => {
      throw new Error("process.exit called");
    }) as any);
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});

    await expect(explainRule("nonexistent-rule-id-12345")).rejects.toThrow("process.exit called");
    expect(exitSpy).toHaveBeenCalledWith(2);

    exitSpy.mockRestore();
    errSpy.mockRestore();
  });
});
