import { describe, it, expect } from "vitest";
import { runRegexWithTimeout } from "../../src/detectors/regex-runner.js";

describe("Safe Regex Runner (Worker-thread ReDoS Guard)", () => {
  it("executes standard non-catastrophic regex normally", async () => {
    const result = await runRegexWithTimeout("AKIA[0-9A-Z]{16}", "g", "token AKIA1234567890ABCDEF here");
    expect(result.matched).toBe(true);
    expect(result.matches[0]?.value).toBe("AKIA1234567890ABCDEF");
  });

  it("terminates and rejects catastrophic backtracking ReDoS pattern exceeding timeout", async () => {
    const evilPattern = "(a+)+$";
    const evilText = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaX";

    await expect(
      runRegexWithTimeout(evilPattern, "g", evilText, 100)
    ).rejects.toThrow("ReDoS protection");
  }, 10000);
});
