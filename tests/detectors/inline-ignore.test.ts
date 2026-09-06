import { describe, it, expect } from "vitest";
import { SecretDetector } from "../../src/detectors/detector.js";
import { DETECTION_RULES } from "../../src/detectors/rules.js";

const MOCK_STRIPE = ["sk", "live", "abcdef1234567890abcdef1234"].join("_");

describe("Inline Ignore Comments (// gitleak-radar:ignore)", () => {
  const detector = new SecretDetector(DETECTION_RULES);

  it("suppresses secret on the same line with // gitleak-radar:ignore", () => {
    const line = `const key = "${MOCK_STRIPE}"; // gitleak-radar:ignore`;
    const findings = detector.scanLine(line, 1, "test.ts");
    expect(findings).toHaveLength(0);
  });

  it("suppresses secret with hash syntax in python or yaml (# gitleak-radar:ignore)", () => {
    const line = `STRIPE_KEY = "${MOCK_STRIPE}" # gitleak-radar:ignore`;
    const findings = detector.scanLine(line, 1, "config.py");
    expect(findings).toHaveLength(0);
  });

  it("suppresses secret on next line with // gitleak-radar:ignore-next-line", () => {
    const prevLine = "// gitleak-radar:ignore-next-line";
    const line = `const key = "${MOCK_STRIPE}";`;
    const findings = detector.scanLine(line, 2, "test.ts", "low", prevLine);
    expect(findings).toHaveLength(0);
  });

  it("suppresses only the targeted rule ID when specified", () => {
    const line = `const key = "${MOCK_STRIPE}"; // gitleak-radar:ignore stripe-api-key`;
    const findings = detector.scanLine(line, 1, "test.ts");
    expect(findings).toHaveLength(0);
  });

  it("does not suppress if targeted rule ID does not match", () => {
    const line = `const key = "${MOCK_STRIPE}"; // gitleak-radar:ignore aws-access-key`;
    const findings = detector.scanLine(line, 1, "test.ts");
    expect(findings).toHaveLength(1);
    expect(findings[0]!.ruleId).toBe("stripe-api-key");
  });
});
