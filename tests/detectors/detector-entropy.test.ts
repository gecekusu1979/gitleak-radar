import { describe, it, expect } from "vitest";
import { SecretDetector } from "../../src/detectors/detector.js";
import { DETECTION_RULES } from "../../src/detectors/rules.js";

describe("Detector Entropy Validation", () => {
  const detector = new SecretDetector(DETECTION_RULES);

  it("ignores generic api key when entropy is too low (repetitive pattern)", () => {
    const line = 'const api_key = "abcdefabcdefabcdefabcdef";';
    const findings = detector.scanLine(line, 1, "config.ts");
    const genericFindings = findings.filter((f) => f.ruleId === "generic-api-key");
    expect(genericFindings.length).toBe(0);
  });

  it("ignores natural language variable assignment matching generic pattern", () => {
    // 32 karakter ama dogal dil (processUserAuthenticationRequest) -> base64 esiginin altinda
    const line = 'const api_key = "processUserAuthenticationRequest";';
    const findings = detector.scanLine(line, 1, "config.ts");
    const genericFindings = findings.filter((f) => f.ruleId === "generic-api-key");
    expect(genericFindings.length).toBe(0);
  });

  it("detects generic api key when entropy is high (random characters)", () => {
    const line = 'const api_key = "d8G3mK9qL2pZ0vW5xY7bN1cM4rT6uJ8y";';
    const findings = detector.scanLine(line, 1, "config.ts");
    const genericFindings = findings.filter((f) => f.ruleId === "generic-api-key");
    expect(genericFindings.length).toBe(1);
  });
});
