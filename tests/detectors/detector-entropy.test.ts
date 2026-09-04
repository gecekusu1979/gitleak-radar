import { describe, it, expect } from "vitest";
import { SecretDetector } from "../../src/detectors/detector.js";
import { DETECTION_RULES } from "../../src/detectors/rules.js";

describe("Detector Entropy Validation", () => {
  const detector = new SecretDetector(DETECTION_RULES);

  it("ignores generic api key when entropy is too low (repetitive pattern)", () => {
    // 24 karakter ama sadece 'abcdef' tekrarı -> düşük entropi
    const line = 'const api_key = "abcdefabcdefabcdefabcdef";';
    const findings = detector.scanLine(line, 1, "config.ts");
    const genericFindings = findings.filter((f) => f.ruleId === "generic-api-key");
    expect(genericFindings.length).toBe(0);
  });

  it("detects generic api key when entropy is high (random characters)", () => {
    // 32 karakterlik rastgele hex/base64 token -> yüksek entropi (> 3.5)
    const line = 'const api_key = "d8G3mK9qL2pZ0vW5xY7bN1cM4rT6uJ8y";';
    const findings = detector.scanLine(line, 1, "config.ts");
    const genericFindings = findings.filter((f) => f.ruleId === "generic-api-key");
    expect(genericFindings.length).toBe(1);
  });
});
