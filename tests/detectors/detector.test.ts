import { describe, it, expect } from "vitest";
import { SecretDetector } from "../../src/detectors/detector.js";
import { DETECTION_RULES } from "../../src/detectors/rules.js";

describe("SecretDetector", () => {
  const detector = new SecretDetector(DETECTION_RULES);

  it("detects valid AWS access key structure and masks it safely", () => {
    const fakeKey = "AKIA" + "J7B2Z3K4L5M6N7P8";
    const line = `const awsKey = "${fakeKey}";`;
    const findings = detector.scanLine(line, 1, "config.ts");

    expect(findings.length).toBe(1);
    expect(findings[0]?.ruleId).toBe("aws-access-key");
    expect(findings[0]?.maskedValue).toBe("AKIA********N7P8");
    expect(findings[0]?.maskedValue).not.toContain("J7B2Z3K4");
  });

  it("ignores dummy/placeholder keys with false positive suppression", () => {
    const line = 'const aws = "AKIA_YOUR_API_KEY_HERE";';
    const findings = detector.scanLine(line, 1, "index.ts");
    expect(findings.length).toBe(0);
  });

  it("detects GitHub PAT formats", () => {
    const fakeGhp = "ghp_" + "1234567890abcdefghijklmnopqrstuvwxyz";
    const line = `const token = "${fakeGhp}";`;
    const findings = detector.scanLine(line, 10, "auth.ts");

    expect(findings.length).toBe(1);
    expect(findings[0]?.ruleId).toBe("github-pat");
  });

  it("detects Private Key block headers", () => {
    const line = "-----BEGIN RSA PRIVATE KEY-----";
    const findings = detector.scanLine(line, 1, "cert.pem");

    expect(findings.length).toBe(1);
    expect(findings[0]?.severity).toBe("critical");
  });

  it("ignores documentation examples in Markdown files", () => {
    const line = "Set your key like: api_key='YOUR_API_KEY_CHANGE_ME'";
    const findings = detector.scanLine(line, 5, "README.md");
    expect(findings.length).toBe(0);
  });
});
