import { describe, expect, it } from "vitest";
import crypto from "node:crypto";
import { SecretDetector } from "../../src/detectors/detector.js";
import { DETECTION_RULES } from "../../src/detectors/rules.js";

describe("recursive decoding and allowlist", () => {
  it("detects a Base64-encoded secret", () => {
    const detector = new SecretDetector(DETECTION_RULES);
    const encoded = Buffer.from("AKIAIOSFODNN7QAZWSXE").toString("base64");
    const findings = detector.scanLine(`encoded=${encoded}`, 1, "config.env");

    expect(findings.some((finding) => finding.ruleId === "aws-access-key")).toBe(true);
  });

  it("decodes through two layers", () => {
    const detector = new SecretDetector(DETECTION_RULES);
    const once = Buffer.from("AKIAIOSFODNN7QAZWSXE").toString("base64");
    const twice = Buffer.from(once).toString("base64");
    const findings = detector.scanLine(twice, 1, "config.env");

    expect(findings.some((finding) => finding.ruleId === "aws-access-key")).toBe(true);
  });

  it("detects URL-encoded secrets", () => {
    const detector = new SecretDetector(DETECTION_RULES);
    const encoded = "%41%4BIAIOSFODNN7QAZWSXE";
    const findings = detector.scanLine(`value=${encoded}`, 1, "config.env");

    expect(findings.some((finding) => finding.ruleId === "aws-access-key")).toBe(true);
  });

  it("suppresses an exact allowlist value and its fingerprint", () => {
    const secret = "AKIAIOSFODNN7QAZWSXE";
    const encoded = Buffer.from(secret).toString("base64");
    const fingerprint = crypto.createHash("sha256").update(secret).digest("hex");

    expect(new SecretDetector(DETECTION_RULES, [secret]).scanLine(secret, 1, "config.env")).toEqual([]);
    expect(new SecretDetector(DETECTION_RULES, [fingerprint]).scanLine(encoded, 1, "config.env")).toEqual([]);
  });

  it("does not decode arbitrary binary data", () => {
    const detector = new SecretDetector(DETECTION_RULES);
    expect(detector.scanLine("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 1, "config.env")).toEqual([]);
  });
});
