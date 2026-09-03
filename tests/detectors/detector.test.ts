import { describe, it, expect } from "vitest";
import { SecretDetector } from "../../src/detectors/detector.js";
import { DETECTION_RULES } from "../../src/detectors/rules.js";

describe("SecretDetector - Rules & Masking", () => {
  const detector = new SecretDetector(DETECTION_RULES);

  it("detects AWS Access Key pattern", () => {
    const line = "aws_access_key_id = AKIAIOSFODNN7QAZWSXE";
    const findings = detector.scanLine(line, 1, "config.js", "low");
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0]?.ruleId).toBe("aws-access-key");
  });

  it("detects JWT token format", () => {
    const line = "const auth = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.fakeSignaturePartHere1234567890';";
    const findings = detector.scanLine(line, 1, "auth.ts", "low");
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0]?.ruleId).toBe("jwt");
  });

  it("detects PostgreSQL connection string via db-connection-string rule", () => {
    const line = "const db = 'postgres://dbuser:mockSecretPass99@db.internal:5432/appdb';";
    const findings = detector.scanLine(line, 1, "db.ts", "low");
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0]?.ruleId).toBe("db-connection-string");
  });

  it("detects MongoDB connection string via db-connection-string rule", () => {
    const line = "const mongo = 'mongodb://fakeAdmin:fakeSecretPass123@cluster0.example.mongodb.net/test';";
    const findings = detector.scanLine(line, 1, "mongo.ts", "low");
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0]?.ruleId).toBe("db-connection-string");
  });

  it("detects Private Key block headers", () => {
    const line = "-----BEGIN RSA PRIVATE KEY-----";
    const findings = detector.scanLine(line, 1, "server.key", "low");
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0]?.ruleId).toBe("private-key");
  });

  it("safely masks secret values", () => {
    const line = "postgres://admin:superSecretPassword123@localhost:5432/db";
    const findings = detector.scanLine(line, 1, "index.ts", "low");
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0]?.maskedValue).toContain("****");
    expect(findings[0]?.maskedValue).not.toContain("superSecretPassword123");
  });

  it("ignores dummy placeholder and template tokens", () => {
    const line = "const key = 'AKIA_YOUR_API_KEY_HERE';";
    const findings = detector.scanLine(line, 1, "readme.md", "low");
    expect(findings.length).toBe(0);
  });
});
