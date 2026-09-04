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

  it("detects JWT token format with high severity", () => {
    const line = "const auth = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.fakeSignaturePartHere1234567890';";
    const findings = detector.scanLine(line, 1, "auth.ts", "low");
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0]?.ruleId).toBe("jwt");
    expect(findings[0]?.severity).toBe("high");
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

  it("detects unquoted API_KEY in .env format", () => {
    const line = "API_KEY=prod_api_token_abcdef1234567890abcdef";
    const findings = detector.scanLine(line, 1, ".env", "low");
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0]?.ruleId).toBe("generic-api-key");
  });

  it("detects unquoted DB_PASSWORD in .env format with comment", () => {
    const line = "DB_PASSWORD=SuperSecretPass123456 # database password";
    const findings = detector.scanLine(line, 1, ".env", "low");
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0]?.ruleId).toBe("generic-password");
  });

  it("maintains quoted generic secret detection", () => {
    const apiKeyLine = 'API_KEY="prod_api_token_abcdef1234567890abcdef"';
    const passLine = "DB_PASSWORD='SuperSecretPass123456'";
    expect(detector.scanLine(apiKeyLine, 1, "config.ts", "low").length).toBeGreaterThan(0);
    expect(detector.scanLine(passLine, 1, "config.ts", "low").length).toBeGreaterThan(0);
  });

  it("detects gho_ and ghs_ GitHub tokens", () => {
    const gho = "gho_123456789012345678901234567890123456";
    const ghs = "ghs_123456789012345678901234567890123456";
    const fGho = detector.scanLine(`token = "${gho}"`, 1, "app.ts", "low");
    const fGhs = detector.scanLine(`token = "${ghs}"`, 1, "app.ts", "low");
    expect(fGho.length).toBeGreaterThan(0);
    expect(fGho[0]?.ruleId).toBe("github-pat");
    expect(fGhs.length).toBeGreaterThan(0);
    expect(fGhs[0]?.ruleId).toBe("github-pat");
  });

  it("rejects short generic bearer tokens and detects valid 20+ char tokens", () => {
    const shortLine = "Authorization: Bearer shorttoken123";
    const validLine = "Authorization: Bearer abcdef1234567890abcdef12";
    expect(detector.scanLine(shortLine, 1, "req.ts", "low").length).toBe(0);
    const validFindings = detector.scanLine(validLine, 1, "req.ts", "low");
    expect(validFindings.length).toBeGreaterThan(0);
    expect(validFindings[0]?.ruleId).toBe("generic-bearer-token");
  });

  it("masks 12-character secrets with at most 2 visible chars at boundaries", () => {
    const secret = "abcdef123456"; // 12 karakter
    const masked = detector.mask(secret);
    expect(masked.startsWith("ab")).toBe(true);
    expect(masked.endsWith("56")).toBe(true);
    expect(masked).toBe("ab********56");
  });

  it("skips regex evaluation when keyword prefilter does not match", () => {
    let regexExecuted = false;
    const customRule = {
      id: "custom-test-rule",
      name: "Custom Test Rule",
      description: "Testing prefilter",
      severity: "high" as const,
      keywords: ["secret_token_marker"],
      pattern: {
        get lastIndex() { return 0; },
        set lastIndex(_) {},
        exec: () => {
          regexExecuted = true;
          return null;
        }
      } as unknown as RegExp
    };

    const detector = new SecretDetector([customRule]);

    // 1. Keyword içermeyen satırda regex hiç tetiklenmemeli
    detector.scanLine("normal line with no matching token", 1, "test.js");
    expect(regexExecuted).toBe(false);

    // 2. Keyword içeren satırda regex tetiklenmeli
    detector.scanLine("contains SECRET_TOKEN_MARKER here", 2, "test.js");
    expect(regexExecuted).toBe(true);
  });
});
