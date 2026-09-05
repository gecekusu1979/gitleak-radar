import { describe, it, expect } from "vitest";
import { compileCustomRule, getEffectiveRules, loadExternalRulesFile } from "../../src/config/loader.js";
import { SecretDetector } from "../../src/detectors/detector.js";
import { type CustomRuleDefinition } from "../../src/types/index.js";
import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";

describe("Custom Rules Engine", () => {
  it("compiles a valid custom rule and detects matching tokens", () => {
    const def: CustomRuleDefinition = {
      id: "corp-token",
      name: "Corporate Secret Token",
      description: "Detects company private token",
      severity: "critical",
      regex: "CORP_[A-Z0-9]{16}",
      keywords: ["corp_"]
    };

    const rule = compileCustomRule(def);
    expect(rule.id).toBe("corp-token");
    expect(rule.severity).toBe("critical");

    const detector = new SecretDetector([rule]);
    const findings = detector.scanLine("const key = 'CORP_ABC123XYZ7890123';", 1, "config.ts");

    expect(findings).toHaveLength(1);
    expect(findings[0]?.ruleId).toBe("corp-token");
    expect(findings[0]?.severity).toBe("critical");
  });

  it("throws descriptive error on invalid regex syntax", () => {
    const def: CustomRuleDefinition = {
      id: "broken-regex",
      name: "Broken Regex",
      description: "Invalid regex test",
      severity: "high",
      regex: "[a-z(" // unclosed group
    };

    expect(() => compileCustomRule(def)).toThrowError(/Invalid regex in custom rule/);
  });

  it("rejects custom rules with catastrophic-backtracking nested quantifiers", () => {
    const def: CustomRuleDefinition = {
      id: "evil-rule",
      name: "Suspicious Token",
      description: "Nested quantifier ReDoS pattern",
      severity: "high",
      regex: "(a+)+$"
    };

    expect(() => compileCustomRule(def)).toThrowError(/nested quantifiers|catastrophic backtracking/i);
  });

  it("still compiles benign rules containing repeated groups without nested quantifiers", () => {
    const def: CustomRuleDefinition = {
      id: "benign-repeat",
      name: "Benign repeated group",
      description: "Non-catastrophic pattern",
      severity: "low",
      regex: "(ab)+cd"
    };

    expect(() => compileCustomRule(def)).not.toThrow();
  });

  it("enforces entropy thresholds on custom rules when configured", () => {
    const def: CustomRuleDefinition = {
      id: "entropy-token",
      name: "High Entropy Token",
      description: "Must meet min entropy",
      severity: "high",
      regex: "SECRET_[a-zA-Z0-9]{16}",
      minEntropy: 3.2
    };

    const rule = compileCustomRule(def);
    const detector = new SecretDetector([rule]);

    const lowEntropy = detector.scanLine("SECRET_AAAAAAAAAAAAAAAA", 1, "dummy.ts");
    expect(lowEntropy).toHaveLength(0);

    const highEntropy = detector.scanLine("SECRET_a8K9zX1mQ2wE4rTy", 1, "dummy.ts");
    expect(highEntropy).toHaveLength(1);
  });

  it("loads and parses external custom rules file correctly", async () => {
    const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "gitleak-custom-rules-"));
    const rulesFile = path.join(tempDir, "rules.json");

    await fs.writeFile(
      rulesFile,
      JSON.stringify([
        {
          id: "external-key",
          name: "External Vendor Key",
          severity: "medium",
          regex: "EXT_[0-9]{8}"
        }
      ]),
      "utf-8"
    );

    const rules = await loadExternalRulesFile(rulesFile);
    expect(rules).toHaveLength(1);
    expect(rules[0]?.id).toBe("external-key");

    await fs.rm(tempDir, { recursive: true, force: true });
  });
});
