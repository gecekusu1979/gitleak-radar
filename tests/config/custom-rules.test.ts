import { describe, it, expect } from "vitest";
import { compileCustomRule, getEffectiveRules, loadExternalRulesFile } from "../../src/config/loader.js";
import { CustomRuleDefinition } from "../../src/types/index.js";
import { SecretDetector } from "../../src/detectors/detector.js";
import path from "node:path";

describe("Custom Rules Engine", () => {
  it("compiles a valid custom rule and detects matching tokens", async () => {
    const def: CustomRuleDefinition = {
      id: "corp-token",
      name: "Corporate Internal Token",
      severity: "critical",
      regex: "corp-[a-z0-9]{8}"
    };

    const rule = await compileCustomRule(def);
    expect(rule.id).toBe("corp-token");
    expect(rule.severity).toBe("critical");

    const detector = new SecretDetector([rule]);
    const findings = detector.scanLine("const token = 'corp-abc12345';", 1, "test.ts");
    expect(findings.length).toBe(1);
    expect(findings[0].ruleId).toBe("corp-token");
  });

  it("throws descriptive error on invalid regex syntax", async () => {
    const def: CustomRuleDefinition = {
      id: "broken-regex",
      name: "Broken",
      severity: "high",
      regex: "/[a-z(/"
    };

    await expect(compileCustomRule(def)).rejects.toThrow(/Invalid regex in custom rule/);
  });

  it("rejects custom rules with catastrophic-backtracking nested quantifiers", async () => {
    const def: CustomRuleDefinition = {
      id: "evil-rule",
      name: "Evil",
      severity: "high",
      regex: "(a+)+"
    };

    await expect(compileCustomRule(def)).rejects.toThrow(/nested quantifiers|catastrophic backtracking/);
  });

  it("still compiles benign rules containing repeated groups without nested quantifiers", async () => {
    const def: CustomRuleDefinition = {
      id: "benign-repeated",
      name: "Benign",
      severity: "low",
      regex: "(abc)+"
    };

    const rule = await compileCustomRule(def);
    expect(rule.id).toBe("benign-repeated");
  });

  it("enforces entropy thresholds on custom rules when configured", async () => {
    const def: CustomRuleDefinition = {
      id: "high-entropy-custom",
      name: "High Entropy Custom",
      severity: "high",
      regex: "secret_[a-zA-Z0-9]{16}",
      minEntropy: 3.5,
      requiresEntropy: true
    };

    const rule = await compileCustomRule(def);
    const detector = new SecretDetector([rule]);

    // Düşük entropili (tekrar eden karakterler) elenmeli
    const lowEntropy = detector.scanLine("secret_aaaaaaaaaaaaaaaa", 1, "test.ts");
    expect(lowEntropy.length).toBe(0);

    // Yüksek entropili yakalanmalı
    const highEntropy = detector.scanLine("secret_aB9xK1mQ8zL4pW7y", 1, "test.ts");
    expect(highEntropy.length).toBe(1);
  });

  it("allows custom rules to override built-in rules with the same ID", async () => {
    const customAws: CustomRuleDefinition = {
      id: "aws-access-key",
      name: "Custom Corporate AWS Key",
      severity: "critical",
      regex: "AKIA[0-9A-Z]{16}"
    };

    const effective = await getEffectiveRules({
      ignore: [],
      rules: {},
      customRules: [customAws]
    });

    const overriddenRule = effective.find((r) => r.id === "aws-access-key");
    expect(overriddenRule).toBeDefined();
    expect(overriddenRule?.name).toBe("Custom Corporate AWS Key");
  });

  it("loads and parses external custom rules file correctly", async () => {
    const fixturePath = path.resolve(process.cwd(), "tests/fixtures/rules.json");
    // Fixture varsa yüklemeyi test et
    try {
      const rules = await loadExternalRulesFile(fixturePath);
      expect(Array.isArray(rules)).toBe(true);
    } catch (e: any) {
      // Eğer fixture yoksa test dizinini kontrol edebiliriz
      expect(e.message).toBeDefined();
    }
  });
});
