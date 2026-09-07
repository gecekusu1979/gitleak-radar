import { runRegexWithTimeout } from "../detectors/regex-runner.js";
import fs from "node:fs/promises";
import path from "node:path";
import { z } from "zod";
import { DETECTION_RULES } from "../detectors/rules.js";
import { CustomRuleSchema, type CustomRuleDefinition, type DetectionRule } from "../types/index.js";

const VALID_RULE_IDS = DETECTION_RULES.map((r) => r.id) as [string, ...string[]];

function validateGlobPattern(pattern: string): void {
  let bracketCount = 0;
  for (let i = 0; i < pattern.length; i++) {
    const char = pattern[i];
    if (char === "[") {
      bracketCount++;
    } else if (char === "]") {
      bracketCount--;
      if (bracketCount < 0) {
        throw new Error(`Invalid glob pattern in .gitleak-radar.json ignore list: "${pattern}"`);
      }
    }
  }
  if (bracketCount !== 0) {
    throw new Error(`Invalid glob pattern in .gitleak-radar.json ignore list: "${pattern}"`);
  }

  let braceCount = 0;
  for (let i = 0; i < pattern.length; i++) {
    const char = pattern[i];
    if (char === "{") {
      braceCount++;
    } else if (char === "}") {
      braceCount--;
      if (braceCount < 0) {
        throw new Error(`Invalid glob pattern in .gitleak-radar.json ignore list: "${pattern}"`);
      }
    }
  }
  if (braceCount !== 0) {
    throw new Error(`Invalid glob pattern in .gitleak-radar.json ignore list: "${pattern}"`);
  }
}

const REDOS_NESTED_QUANTIFIER = /\([^()]*[+*][^()]*\)[+*]/;

function assertRegexIsSafe(source: string, ruleId: string): void {
  if (REDOS_NESTED_QUANTIFIER.test(source)) {
    throw new Error(
      `Custom rule "${ruleId}" rejected: Regex contains dangerous nested quantifiers (e.g., (a+)+) susceptible to catastrophic backtracking (ReDoS). Simplify the pattern.`
    );
  }
}

export async function validateCustomRegexWorker(pattern: string, flags: string, ruleId: string): Promise<void> {
  // Backtracking tetikleyecek tipik evil payload ile worker-thread timeout kontrolü
  const probePayload = "a".repeat(40) + "!";
  try {
    await runRegexWithTimeout(pattern, flags, probePayload, 250);
  } catch (err: any) {
    if (err.message && err.message.includes("ReDoS protection")) {
      throw new Error(`Custom rule "${ruleId}" rejected: Execution exceeded 250ms timeout during ReDoS safety check.`);
    }
  }
}

export async function compileCustomRule(def: CustomRuleDefinition): Promise<DetectionRule> {
  let pattern: RegExp;
  let rawPattern: string;
  let flags: string;

  try {
    const slashMatch = def.regex.match(/^\/(.+)\/([a-z]*)$/i);
    if (slashMatch && slashMatch[1]) {
      rawPattern = slashMatch[1];
      flags = slashMatch[2]?.includes("g") ? slashMatch[2] : (slashMatch[2] || "") + "g";
    } else {
      rawPattern = def.regex;
      flags = "g";
    }

    assertRegexIsSafe(rawPattern, def.id);
    await validateCustomRegexWorker(rawPattern, flags, def.id);
    pattern = new RegExp(rawPattern, flags);
  } catch (err: any) {
    throw new Error(`Invalid regex in custom rule "${def.id}": ${err.message}`);
  }

  return {
    id: def.id,
    name: def.name,
    description: def.description,
    severity: def.severity,
    pattern,
    keywords: def.keywords && def.keywords.length > 0 ? def.keywords : undefined,
    minEntropy: def.minEntropy,
    requiresEntropy: def.requiresEntropy ?? (typeof def.minEntropy === "number")
  };
}

export const ConfigSchema = z.object({
  ignore: z.array(z.string()).default([]),
  rules: z.record(z.enum(VALID_RULE_IDS), z.boolean()).default({}),
  customRules: z.array(CustomRuleSchema).default([]),
  maxFileSize: z.union([z.string(), z.number()]).optional()
});

export type RadarConfig = z.infer<typeof ConfigSchema>;

const DEFAULT_CONFIG: RadarConfig = {
  ignore: [],
  rules: {},
  customRules: []
};

export async function loadExternalRulesFile(filePath: string): Promise<DetectionRule[]> {
  const resolved = path.resolve(process.cwd(), filePath);
  let raw: string;
  try {
    raw = (await fs.readFile(resolved, "utf-8")).replace(/^\uFEFF/, "");
  } catch (err: any) {
    throw new Error(`Failed to read rules file at "${filePath}": ${err.message}`);
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err: any) {
    throw new Error(`Invalid JSON in rules file "${filePath}": ${err.message}`);
  }

  let ruleDefs: CustomRuleDefinition[] = [];
  if (Array.isArray(parsed)) {
    const arraySchema = z.array(CustomRuleSchema);
    const parsedArray = arraySchema.safeParse(parsed);
    if (!parsedArray.success) {
      const issues = parsedArray.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; ");
      throw new Error(`Validation error in rules file "${filePath}": ${issues}`);
    }
    ruleDefs = parsedArray.data;
  } else if (parsed && typeof parsed === "object") {
    const obj = parsed as Record<string, unknown>;
    const targetArray = obj.customRules ?? obj.rules;
    if (Array.isArray(targetArray)) {
      const arraySchema = z.array(CustomRuleSchema);
      const parsedArray = arraySchema.safeParse(targetArray);
      if (!parsedArray.success) {
        const issues = parsedArray.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; ");
        throw new Error(`Validation error in rules file "${filePath}": ${issues}`);
      }
      ruleDefs = parsedArray.data;
    } else {
      throw new Error(`Rules file "${filePath}" must contain a JSON array of rules or a "customRules" property.`);
    }
  } else {
    throw new Error(`Rules file "${filePath}" must contain a JSON array or object.`);
  }

  return Promise.all(ruleDefs.map(compileCustomRule));
}

export async function loadConfig(targetDir: string): Promise<RadarConfig> {
  let currentDir = path.resolve(targetDir);

  while (true) {
    const configPath = path.join(currentDir, ".gitleak-radar.json");
    let raw: string;
    try {
      raw = (await fs.readFile(configPath, "utf-8")).replace(/^\uFEFF/, "");
    } catch (err: any) {
      if (err?.code === "ENOENT") {
        const parent = path.dirname(currentDir);
        if (parent === currentDir) {
          return DEFAULT_CONFIG;
        }
        currentDir = parent;
        continue;
      }
      throw err;
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch (err: any) {
      throw new Error(`Invalid .gitleak-radar.json: Malformed JSON (${err.message})`);
    }

    const result = ConfigSchema.safeParse(parsed);
    if (!result.success) {
      const issues = result.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; ");
      throw new Error(
        `Invalid .gitleak-radar.json: ${issues}\nValid built-in rule IDs: ${VALID_RULE_IDS.join(", ")}`
      );
    }

    for (const pattern of result.data.ignore) {
      validateGlobPattern(pattern);
    }

    return result.data;
  }
}

export async function getEffectiveRules(config: RadarConfig, extraRules: DetectionRule[] = []): Promise<DetectionRule[]> {
  const ruleMap = new Map<string, DetectionRule>();

  // 1. Yerleşik kuralları temel olarak ekle
  for (const rule of DETECTION_RULES) {
    ruleMap.set(rule.id, rule);
  }

  // 2. Config customRules kuralları yerleşik kuralların üzerine yazar (override)
  const configCustomRules = await Promise.all((config.customRules || []).map(compileCustomRule));
  for (const rule of configCustomRules) {
    ruleMap.set(rule.id, rule);
  }

  // 3. CLI/harici dosya kuralları en yüksek öncelikle üzerine yazar
  for (const rule of extraRules) {
    ruleMap.set(rule.id, rule);
  }

  // 4. config.rules ile devre dışı bırakılanları filtrele
  return Array.from(ruleMap.values()).filter((rule) => {
    if (config.rules && config.rules[rule.id] !== undefined) {
      return config.rules[rule.id];
    }
    return true;
  });
}
