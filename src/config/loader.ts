import fs from "node:fs/promises";
import path from "node:path";
import { z } from "zod";
import { DETECTION_RULES } from "../detectors/rules.js";

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

export const ConfigSchema = z.object({
  ignore: z.array(z.string()).default([]),
  rules: z.record(z.enum(VALID_RULE_IDS), z.boolean()).default({})
});

export type RadarConfig = z.infer<typeof ConfigSchema>;

const DEFAULT_CONFIG: RadarConfig = {
  ignore: [],
  rules: {}
};

export async function loadConfig(targetDir: string): Promise<RadarConfig> {
  let currentDir = path.resolve(targetDir);

  while (true) {
    const configPath = path.join(currentDir, ".gitleak-radar.json");
    let raw: string;
    try {
      raw = await fs.readFile(configPath, "utf-8");
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
        `Invalid .gitleak-radar.json: ${issues}\nValid rule IDs: ${VALID_RULE_IDS.join(", ")}`
      );
    }

    for (const pattern of result.data.ignore) {
      validateGlobPattern(pattern);
    }

    return result.data;
  }
}
