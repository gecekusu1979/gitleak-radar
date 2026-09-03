import fs from "node:fs/promises";
import path from "node:path";
import { z } from "zod";

export const ConfigSchema = z.object({
  ignore: z.array(z.string()).default([]),
  rules: z.record(z.string(), z.boolean()).default({})
});

export type RadarConfig = z.infer<typeof ConfigSchema>;

const DEFAULT_CONFIG: RadarConfig = {
  ignore: [],
  rules: {}
};

export async function loadConfig(targetDir: string): Promise<RadarConfig> {
  const configPath = path.resolve(targetDir, ".gitleak-radar.json");
  try {
    const raw = await fs.readFile(configPath, "utf-8");
    const parsed = JSON.parse(raw);
    return ConfigSchema.parse(parsed);
  } catch {
    return DEFAULT_CONFIG;
  }
}
