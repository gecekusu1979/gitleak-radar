import { z } from "zod";

export type Severity = "low" | "medium" | "high" | "critical";

export const SeverityOrder: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1
};

export const DetectionRuleSchema = z.object({
  id: z.string(),
  name: z.string(),
  description: z.string(),
  severity: z.enum(["low", "medium", "high", "critical"]),
  pattern: z.instanceof(RegExp),
  keywords: z.array(z.string()).optional(),
  minEntropy: z.number().optional(),
  requiresEntropy: z.boolean().optional()
});

export type DetectionRule = z.infer<typeof DetectionRuleSchema>;

export const CustomRuleSchema = z.object({
  id: z.string().min(1, "Rule ID cannot be empty"),
  name: z.string().min(1, "Rule Name cannot be empty"),
  description: z.string().default("Custom user-defined detection rule"),
  severity: z.enum(["low", "medium", "high", "critical"]).default("high"),
  regex: z.string().min(1, "Regex cannot be empty"),
  keywords: z.array(z.string()).optional(),
  minEntropy: z.number().optional(),
  requiresEntropy: z.boolean().optional()
});

export type CustomRuleDefinition = z.infer<typeof CustomRuleSchema>;

export interface Finding {
  ruleId: string;
  ruleName: string;
  severity: Severity;
  file: string;
  line: number;
  column: number;
  maskedValue: string;
  commit?: string;
  commitAuthor?: string;
  commitDate?: string;
}

export interface ScanOptions {
  path: string;
  severity?: Severity;
  json?: boolean;
  ignore?: string[];
  verbose?: boolean;
  staged?: boolean;
  history?: boolean;
  maxCommits?: number;
  rulesPath?: string;
  onFileAction?: (filePath: string, status: "scanned" | "ignored" | "binary") => void;
}

export type ScoreTier = "Excellent" | "Good" | "Warning" | "Critical";

export interface ScoreReport {
  score: number;
  tier: ScoreTier;
  counts: Record<Severity, number>;
}

export interface ScanResult {
  summary: {
    filesScanned: number;
    linesScanned: number;
    findings: number;
    score: number;
    tier: ScoreTier;
    durationMs: number;
    commitsScanned?: number;
  };
  findings: Finding[];
}
