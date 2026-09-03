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
  keywords: z.array(z.string()).optional()
});

export type DetectionRule = z.infer<typeof DetectionRuleSchema>;

export interface Finding {
  ruleId: string;
  ruleName: string;
  severity: Severity;
  file: string;
  line: number;
  column: number;
  maskedValue: string;
}

export interface ScanOptions {
  path: string;
  severity?: Severity;
  json?: boolean;
  ignore?: string[];
  verbose?: boolean;
  staged?: boolean;
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
  };
  findings: Finding[];
}
