import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { type Finding, type ScanResult, type Severity } from "../types/index.js";

export type GitLabSeverity = "blocker" | "critical" | "major" | "minor" | "info";

export interface GitLabCodeQualityIssue {
  description: string;
  check_name: string;
  fingerprint: string;
  severity: GitLabSeverity;
  location: {
    path: string;
    lines: {
      begin: number;
    };
  };
}

function mapToGitLabSeverity(severity: Severity): GitLabSeverity {
  switch (severity) {
    case "critical":
      return "blocker";
    case "high":
      return "critical";
    case "medium":
      return "major";
    case "low":
      return "minor";
  }
}

export function generateGitLabReport(result: ScanResult): GitLabCodeQualityIssue[] {
  return result.findings.map((finding) => {
    const rawFingerprint = `${finding.file}:${finding.line}:${finding.column}:${finding.ruleId}:${finding.maskedValue}`;
    const fingerprint = crypto.createHash("sha256").update(rawFingerprint).digest("hex");

    return {
      description: `[${finding.severity.toUpperCase()}] ${finding.ruleName}: Secret detected (${finding.maskedValue}). Revoke immediately.`,
      check_name: finding.ruleId,
      fingerprint,
      severity: mapToGitLabSeverity(finding.severity),
      location: {
        path: finding.file.replace(/\\/g, "/"),
        lines: {
          begin: finding.line
        }
      }
    };
  });
}

export function renderGitLabReport(result: ScanResult, outputPath?: string): void {
  const issues = generateGitLabReport(result);
  const jsonOutput = JSON.stringify(issues, null, 2);

  if (outputPath) {
    const resolvedPath = path.resolve(process.cwd(), outputPath);
    fs.mkdirSync(path.dirname(resolvedPath), { recursive: true });
    fs.writeFileSync(resolvedPath, jsonOutput + "\n", "utf-8");
  } else {
    console.log(jsonOutput);
  }
}
