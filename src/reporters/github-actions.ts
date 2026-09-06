import { type Finding, type ScanResult } from "../types/index.js";

/**
 * GitHub Actions workflow komutları için özel karakterleri kaçış karakteriyle korur.
 */
function escapeProperty(value: string): string {
  return value
    .replace(/%/g, "%25")
    .replace(/\r/g, "%0D")
    .replace(/\n/g, "%0A")
    .replace(/:/g, "%3A")
    .replace(/,/g, "%2C");
}

function escapeData(value: string): string {
  return value
    .replace(/%/g, "%25")
    .replace(/\r/g, "%0D")
    .replace(/\n/g, "%0A");
}

export function formatFindingAnnotation(finding: Finding): string {
  const level = finding.severity === "critical" || finding.severity === "high" ? "error" : "warning";
  const file = escapeProperty(finding.file);
  const line = finding.line;
  const col = finding.column;
  const title = escapeProperty(`GitLeak Radar: ${finding.ruleName} [${finding.severity.toUpperCase()}]`);
  const message = escapeData(
    `Secret detected: ${finding.maskedValue} (${finding.ruleId}). Remove credential and revoke immediately.`
  );

  return `::${level} file=${file},line=${line},col=${col},title=${title}::${message}`;
}

export function renderGitHubActionsReport(result: ScanResult): void {
  for (const finding of result.findings) {
    console.log(formatFindingAnnotation(finding));
  }
}
