import { ScanResult } from "../types/index.js";

export function renderJsonReport(result: ScanResult): void {
  const output = {
    summary: {
      filesScanned: result.summary.filesScanned,
      linesScanned: result.summary.linesScanned,
      findings: result.summary.findings,
      score: result.summary.score,
      tier: result.summary.tier,
      durationMs: result.summary.durationMs
    },
    findings: result.findings.map((f) => ({
      rule: f.ruleId,
      name: f.ruleName,
      severity: f.severity,
      file: f.file,
      line: f.line,
      column: f.column,
      maskedValue: f.maskedValue
    }))
  };

  console.log(JSON.stringify(output, null, 2));
}