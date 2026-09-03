import { DetectionRule, Finding, Severity, SeverityOrder } from "../types/index.js";
import { isPlaceholderOrExample } from "../scanner/file-filter.js";

export class SecretDetector {
  private rules: DetectionRule[];

  constructor(rules: DetectionRule[]) {
    this.rules = rules;
  }

  public mask(value: string): string {
    const trimmed = value.trim();
    if (trimmed.length <= 8) {
      return "********";
    }
    const visibleLength = Math.min(4, Math.floor(trimmed.length / 4));
    const prefix = trimmed.slice(0, visibleLength);
    const suffix = trimmed.slice(-visibleLength);
    return `${prefix}********${suffix}`;
  }

  public scanLine(
    line: string,
    lineNumber: number,
    filePath: string,
    minSeverity: Severity = "low"
  ): Finding[] {
    const findings: Finding[] = [];
    const minRank = SeverityOrder[minSeverity];

    for (const rule of this.rules) {
      if (SeverityOrder[rule.severity] < minRank) {
        continue;
      }

      rule.pattern.lastIndex = 0;
      let match: RegExpExecArray | null;

      while ((match = rule.pattern.exec(line)) !== null) {
        const rawSecret = match[1] ?? match[0];
        const index = match.index;

        if (isPlaceholderOrExample(rawSecret, line, filePath)) {
          continue;
        }

        findings.push({
          ruleId: rule.id,
          ruleName: rule.name,
          severity: rule.severity,
          file: filePath,
          line: lineNumber,
          column: index + 1,
          maskedValue: this.mask(rawSecret)
        });
      }
    }

    return findings;
  }
}
