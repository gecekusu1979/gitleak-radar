export const MAX_LINE_LENGTH = 8192;
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
    const visibleLength = Math.min(2, Math.floor(trimmed.length / 6));
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
    // ReDoS Koruması: Aşırı uzun minified satırlarda regex kilitlenmesini önle
    const targetLine = line.length > MAX_LINE_LENGTH ? line.slice(0, MAX_LINE_LENGTH) : line;
    const minRank = SeverityOrder[minSeverity];
    const lowerLine = targetLine.toLowerCase();

    for (const rule of this.rules) {
      if (SeverityOrder[rule.severity] < minRank) {
        continue;
      }

      // Keyword pre-filtering: Kuralda keyword tanımlıysa ve satırda hiçbiri yoksa regex'i atla
      if (rule.keywords && rule.keywords.length > 0) {
        const hasKeyword = rule.keywords.some((k) => lowerLine.includes(k.toLowerCase()));
        if (!hasKeyword) {
          continue;
        }
      }

      rule.pattern.lastIndex = 0;
      let match: RegExpExecArray | null;

      while ((match = rule.pattern.exec(targetLine)) !== null) {
        const rawSecret = match[1] ?? match[0];
        const index = match.index;

        if (isPlaceholderOrExample(rawSecret, targetLine, filePath)) {
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

