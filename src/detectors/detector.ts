import { type DetectionRule, type Finding, type Severity, SeverityOrder } from "../types/index.js";
import { isPlaceholderOrExample } from "../scanner/file-filter.js";
import { calculateShannonEntropy, isHighEntropyToken } from "./entropy.js";

export const MAX_LINE_LENGTH = 8192;

export class SecretDetector {
  private rules: DetectionRule[];

  constructor(rules: DetectionRule[]) {
    this.rules = rules;
  }

  public mask(secret: string): string {
    if (secret.length <= 4) {
      return "*".repeat(secret.length);
    }
    const prefix = secret.slice(0, 2);
    const suffix = secret.slice(-2);
    return `${prefix}${"*".repeat(secret.length - 4)}${suffix}`;
  }

  public scanLine(
    line: string,
    lineNumber: number,
    filePath: string,
    minSeverity: Severity = "low"
  ): Finding[] {
    const findings: Finding[] = [];
    const targetLine = line.length > MAX_LINE_LENGTH ? line.slice(0, MAX_LINE_LENGTH) : line;
    const lowerLine = targetLine.toLowerCase();
    const minSeverityWeight = SeverityOrder[minSeverity];

    for (const rule of this.rules) {
      if (SeverityOrder[rule.severity] < minSeverityWeight) {
        continue;
      }

      if (rule.keywords && rule.keywords.length > 0) {
        const matchesKeyword = rule.keywords.some((kw) => lowerLine.includes(kw.toLowerCase()));
        if (!matchesKeyword) {
          continue;
        }
      }

      rule.pattern.lastIndex = 0;
      let match: RegExpExecArray | null;

      while ((match = rule.pattern.exec(targetLine)) !== null) {
        const rawSecret = match[1] || match[0];

        if (isPlaceholderOrExample(rawSecret, targetLine, filePath)) {
          continue;
        }

        if (rule.requiresEntropy || typeof rule.minEntropy === "number") {
          const tokenEntropy = calculateShannonEntropy(rawSecret);
          const minThreshold = typeof rule.minEntropy === "number" ? rule.minEntropy : 3.0;
          if (tokenEntropy < minThreshold) {
            continue;
          }
        }

        const matchIndex = match.index;
        const secretSubIndex = match[0].indexOf(rawSecret);
        const column = matchIndex + (secretSubIndex !== -1 ? secretSubIndex : 0) + 1;

        findings.push({
          ruleId: rule.id,
          ruleName: rule.name,
          severity: rule.severity,
          file: filePath,
          line: lineNumber,
          column,
          maskedValue: this.mask(rawSecret)
        });

        if (!rule.pattern.global) {
          break;
        }
      }
    }

    return findings;
  }
}
