import crypto from "node:crypto";
import { type DetectionRule, type Finding, type Severity, SeverityOrder } from "../types/index.js";
import { isPlaceholderOrExample } from "../scanner/file-filter.js";
import { calculateShannonEntropy, isHighEntropyToken } from "./entropy.js";
import { isLineIgnoredByDirective } from "./inline-ignore.js";
import { recursivelyDecodeLine } from "./decoder.js";

export const MAX_LINE_LENGTH = 8192;

export class SecretDetector {
  private rules: DetectionRule[];
  private allowlist: ReadonlySet<string>;

  constructor(rules: DetectionRule[], allowlist: string[] = []) {
    this.rules = rules;
    this.allowlist = new Set(allowlist.map((value) => value.trim()).filter(Boolean));
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
    minSeverity: Severity = "low",
    previousLine?: string
  ): Finding[] {
    const findings: Finding[] = [];
    const targetLine = line.length > MAX_LINE_LENGTH ? line.slice(0, MAX_LINE_LENGTH) : line;
    const lowerLine = targetLine.toLowerCase();
    const minSeverityWeight = SeverityOrder[minSeverity];

    if (isLineIgnoredByDirective(targetLine, previousLine)) {
      return [];
    }

    this.scanText(targetLine, lineNumber, filePath, minSeverity, previousLine, 0, 0, findings);

    for (const candidate of recursivelyDecodeLine(targetLine)) {
      this.scanText(candidate.text, lineNumber, filePath, minSeverity, undefined, candidate.offset, 0, findings);
    }

    return findings.filter((finding, index, all) =>
      all.findIndex((other) => other.ruleId === finding.ruleId && other.secretHash === finding.secretHash) === index
    );
  }

  private scanText(
    targetLine: string,
    lineNumber: number,
    filePath: string,
    minSeverity: Severity,
    previousLine: string | undefined,
    columnOffset: number,
    _depth: number,
    findings: Finding[]
  ): void {
    const lowerLine = targetLine.toLowerCase();
    const minSeverityWeight = SeverityOrder[minSeverity];

    for (const rule of this.rules) {
      if (SeverityOrder[rule.severity] < minSeverityWeight) {
        continue;
      }

      if (isLineIgnoredByDirective(targetLine, previousLine, rule.id)) {
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

        const secretHash = crypto.createHash("sha256").update(rawSecret).digest("hex");
        if (this.allowlist.has(rawSecret) || this.allowlist.has(secretHash)) {
          continue;
        }
        if (isPlaceholderOrExample(rawSecret, targetLine, filePath)) {
          continue;
        }

        // 1. Dinamik karakter kumesi tabanli entropi denetimi
        if (rule.requiresEntropy) {
          if (!isHighEntropyToken(rawSecret)) {
            continue;
          }
        }

        // 2. Kurala ozel tanimlanmis mutlak Shannon entropi esigi
        if (typeof rule.minEntropy === "number") {
          const tokenEntropy = calculateShannonEntropy(rawSecret);
          if (tokenEntropy < rule.minEntropy) {
            continue;
          }
        }

        const matchIndex = match.index;
        const secretSubIndex = match[0].indexOf(rawSecret);
        const column = columnOffset + matchIndex + (secretSubIndex !== -1 ? secretSubIndex : 0) + 1;

        findings.push({
          ruleId: rule.id,
          ruleName: rule.name,
          severity: rule.severity,
          file: filePath,
          line: lineNumber,
          column,
          maskedValue: this.mask(rawSecret),
          secretHash
        });

        if (!rule.pattern.global) {
          break;
        }
      }
    }

  }
}
