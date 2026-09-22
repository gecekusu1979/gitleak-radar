import crypto from "node:crypto";
import { type DetectionRule, type Finding, type Severity, SeverityOrder } from "../types/index.js";
import { isPlaceholderOrExample } from "../scanner/file-filter.js";
import { calculateShannonEntropy, isHighEntropyToken } from "./entropy.js";
import { isLineIgnoredByDirective } from "./inline-ignore.js";
import { recursivelyDecodeLine, DEFAULT_MAX_DECODE_DEPTH } from "./decoder.js";

export const MAX_LINE_LENGTH = 8192;

export class SecretDetector {
  private rules: DetectionRule[];
  private allowlist: ReadonlySet<string>;
  private maxDecodeDepth: number;

  constructor(rules: DetectionRule[], allowlist: string[] = [], maxDecodeDepth: number = DEFAULT_MAX_DECODE_DEPTH) {
    this.rules = rules;
    this.allowlist = new Set(allowlist.map((value) => value.trim()).filter(Boolean));
    this.maxDecodeDepth = maxDecodeDepth;
  }

  public mask(secret: string): string {
    if (secret.length <= 4) {
      return "*".repeat(secret.length);
    }
    const prefix = secret.slice(0, 2);
    const suffix = secret.slice(-2);
    return `${prefix}${"*".repeat(secret.length - 4)}${suffix}`;
  }

  private isAllowlisted(secret: string): boolean {
    if (this.allowlist.size === 0) return false;
    if (this.allowlist.has(secret)) return true;
    const hash = crypto.createHash("sha256").update(secret).digest("hex");
    return this.allowlist.has(hash);
  }

  private scanText(
    text: string,
    lineNumber: number,
    filePath: string,
    minSeverity: Severity,
    previousLine: string | undefined,
    colOffset: number,
    findings: Finding[]
  ): void {
    const lowerText = text.toLowerCase();
    const minSeverityWeight = SeverityOrder[minSeverity];

    for (const rule of this.rules) {
      if (SeverityOrder[rule.severity] < minSeverityWeight) {
        continue;
      }

      if (isLineIgnoredByDirective(text, previousLine, rule.id)) {
        continue;
      }

      if (rule.keywords && rule.keywords.length > 0) {
        const matchesKeyword = rule.keywords.some((kw) => lowerText.includes(kw.toLowerCase()));
        if (!matchesKeyword) {
          continue;
        }
      }

      rule.pattern.lastIndex = 0;
      let match: RegExpExecArray | null;

      while ((match = rule.pattern.exec(text)) !== null) {
        const rawSecret = match[1] || match[0];

        if (isPlaceholderOrExample(rawSecret, text, filePath)) {
          continue;
        }

        if (this.isAllowlisted(rawSecret)) {
          continue;
        }

        if (rule.requiresEntropy) {
          if (!isHighEntropyToken(rawSecret)) {
            continue;
          }
        }

        if (typeof rule.minEntropy === "number") {
          const tokenEntropy = calculateShannonEntropy(rawSecret);
          if (tokenEntropy < rule.minEntropy) {
            continue;
          }
        }

        const matchIndex = match.index;
        const secretSubIndex = match[0].indexOf(rawSecret);
        const column = colOffset + matchIndex + (secretSubIndex !== -1 ? secretSubIndex : 0) + 1;

        findings.push({
          ruleId: rule.id,
          ruleName: rule.name,
          severity: rule.severity,
          file: filePath,
          line: lineNumber,
          column,
          maskedValue: this.mask(rawSecret),
          secretHash: crypto.createHash("sha256").update(rawSecret).digest("hex")
        });

        if (!rule.pattern.global) {
          break;
        }
      }
    }
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

    if (isLineIgnoredByDirective(targetLine, previousLine)) {
      return [];
    }

    // Doğrudan tarama
    this.scanText(targetLine, lineNumber, filePath, minSeverity, previousLine, 0, findings);

    // Encode edilmiş içerikleri çözerek tarama
    for (const candidate of recursivelyDecodeLine(targetLine, this.maxDecodeDepth)) {
      this.scanText(candidate.text, lineNumber, filePath, minSeverity, undefined, candidate.offset, findings);
    }

    return findings;
  }
}
