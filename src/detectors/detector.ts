import crypto from "node:crypto";
import { type DetectionRule, type Finding, type Severity, SeverityOrder } from "../types/index.js";
import { isPlaceholderOrExample } from "../scanner/file-filter.js";
import { calculateShannonEntropy, isHighEntropyToken } from "./entropy.js";
import { isLineIgnoredByDirective } from "./inline-ignore.js";
import { recursivelyDecodeLine, DEFAULT_MAX_DECODE_DEPTH } from "./decoder.js";
import { AhoCorasick } from "./aho-corasick.js";

export const MAX_LINE_LENGTH = 65536;

export class SecretDetector {
  private rules: DetectionRule[];
  private allowlist: ReadonlySet<string>;
  private maxDecodeDepth: number;
  private ahoCorasick: AhoCorasick | null = null;
  private hasRulesWithoutKeywords: boolean = false;

  constructor(rules: DetectionRule[], allowlist: string[] = [], maxDecodeDepth: number = DEFAULT_MAX_DECODE_DEPTH) {
    this.rules = rules;
    this.allowlist = new Set(allowlist.map((value) => value.trim()).filter(Boolean));
    this.maxDecodeDepth = maxDecodeDepth;

    const allKeywords = new Set<string>();
    for (const rule of rules) {
      if (rule.keywords && rule.keywords.length > 0) {
        for (const kw of rule.keywords) {
          allKeywords.add(kw.toLowerCase());
        }
      } else {
        this.hasRulesWithoutKeywords = true;
      }
    }
    if (allKeywords.size > 0) {
      this.ahoCorasick = new AhoCorasick(Array.from(allKeywords));
    }
  }

  public mask(secret: string): string {
    if (secret.length <= 6) {
      return "*".repeat(secret.length);
    }
    const revealCount = Math.min(4, Math.floor(secret.length * 0.25));
    const prefixLen = Math.floor(revealCount / 2);
    const suffixLen = revealCount - prefixLen;

    const prefix = prefixLen > 0 ? secret.slice(0, prefixLen) : "";
    const suffix = suffixLen > 0 ? secret.slice(-suffixLen) : "";
    return `${prefix}${"*".repeat(secret.length - revealCount)}${suffix}`;
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

    let matchedGlobalKeywords: Set<string> | null = null;

    // Global Keyword Pre-filter Performance Optimization
    if (this.ahoCorasick) {
      const found = this.ahoCorasick.search(lowerText);
      if (found.length === 0 && !this.hasRulesWithoutKeywords) {
        return; // Skip completely if no keywords map and all rules require keywords
      }
      matchedGlobalKeywords = new Set(found);
    }

    for (const rule of this.rules) {
      if (SeverityOrder[rule.severity] < minSeverityWeight) {
        continue;
      }

      if (isLineIgnoredByDirective(text, previousLine, rule.id)) {
        continue;
      }

      if (rule.keywords && rule.keywords.length > 0) {
        let matchesKeyword = false;
        if (matchedGlobalKeywords) {
          matchesKeyword = rule.keywords.some((kw) => matchedGlobalKeywords!.has(kw.toLowerCase()));
        } else {
          matchesKeyword = rule.keywords.some((kw) => lowerText.includes(kw.toLowerCase()));
        }

        if (!matchesKeyword) {
          continue;
        }
      }

      rule.pattern.lastIndex = 0;
      let match: RegExpExecArray | null;

      while ((match = rule.pattern.exec(text)) !== null) {
        const rawSecret = match[1] || match[2] || match[0];

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
          secretHash: crypto.createHash("sha256").update(`${filePath}:${rule.id}:${rawSecret}`).digest("hex"),
          rawSecret
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

    // MIME Base64 continuation (e.g. 76 column wrapped B64) safely capped to < 1000
    if (previousLine) {
      const pT = previousLine.trim();
      const cT = line.trim();
      if (pT.length < 1000 && cT.length < 1000 && /^[A-Za-z0-9+\/]{40,}=*$/.test(pT) && /^[A-Za-z0-9+\/]{16,}=*$/.test(cT)) {
        line = pT + cT;
      }
    }

    // ZWSP and invisible formatting mark stripping for evasion prevention
    let sanitizedLine = line.replace(/[\u200B-\u200D\uFEFF]/g, "");

    // Prevent ReDoS by capping the line length EARLY before complex operations
    sanitizedLine = sanitizedLine.length > MAX_LINE_LENGTH ? sanitizedLine.slice(0, MAX_LINE_LENGTH) : sanitizedLine;

    // String.fromCharCode obfuscation
    sanitizedLine = sanitizedLine.replace(/String\.fromCharCode\s*\(([\d\s,]+)\)/g, (_, nums) => {
      try {
        return String.fromCharCode(...nums.split(',').map((n: string) => parseInt(n.trim(), 10)));
      } catch {
        return _;
      }
    });

    // 1. Inline yorum blokları temizleme (/* ... */) and implicit concatenation
    sanitizedLine = sanitizedLine.replace(/\/\*[\s\S]*?\*\//g, '');
    sanitizedLine = sanitizedLine.replace(/["']\s*\+?\s*\n?\s*["']/g, '');

    // 2. Hex ve Octal decoding
    sanitizedLine = sanitizedLine.replace(/\\x([0-9a-fA-F]{2})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
    sanitizedLine = sanitizedLine.replace(/\\([0-3][0-7]{2})/g, (_, oct) => String.fromCharCode(parseInt(oct, 8)));

    // Unicode escape sequence normalization (e.g. \u0067 -> g)
    sanitizedLine = sanitizedLine.replace(/\\u00([0-9a-fA-F]{2})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)));

    // URL Decode
    sanitizedLine = sanitizedLine.replace(/%([0-9a-fA-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));

    // HTML Decimal Entity Decode
    sanitizedLine = sanitizedLine.replace(/&#(\d{2,3});/g, (_, d) => String.fromCharCode(parseInt(d, 10)));

    // Template Engine & Macro stripping
    sanitizedLine = sanitizedLine.replace(/(?:\{\{|\}\}|<%[=\-]?|[-]?%>)/g, '');

    // 3. String Formatting & Template Injection (.format / string.Format)
    sanitizedLine = sanitizedLine.replace(/(?:string\.Format|\.format)\s*\([^,]+,\s*(["'][^"']+["'](?:\s*,\s*["'][^"']+["'])*)\)/g,
      (_, args) => args.replace(/["',\s]/g, '')
    );

    // Functional Array Transformation stripping ("['g', 'h', 'p']" -> "ghp")
    sanitizedLine = sanitizedLine.replace(/\[\s*(?:['"][A-Za-z0-9_\-]{1,4}['"]\s*,\s*){3,}['"][A-Za-z0-9_\-]{1,4}['"]\s*\]/g, (match) => {
      return match.replace(/['",\s\[\]]/g, '');
    });

    // 4. Gürültü Karakteri Enjeksiyonu (Delimiter Stripping for specific substrings or chains) 
    // Hedef: 'g-h-p_-' veya 's_k_l_i_v_e_'
    sanitizedLine = sanitizedLine.replace(/\b([a-zA-Z0-9][-_\.]){3,}[a-zA-Z0-9]\b/g, (match) => {
      return match.replace(/[-_\.]/g, '');
    });

    // Naive Cyrillic Homoglyph Normalization (Fold tricky Cyrillic characters to ASCII to prevent evasion)
    sanitizedLine = sanitizedLine.replace(/[Аа]/g, "a")
      .replace(/[В]/g, "B")
      .replace(/[Сс]/g, "c")
      .replace(/[Ее]/g, "e")
      .replace(/[Оо]/g, "o")
      .replace(/[Рр]/g, "p")
      .replace(/[Хх]/g, "x")
      .replace(/[М]/g, "M")
      .replace(/[Н]/g, "H")
      .replace(/[Т]/g, "T");

    if (isLineIgnoredByDirective(sanitizedLine, previousLine)) {
      return [];
    }

    // Doğrudan tarama
    this.scanText(sanitizedLine, lineNumber, filePath, minSeverity, previousLine, 0, findings);

    // Encode edilmiş içerikleri çözerek tarama
    for (const candidate of recursivelyDecodeLine(sanitizedLine, this.maxDecodeDepth)) {
      this.scanText(candidate.text, lineNumber, filePath, minSeverity, undefined, candidate.offset, findings);
    }

    return findings;
  }
}
