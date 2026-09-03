import fg from "fast-glob";
import path from "node:path";
import { Finding, ScanOptions, ScanResult } from "../types/index.js";
import { SecretDetector } from "../detectors/detector.js";
import { DETECTION_RULES } from "../detectors/rules.js";
import { EXCLUDED_DIRECTORIES, shouldIgnoreFile } from "./file-filter.js";
import { readFileLines } from "./file-reader.js";
import { calculateSecurityScore } from "../scoring/scorer.js";
import { loadConfig } from "../config/loader.js";

export class ProjectScanner {
  public async scan(options: ScanOptions): Promise<ScanResult> {
    const startTime = performance.now();
    const targetDir = path.resolve(process.cwd(), options.path);
    const config = await loadConfig(targetDir);

    const activeRules = DETECTION_RULES.filter(
      (rule) => config.rules[rule.id] !== false
    );
    const detector = new SecretDetector(activeRules);

    const mergedIgnores = [
      ...EXCLUDED_DIRECTORIES,
      ...(options.ignore ?? []).map((i: string) => `**/${i}/**`),
      ...config.ignore.map((i: string) => `**/${i}/**`)
    ];

    const files = await fg(["**/*"], {
      cwd: targetDir,
      dot: true,
      ignore: mergedIgnores,
      onlyFiles: true,
      followSymbolicLinks: false
    });

    let totalScannedFiles = 0;
    let totalScannedLines = 0;
    const findings: Finding[] = [];

    for (const relativePath of files) {
      if (shouldIgnoreFile(relativePath)) {
        options.onFileAction?.(relativePath, "ignored");
        continue;
      }

      const absolutePath = path.join(targetDir, relativePath);
      const fileData = await readFileLines(absolutePath);

      if (!fileData) {
        options.onFileAction?.(relativePath, "binary");
        continue;
      }

      options.onFileAction?.(relativePath, "scanned");
      totalScannedFiles++;
      totalScannedLines += fileData.totalLines;

      for (let i = 0; i < fileData.lines.length; i++) {
        const lineContent = fileData.lines[i]!;
        const lineFindings = detector.scanLine(
          lineContent,
          i + 1,
          relativePath,
          options.severity ?? "low"
        );
        findings.push(...lineFindings);
      }
    }

    const durationMs = Math.round(performance.now() - startTime);
    const scoreReport = calculateSecurityScore(findings);

    return {
      summary: {
        filesScanned: totalScannedFiles,
        linesScanned: totalScannedLines,
        findings: findings.length,
        score: scoreReport.score,
        tier: scoreReport.tier,
        durationMs
      },
      findings
    };
  }
}
