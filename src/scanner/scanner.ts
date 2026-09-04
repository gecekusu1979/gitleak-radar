import fg from "fast-glob";
import path from "node:path";
import { type Finding, type ScanOptions, type ScanResult } from "../types/index.js";
import { SecretDetector } from "../detectors/detector.js";
import { DETECTION_RULES } from "../detectors/rules.js";
import { EXCLUDED_DIRECTORIES, shouldIgnorePath } from "./file-filter.js";
import { readFileLines, type FileContent } from "./file-reader.js";
import { calculateSecurityScore } from "../scoring/scorer.js";
import { loadConfig } from "../config/loader.js";
import { getStagedFiles, isInsideGitRepo, getGitRoot, readStagedFileLines } from "../git/staged.js";
import { scanGitHistory } from "../git/history.js";

export class ProjectScanner {
  public async scan(options: ScanOptions): Promise<ScanResult> {
    const startTime = performance.now();
    const targetDir = path.resolve(process.cwd(), options.path);

    const config = await loadConfig(targetDir);
    const activeRules = DETECTION_RULES.filter((rule) => config.rules[rule.id] !== false);
    const detector = new SecretDetector(activeRules);

    // 1. Mod: Git History Scanning (--history)
    if (options.history) {
      const isRepo = await isInsideGitRepo(targetDir);
      if (!isRepo) {
        throw new Error("Cannot run --history scan: Specified path is not inside a Git repository.");
      }

      const mergedIgnores = [
        ...(options.ignore ?? []),
        ...config.ignore
      ];

      const historyResult = await scanGitHistory(
        targetDir,
        detector,
        options.severity ?? "low",
        mergedIgnores,
        options.maxCommits,
        options.onFileAction
      );

      const durationMs = Math.round(performance.now() - startTime);
      const scoreReport = calculateSecurityScore(historyResult.findings);

      return {
        summary: {
          filesScanned: historyResult.distinctFilesScanned,
          commitsScanned: historyResult.totalCommits,
          linesScanned: historyResult.totalLinesScanned,
          findings: historyResult.findings.length,
          score: scoreReport.score,
          tier: scoreReport.tier,
          durationMs
        },
        findings: historyResult.findings
      };
    }

    // 2. Mod: Git Staged Scanning (--staged)
    if (options.staged) {
      const isRepo = await isInsideGitRepo(targetDir);
      if (!isRepo) {
        throw new Error("Cannot run --staged scan: Specified path is not inside a Git repository.");
      }
    }

    let candidateFiles: string[] = [];

    if (options.staged) {
      candidateFiles = await getStagedFiles(targetDir);
    } else {
      const mergedIgnores = [
        ...EXCLUDED_DIRECTORIES,
        ...(options.ignore ?? []).map((i: string) => `**/${i}/**`),
        ...config.ignore.map((i: string) => `**/${i}/**`)
      ];

      candidateFiles = await fg(["**/*"], {
        cwd: targetDir,
        dot: true,
        ignore: mergedIgnores,
        onlyFiles: true,
        followSymbolicLinks: false
      });
    }

    let totalScannedFiles = 0;
    let totalScannedLines = 0;
    const findings: Finding[] = [];

    for (const rawPath of candidateFiles) {
      const normalizedPath = rawPath.replace(/\\/g, "/");

      if (shouldIgnorePath(normalizedPath, [...(options.ignore ?? []), ...config.ignore])) {
        options.onFileAction?.(normalizedPath, "ignored");
        continue;
      }

      const absolutePath = path.resolve(targetDir, normalizedPath);
      let fileData: FileContent | null = null;

      if (options.staged) {
        const gitRoot = await getGitRoot(targetDir);
        const relToGitRoot = path.relative(gitRoot, absolutePath).replace(/\\/g, "/");
        fileData = await readStagedFileLines(gitRoot, relToGitRoot);
      } else {
        fileData = await readFileLines(absolutePath);
      }

      if (!fileData) {
        options.onFileAction?.(normalizedPath, "binary");
        continue;
      }

      options.onFileAction?.(normalizedPath, "scanned");
      totalScannedFiles++;
      totalScannedLines += fileData.totalLines;

      for (let i = 0; i < fileData.lines.length; i++) {
        const lineContent = fileData.lines[i]!;
        const lineFindings = detector.scanLine(
          lineContent,
          i + 1,
          normalizedPath,
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

export async function scan(options: ScanOptions): Promise<ScanResult> {
  const scanner = new ProjectScanner();
  return scanner.scan(options);
}
