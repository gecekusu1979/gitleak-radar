import fg from "fast-glob";
import path from "node:path";
import fs from "node:fs";
import { type Finding, type ScanOptions, type ScanResult, type DetectionRule } from "../types/index.js";
import { SecretDetector } from "../detectors/detector.js";
import { EXCLUDED_DIRECTORIES, shouldIgnorePath } from "./file-filter.js";
import { readFileLines, parseByteSize, DEFAULT_MAX_FILE_SIZE_BYTES, type FileContent } from "./file-reader.js";
import { calculateSecurityScore } from "../scoring/scorer.js";
import { loadConfig, getEffectiveRules, loadExternalRulesFile } from "../config/loader.js";
import { getStagedFiles, isInsideGitRepo, getGitRoot, readStagedFileLines } from "../git/staged.js";
import { getChangedFilesSince } from "../git/incremental.js";
import { scanGitHistory } from "../git/history.js";
import { saveBaseline, loadBaselineFingerprints, filterFindingsByBaseline } from "../baseline/baseline.js";

export class ProjectScanner {
  public async scan(options: ScanOptions): Promise<ScanResult> {
    const startTime = performance.now();
    const targetDir = path.resolve(process.cwd(), options.path);

    const config = await loadConfig(targetDir);

    let extraRules: DetectionRule[] = [];
    if (options.rulesPath) {
      extraRules = await loadExternalRulesFile(options.rulesPath);
    }

    const activeRules = getEffectiveRules(config, extraRules);
    const detector = new SecretDetector(activeRules);

    const rawLimit = options.maxFileSize ?? config.maxFileSize;
    const maxFileSizeBytes = rawLimit !== undefined ? parseByteSize(rawLimit) : DEFAULT_MAX_FILE_SIZE_BYTES;

    let rawFindings: Finding[] = [];
    let filesScannedCount = 0;
    let linesScannedCount = 0;
    let commitsScannedCount: number | undefined;

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
        options.onFileAction,
        maxFileSizeBytes
      );

      rawFindings = historyResult.findings;
      filesScannedCount = historyResult.distinctFilesScanned;
      linesScannedCount = historyResult.totalLinesScanned;
      commitsScannedCount = historyResult.totalCommits;
    } else {
      if (options.staged || options.since) {
        const isRepo = await isInsideGitRepo(targetDir);
        if (!isRepo) {
          throw new Error(`Cannot run ${options.staged ? "--staged" : "--since"} scan: Specified path is not inside a Git repository.`);
        }
      }

      let candidateFiles: string[] = [];

      if (options.staged) {
        candidateFiles = await getStagedFiles(targetDir);
      } else if (options.since) {
        candidateFiles = await getChangedFilesSince(targetDir, options.since);
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
          fileData = await readStagedFileLines(gitRoot, relToGitRoot, maxFileSizeBytes);
        } else {
          fileData = await readFileLines(absolutePath, maxFileSizeBytes);
        }

        if (!fileData) {
          options.onFileAction?.(normalizedPath, "binary");
          continue;
        }

        options.onFileAction?.(normalizedPath, "scanned");
        filesScannedCount++;
        linesScannedCount += fileData.totalLines;

        for (let i = 0; i < fileData.lines.length; i++) {
          const lineContent = fileData.lines[i]!;
          const previousLine = i > 0 ? fileData.lines[i - 1] : undefined;
          const lineFindings = detector.scanLine(
            lineContent,
            i + 1,
            normalizedPath,
            options.severity ?? "low",
            previousLine
          );
          rawFindings.push(...lineFindings);
        }
      }
    }

    // Baseline Mantığı
    const defaultBaselineFile = path.resolve(targetDir, ".gitleak-radar-baseline.json");

    if (options.createBaseline) {
      const targetBaselinePath = typeof options.createBaseline === "string"
        ? path.resolve(process.cwd(), options.createBaseline)
        : defaultBaselineFile;

      await saveBaseline(targetBaselinePath, rawFindings);

      const durationMs = Math.round(performance.now() - startTime);
      return {
        summary: {
          filesScanned: filesScannedCount,
          linesScanned: linesScannedCount,
          findings: 0,
          suppressedFindings: rawFindings.length,
          score: 100,
          tier: "Excellent",
          durationMs,
          commitsScanned: commitsScannedCount
        },
        findings: []
      };
    }

    let finalFindings = rawFindings;
    let suppressedCount = 0;
    const resolvedBaselinePath = options.baselinePath
      ? path.resolve(process.cwd(), options.baselinePath)
      : (fs.existsSync(defaultBaselineFile) ? defaultBaselineFile : null);

    if (resolvedBaselinePath && fs.existsSync(resolvedBaselinePath)) {
      const baselineFPs = await loadBaselineFingerprints(resolvedBaselinePath);
      const filtered = filterFindingsByBaseline(rawFindings, baselineFPs);
      finalFindings = filtered.activeFindings;
      suppressedCount = filtered.suppressedCount;
    }

    const durationMs = Math.round(performance.now() - startTime);
    const scoreReport = calculateSecurityScore(finalFindings);

    return {
      summary: {
        filesScanned: filesScannedCount,
        linesScanned: linesScannedCount,
        findings: finalFindings.length,
        suppressedFindings: suppressedCount > 0 ? suppressedCount : undefined,
        score: scoreReport.score,
        tier: scoreReport.tier,
        durationMs,
        commitsScanned: commitsScannedCount
      },
      findings: finalFindings
    };
  }
}

export async function scan(options: ScanOptions): Promise<ScanResult> {
  const scanner = new ProjectScanner();
  return scanner.scan(options);
}
