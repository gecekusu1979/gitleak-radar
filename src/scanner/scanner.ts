import fg from "fast-glob";
import path from "node:path";
import fs from "node:fs";
import { type Finding, type ScanOptions, type ScanResult, type DetectionRule } from "../types/index.js";
import { SecretDetector } from "../detectors/detector.js";
import { SemanticParser } from "../detectors/semantic-parser.js";
import { ArchiveProcessor } from "../detectors/archive-processor.js";
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
    const absoluteScanPath = path.resolve(process.cwd(), options.path);
    let targetConfigDir = absoluteScanPath;
    let isFileScan = false;

    try {
      const lstats = await fs.promises.lstat(absoluteScanPath);
      if (lstats.isSymbolicLink()) {
        throw new Error(`Invalid scan path: "${options.path}" is a symbolic link. Please provide a direct file or directory path.`);
      }
      if (lstats.isFile()) {
        isFileScan = true;
        targetConfigDir = path.dirname(absoluteScanPath);
      }
    } catch (err: any) {
      if (err.code === "ENOENT") {
        throw new Error(`Invalid scan path: "${options.path}" does not exist.`);
      }
      throw err;
    }

    const config = await loadConfig(targetConfigDir);

    let extraRules: DetectionRule[] = [];
    if (options.rulesPath) {
      extraRules = await loadExternalRulesFile(options.rulesPath);
    }

    const activeRules = await getEffectiveRules(config, extraRules);
    const maxDecodeDepth = options.maxDecodeDepth ?? config.maxDecodeDepth ?? 3;
    const detector = new SecretDetector(
      activeRules,
      [...(config.allowlist ?? []), ...(options.allowlist ?? [])],
      maxDecodeDepth
    );
    const semanticParser = new SemanticParser(detector);
    const archiveProcessor = new ArchiveProcessor(detector);

    const rawLimit = options.maxFileSize ?? config.maxFileSize;
    const maxFileSizeBytes = rawLimit !== undefined ? parseByteSize(rawLimit) : DEFAULT_MAX_FILE_SIZE_BYTES;

    let rawFindings: Finding[] = [];
    let filesScannedCount = 0;
    let skippedFilesCount = 0;
    let linesScannedCount = 0;
    let commitsScannedCount: number | undefined;

    if (options.history) {
      const isRepo = await isInsideGitRepo(targetConfigDir);
      if (!isRepo) {
        throw new Error("Cannot run --history scan: Specified path is not inside a Git repository.");
      }

      const mergedIgnores = [
        ...(options.ignore ?? []),
        ...config.ignore
      ];

      const historyResult = await scanGitHistory(
        targetConfigDir,
        detector,
        options.severity ?? "low",
        mergedIgnores,
        options.maxCommits,
        options.onFileAction,
        maxFileSizeBytes,
        isFileScan ? absoluteScanPath : undefined
      );

      rawFindings = historyResult.findings;
      filesScannedCount = historyResult.distinctFilesScanned;
      linesScannedCount = historyResult.totalLinesScanned;
      commitsScannedCount = historyResult.totalCommits;
    } else {
      if (options.staged || options.since) {
        const isRepo = await isInsideGitRepo(targetConfigDir);
        if (!isRepo) {
          throw new Error(`Cannot run ${options.staged ? "--staged" : "--since"} scan: Specified path is not inside a Git repository.`);
        }
      }

      let candidateFiles: string[] = [];

      if (options.staged) {
        candidateFiles = await getStagedFiles(targetConfigDir);
        if (isFileScan) {
          const expectedRel = path.relative(targetConfigDir, absoluteScanPath).replace(/\\/g, "/");
          candidateFiles = candidateFiles.filter(f => f === expectedRel);
        }
      } else if (options.since) {
        candidateFiles = await getChangedFilesSince(targetConfigDir, options.since);
        if (isFileScan) {
          const expectedRel = path.relative(targetConfigDir, absoluteScanPath).replace(/\\/g, "/");
          candidateFiles = candidateFiles.filter(f => f === expectedRel);
        }
      } else {
        if (isFileScan) {
          candidateFiles = [path.relative(targetConfigDir, absoluteScanPath)];
        } else {
          const mergedIgnores = [
            ...EXCLUDED_DIRECTORIES,
            ...(options.ignore ?? []).map((i: string) => `**/${i}/**`),
            ...config.ignore.map((i: string) => `**/${i}/**`)
          ];

          candidateFiles = await fg(["**/*"], {
            cwd: targetConfigDir,
            dot: true,
            ignore: mergedIgnores,
            onlyFiles: true,
            followSymbolicLinks: false
          });
        }
      }

      for (const rawPath of candidateFiles) {
        const normalizedPath = rawPath.replace(/\\/g, "/");

        if (shouldIgnorePath(normalizedPath, [...(options.ignore ?? []), ...config.ignore], !!options.scanAllExtensions)) {
          options.onFileAction?.(normalizedPath, "ignored");
          continue;
        }

        const absolutePath = path.resolve(targetConfigDir, normalizedPath);

        const archiveExt = normalizedPath.split('.').pop()?.toLowerCase();
        if (archiveExt === "zip" || archiveExt === "jar") {
          if (archiveProcessor.scanArchive(absolutePath, normalizedPath, rawFindings)) {
            filesScannedCount++;
            options.onFileAction?.(normalizedPath, "scanned");
            continue;
          }
        }

        let fileData: FileContent | { skipped: true; reason: string } | null = null;

        if (options.staged) {
          const gitRoot = await getGitRoot(targetConfigDir);
          const relToGitRoot = path.relative(gitRoot, absolutePath).replace(/\\/g, "/");
          fileData = await readStagedFileLines(gitRoot, relToGitRoot, maxFileSizeBytes);
        } else {
          fileData = await readFileLines(absolutePath, maxFileSizeBytes);
        }

        if (!fileData || ('skipped' in fileData)) {
          const reason = (fileData && 'reason' in fileData) ? fileData.reason : "binary";
          skippedFilesCount++;
          options.onFileAction?.(normalizedPath, "ignored"); // Or skipped
          continue;
        }

        options.onFileAction?.(normalizedPath, "scanned");
        filesScannedCount++;
        linesScannedCount += fileData.totalLines;

        const semanticExt = normalizedPath.split('.').pop()?.toLowerCase();
        if (semanticExt === "json" || semanticExt === "yaml" || semanticExt === "yml" || semanticExt === "env") {
          const fullContent = fileData.lines.join("\n");
          if (fullContent.length < 65536) {
            if (semanticParser.parseAndScan(fullContent, normalizedPath, rawFindings)) {
              continue;
            }
          }
        }

        for (let i = 0; i < fileData.lines.length; i++) {
          let lineContent = fileData.lines[i]!;
          const previousLine = i > 0 ? fileData.lines[i - 1] : undefined;

          // Phase 7: Sliding window for unclosed template/string splices
          const tickCount = (lineContent.match(/`/g) || []).length;
          const quoteCount = (lineContent.match(/"/g) || []).length;
          const aposCount = (lineContent.match(/'/g) || []).length;

          const endsWithConcat = /[\+\\]\s*$/.test(lineContent.trim());
          if ((tickCount % 2 !== 0 || quoteCount % 2 !== 0 || aposCount % 2 !== 0 || endsWithConcat) && i < fileData.lines.length - 1) {
            let merged = lineContent.trimEnd();
            let mergeCount = 0;
            for (let j = 1; j <= 2 && i + j < fileData.lines.length; j++) {
              const nextLine = fileData.lines[i + j]!;
              merged += nextLine.trim();
              mergeCount++;
              const t = (nextLine.match(/`/g) || []).length;
              const q = (nextLine.match(/"/g) || []).length;
              const a = (nextLine.match(/'/g) || []).length;
              if (t > 0 || q > 0 || a > 0) break;
            }
            lineContent = merged;
            i += mergeCount;
          }

          // Çok uzun satırları örtüşen parçalara böl (65 536 char limit)
          const MAX_LINE_LENGTH = 65_536;
          const CHUNK_OVERLAP = 256;
          if (lineContent.length > MAX_LINE_LENGTH) {
            let chunkStart = 0;
            while (chunkStart < lineContent.length) {
              const chunk = lineContent.slice(chunkStart, chunkStart + MAX_LINE_LENGTH);
              const chunkFindings = detector.scanLine(
                chunk,
                i + 1,
                normalizedPath,
                options.severity ?? "low",
                previousLine
              );
              for (const f of chunkFindings) f.column += chunkStart;
              rawFindings.push(...chunkFindings);
              if (chunkStart + MAX_LINE_LENGTH >= lineContent.length) break;
              chunkStart += MAX_LINE_LENGTH - CHUNK_OVERLAP;
            }
          } else {
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
    }

    // Baseline Mantığı
    const defaultBaselineFile = path.resolve(targetConfigDir, ".gitleak-radar-baseline.json");

    if (options.createBaseline) {
      const targetBaselinePath = typeof options.createBaseline === "string"
        ? path.resolve(process.cwd(), options.createBaseline)
        : defaultBaselineFile;

      await saveBaseline(targetBaselinePath, rawFindings);

      const durationMs = Math.round(performance.now() - startTime);
      return {
        summary: {
          filesScanned: filesScannedCount,
          skippedFiles: skippedFilesCount > 0 ? skippedFilesCount : undefined,
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

    if (options.verify) {
      const { verifyFinding } = await import("../verifiers/index.js");
      const verifiedSecretsCache = new Map<string, boolean | null>();

      // Concurrency Limit Batch Execution
      const BATCH_SIZE = 5;
      for (let i = 0; i < rawFindings.length; i += BATCH_SIZE) {
        const batch = rawFindings.slice(i, i + BATCH_SIZE);
        await Promise.all(batch.map(async (finding) => {
          if (finding.rawSecret) {
            if (verifiedSecretsCache.has(finding.rawSecret)) {
              const cachedResult = verifiedSecretsCache.get(finding.rawSecret);
              if (cachedResult !== null) finding.verified = cachedResult;
              return;
            }

            const isVerified = await verifyFinding(finding, finding.rawSecret);
            verifiedSecretsCache.set(finding.rawSecret, isVerified);
            if (isVerified !== null) {
              finding.verified = isVerified;
            }
          }
        }));
      }
    }

    for (const f of rawFindings) delete f.rawSecret;

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
        skippedFiles: skippedFilesCount > 0 ? skippedFilesCount : undefined,
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

