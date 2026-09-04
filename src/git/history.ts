import { spawn } from "node:child_process";
import * as readline from "node:readline";
import { SecretDetector } from "../detectors/detector.js";
import { Finding, Severity } from "../types/index.js";
import { shouldIgnorePath } from "../scanner/file-filter.js";

export interface HistoryScanResult {
  findings: Finding[];
  totalCommits: number;
  totalLinesScanned: number;
  distinctFilesScanned: number;
}

const COMMIT_START_MARKER = "__GITLEAK_COMMIT_START__";

/**
 * Git commit geçmişini streaming yöntemiyle, harici komut çalıştırma (diff injection) 
 * risklerine karşı korumalı ve bellek tüketmeden satır satır tarar.
 */
export async function scanGitHistory(
  repoPath: string,
  detector: SecretDetector,
  minSeverity: Severity = "low",
  ignorePatterns: string[] = [],
  maxCommits?: number,
  onProgress?: (filePath: string, status: "scanned" | "ignored" | "binary") => void
): Promise<HistoryScanResult> {
  return new Promise((resolve, reject) => {
    // 1. Güvenlik Bariyerleri:
    // -c diff.external= ve --no-ext-diff ile zararlı harici diff komutları engellenir.
    // Null-byte (%x00) ile güvenli meta veri serileştirmesi yapılır.
    const gitArgs = [
      "-c",
      "diff.external=",
      "log",
      "-p",
      "-U0",
      "--no-color",
      "--full-history",
      "--no-ext-diff",
      `--pretty=format:${COMMIT_START_MARKER}%x00%H%x00%an%x00%aI%x00`
    ];

    if (typeof maxCommits === "number" && maxCommits > 0) {
      gitArgs.push(`-n`, String(maxCommits));
    }

    // Argument injection bariyeri
    gitArgs.push("--");

    const child = spawn("git", gitArgs, {
      cwd: repoPath,
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true
    });

    const rl = readline.createInterface({
      input: child.stdout,
      crlfDelay: Infinity
    });

    const findings: Finding[] = [];
    const seenCommits = new Set<string>();
    const seenFiles = new Set<string>();

    let currentCommit = "";
    let currentAuthor = "";
    let currentDate = "";
    let currentFile = "";
    let currentLineNumber = 0;
    let totalLinesScanned = 0;
    let isFileIgnored = false;

    rl.on("line", (line: string) => {
      // Commit Başlangıcı ve Metadata
      if (line.startsWith(COMMIT_START_MARKER)) {
        const parts = line.split("\0");
        if (parts.length >= 4) {
          currentCommit = parts[1] || "";
          currentAuthor = parts[2] || "";
          currentDate = parts[3] || "";
          if (currentCommit) {
            seenCommits.add(currentCommit);
          }
        }
        currentFile = "";
        isFileIgnored = false;
        return;
      }

      // Dosya Değişikliği Başlığı (+++ b/...)
      if (line.startsWith("+++ ")) {
        let rawPath = line.slice(4).trim();
        // Git tırnaklı yolları temizle: "b/path with spaces" -> b/path with spaces
        if (rawPath.startsWith('"') && rawPath.endsWith('"')) {
          rawPath = rawPath.slice(1, -1);
        }
        // Prefix temizle (b/...)
        if (rawPath.startsWith("b/")) {
          rawPath = rawPath.slice(2);
        }

        currentFile = rawPath;

        if (currentFile === "/dev/null" || !currentFile) {
          isFileIgnored = true;
          return;
        }

        isFileIgnored = shouldIgnorePath(currentFile, ignorePatterns);
        if (!isFileIgnored) {
          seenFiles.add(currentFile);
          onProgress?.(currentFile, "scanned");
        } else {
          onProgress?.(currentFile, "ignored");
        }
        return;
      }

      // Dosya yoksayılmış veya silinmişse diff içeriğini atla
      if (isFileIgnored || !currentFile) {
        return;
      }

      // İkili Dosya Uyarısı
      if (line.startsWith("Binary files ") && line.endsWith("differ")) {
        onProgress?.(currentFile, "binary");
        return;
      }

      // Hunk Başlığı: @@ -old,count +newStart,count @@ [opsiyonel fonksiyon başlığı]
      if (line.startsWith("@@ ")) {
        const match = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/.exec(line);
        if (match && match[1]) {
          currentLineNumber = parseInt(match[1], 10);
        }
        return;
      }

      // Diff İçinde Eklenen Satırlar (+) - Dosya başlığı ('+++') hariç
      if (line.startsWith("+") && !line.startsWith("+++")) {
        const addedContent = line.slice(1);
        totalLinesScanned++;

        const lineFindings = detector.scanLine(
          addedContent,
          currentLineNumber,
          currentFile,
          minSeverity
        );

        for (const f of lineFindings) {
          findings.push({
            ...f,
            commit: currentCommit,
            commitAuthor: currentAuthor,
            commitDate: currentDate
          });
        }

        currentLineNumber++;
      }
    });

    child.on("error", (err) => {
      reject(err);
    });

    let stderr = "";
    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
    });

    child.on("close", (code) => {
      // Git commit olmayan temiz/yeni init edilmiş repo durumları
      if (
        code !== 0 &&
        (stderr.includes("does not have any commits yet") ||
          stderr.includes("unknown revision") ||
          stderr.includes("fatal: your current branch"))
      ) {
        resolve({
          findings: [],
          totalCommits: 0,
          totalLinesScanned: 0,
          distinctFilesScanned: 0
        });
        return;
      }

      if (code !== 0) {
        reject(new Error(`Git history scan failed with exit code ${code}: ${stderr.trim()}`));
      } else {
        resolve({
          findings,
          totalCommits: seenCommits.size,
          totalLinesScanned,
          distinctFilesScanned: seenFiles.size
        });
      }
    });
  });
}
