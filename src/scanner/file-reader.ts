import fs from "node:fs/promises";
import fsSync from "node:fs";

export const MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024; // 10 MB

export interface FileContent {
  path: string;
  lines: string[];
  totalLines: number;
}

export interface ReadFileResult {
  content: string | null;
  skipped: boolean;
  reason?: string;
}

export function readTextFileSafe(filePath: string): ReadFileResult {
  try {
    let stats: any = null;
    if (typeof fsSync.lstatSync === "function") {
      try {
        const lstatRes = fsSync.lstatSync(filePath);
        if (lstatRes && (typeof lstatRes.size === "number" || typeof lstatRes.isSymbolicLink === "function")) {
          stats = lstatRes;
        }
      } catch {
        // fallback
      }
    }

    if (!stats) {
      stats = fsSync.statSync(filePath);
    }

    if (typeof stats?.isSymbolicLink === "function" && stats.isSymbolicLink()) {
      return { content: null, skipped: true, reason: "symbolic links are ignored for security" };
    }
    if (stats && stats.size > MAX_FILE_SIZE_BYTES) {
      return { content: null, skipped: true, reason: "exceeds maximum size (10MB)" };
    }
    const content = fsSync.readFileSync(filePath, "utf-8");
    return { content, skipped: false };
  } catch (err: any) {
    return { content: null, skipped: true, reason: err.message };
  }
}

export async function readFileLines(filePath: string): Promise<FileContent | null> {
  try {
    let stats: any = null;
    if (typeof fs.lstat === "function") {
      try {
        const lstatRes = await fs.lstat(filePath);
        if (lstatRes && (typeof lstatRes.size === "number" || typeof lstatRes.isSymbolicLink === "function")) {
          stats = lstatRes;
        }
      } catch {
        // fallback
      }
    }

    if (!stats) {
      stats = await fs.stat(filePath);
    }

    if (typeof stats?.isSymbolicLink === "function" && stats.isSymbolicLink()) {
      return null;
    }
    if (stats && stats.size > MAX_FILE_SIZE_BYTES) {
      return null;
    }

    const rawBuffer = await fs.readFile(filePath);
    
    const sampleSize = Math.min(rawBuffer.length, 1024);
    for (let i = 0; i < sampleSize; i++) {
      if (rawBuffer[i] === 0) {
        return null;
      }
    }

    const content = rawBuffer.toString("utf-8");
    const lines = content.split(/\r?\n/);

    return {
      path: filePath,
      lines,
      totalLines: lines.length
    };
  } catch {
    return null;
  }
}
