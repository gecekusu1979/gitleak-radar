import fs from "node:fs/promises";

export const MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024; // 10 MB

export interface FileContent {
  path: string;
  lines: string[];
  totalLines: number;
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
