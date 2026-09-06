import fs from "node:fs/promises";

export const DEFAULT_MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024; // 10 MB
export const MAX_FILE_SIZE_BYTES = DEFAULT_MAX_FILE_SIZE_BYTES; // Geriye dönük uyumluluk

export interface FileContent {
  path: string;
  lines: string[];
  totalLines: number;
}

export function parseByteSize(input: string | number): number {
  if (typeof input === "number") {
    if (input <= 0 || !Number.isFinite(input)) {
      throw new Error(`Invalid max file size: "${input}". Must be a positive number.`);
    }
    return Math.floor(input);
  }

  const trimmed = input.trim().toUpperCase();
  const match = trimmed.match(/^(\d+(?:\.\d+)?)\s*(B|KB|K|MB|M|GB|G)?$/);

  if (!match) {
    throw new Error(`Invalid max file size: "${input}". Examples: 5MB, 500KB, 10485760`);
  }

  const num = parseFloat(match[1]!);
  const unit = match[2] || "B";

  let multiplier = 1;
  switch (unit) {
    case "KB":
    case "K":
      multiplier = 1024;
      break;
    case "MB":
    case "M":
      multiplier = 1024 * 1024;
      break;
    case "GB":
    case "G":
      multiplier = 1024 * 1024 * 1024;
      break;
    case "B":
    default:
      multiplier = 1;
      break;
  }

  const result = Math.floor(num * multiplier);
  if (result <= 0) {
    throw new Error(`Invalid max file size: "${input}". Must be greater than 0.`);
  }
  return result;
}

export async function readFileLines(
  filePath: string,
  maxSizeBytes: number = DEFAULT_MAX_FILE_SIZE_BYTES
): Promise<FileContent | null> {
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
    if (stats && stats.size > maxSizeBytes) {
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
