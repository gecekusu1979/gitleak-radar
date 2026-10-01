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
): Promise<FileContent | { skipped: true; reason: string }> {
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
      return { skipped: true, reason: "symlink" };
    }
    if (stats && stats.size > maxSizeBytes) {
      return { skipped: true, reason: "too-large" };
    }

    const rawBuffer = await fs.readFile(filePath);

    // UTF-16 BOM tespiti: FF FE (UTF-16LE) veya FE FF (UTF-16BE)
    let content: string;
    if (rawBuffer.length >= 2 && rawBuffer[0] === 0xff && rawBuffer[1] === 0xfe) {
      // UTF-16LE with BOM
      content = rawBuffer.slice(2).toString("utf16le");
    } else if (rawBuffer.length >= 2 && rawBuffer[0] === 0xfe && rawBuffer[1] === 0xff) {
      // UTF-16BE with BOM — Node.js built-in'de doğrudan BE yok; manuel swap
      const swapped = Buffer.allocUnsafe(rawBuffer.length - 2);
      for (let i = 0; i < rawBuffer.length - 2; i += 2) {
        swapped[i] = rawBuffer[i + 3]!;
        swapped[i + 1] = rawBuffer[i + 2]!;
      }
      content = swapped.toString("utf16le");
    } else {
      // BOM yoksa: null-byte örüntüsüyle UTF-16LE tespiti dene
      // UTF-16LE'de ASCII metin her çift byte'ta null içerir (örn. "A\0B\0")
      const sampleSize = Math.min(rawBuffer.length, 512);
      let nullCount = 0;
      for (let i = 0; i < sampleSize; i++) {
        if (rawBuffer[i] === 0) nullCount++;
      }
      // Byte'ların >%30'u null ise UTF-16LE veya BE olarak deneyerek oku
      if (nullCount / sampleSize > 0.3 && rawBuffer.length >= 4) {
        // İlk byte çift konumdaki karakterlerin printable olup olmadığını kontrol et
        const sample = rawBuffer.slice(0, Math.min(rawBuffer.length, 256));
        // Her iki byte'ta bir printable ASCII olması UTF-16LE işareti
        const leLikely =
          sample.length >= 4 &&
          sample[0]! >= 0x20 && sample[0]! < 0x7f &&
          sample[1] === 0 &&
          sample[2]! >= 0x20 && sample[2]! < 0x7f &&
          sample[3] === 0;

        const beLikely =
          sample.length >= 4 &&
          sample[0] === 0 &&
          sample[1]! >= 0x20 && sample[1]! < 0x7f &&
          sample[2] === 0 &&
          sample[3]! >= 0x20 && sample[3]! < 0x7f;

        if (leLikely) {
          content = rawBuffer.toString("utf16le");
        } else if (beLikely) {
          const swapped = Buffer.allocUnsafe(rawBuffer.length - (rawBuffer.length % 2));
          for (let i = 0; i < swapped.length; i += 2) {
            swapped[i] = rawBuffer[i + 1]!;
            swapped[i + 1] = rawBuffer[i]!;
          }
          content = swapped.toString("utf16le");
        } else {
          // Null interleaving evasion savunması
          content = rawBuffer.toString("utf-8").replace(/\0/g, "");
        }
      } else {
        // Tolerant parsing: null byte'ları temizle
        content = rawBuffer.toString("utf-8").replace(/\0/g, "");
      }
    }

    const lines = content.split(/\r?\n/);

    return {
      path: filePath,
      lines,
      totalLines: lines.length
    };
  } catch (err: any) {
    return { skipped: true, reason: err.message || "read-error" };
  }
}
