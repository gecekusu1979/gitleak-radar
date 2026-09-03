import fs from "node:fs/promises";

export interface FileContent {
  path: string;
  lines: string[];
  totalLines: number;
}

export async function readFileLines(filePath: string): Promise<FileContent | null> {
  try {
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
