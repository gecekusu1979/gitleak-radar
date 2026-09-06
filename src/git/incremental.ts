import { execFile } from "node:child_process";
import { promisify } from "node:util";
import path from "node:path";
import fs from "node:fs/promises";
import { isInsideGitRepo, getGitRoot } from "./staged.js";

const execFileAsync = promisify(execFile);

export async function getChangedFilesSince(targetDir: string, ref: string): Promise<string[]> {
  const isRepo = await isInsideGitRepo(targetDir);
  if (!isRepo) {
    throw new Error("Cannot run --since scan: Specified path is not inside a Git repository.");
  }

  const gitRoot = await getGitRoot(targetDir);

  let diffStdout = "";
  try {
    const res = await execFileAsync("git", ["diff", "--name-only", "--diff-filter=d", "--end-of-options", ref, "--"], {
      cwd: gitRoot
    });
    diffStdout = res.stdout;
  } catch (err: any) {
    throw new Error(`Failed to resolve git reference "${ref}" for incremental scan: ${err.stderr?.trim() || err.message}`);
  }

  // Çalışma dizinindeki yeni (untracked) dosyaları da listeye ekle
  let untrackedStdout = "";
  try {
    const res = await execFileAsync("git", ["ls-files", "--others", "--exclude-standard"], {
      cwd: gitRoot
    });
    untrackedStdout = res.stdout;
  } catch {
    // fallback
  }

  const allLines = [
    ...diffStdout.split(/\r?\n/),
    ...untrackedStdout.split(/\r?\n/)
  ]
    .map((s) => s.trim())
    .map((s) => (s.startsWith('"') && s.endsWith('"') ? s.slice(1, -1) : s))
    .filter(Boolean);

  const uniqueFiles = Array.from(new Set(allLines));
  const existingFiles: string[] = [];

  for (const relativeToGitRoot of uniqueFiles) {
    const absoluteFilePath = path.resolve(gitRoot, relativeToGitRoot);
    try {
      const stat = await fs.stat(absoluteFilePath);
      if (stat.isFile()) {
        const relToTarget = path.relative(targetDir, absoluteFilePath);
        existingFiles.push(relToTarget.replace(/\\/g, "/"));
      }
    } catch {
      // Dosya silinmiş veya erişilemiyorsa atla
    }
  }

  return existingFiles;
}
