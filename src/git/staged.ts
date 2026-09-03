import { execFile } from "node:child_process";
import { promisify } from "node:util";
import path from "node:path";
import fs from "node:fs/promises";

const execFileAsync = promisify(execFile);

export async function isInsideGitRepo(targetDir: string): Promise<boolean> {
  try {
    const { stdout } = await execFileAsync("git", ["rev-parse", "--is-inside-work-tree"], {
      cwd: targetDir
    });
    return stdout.trim() === "true";
  } catch {
    return false;
  }
}

export async function getStagedFiles(targetDir: string): Promise<string[]> {
  const isRepo = await isInsideGitRepo(targetDir);
  if (!isRepo) {
    throw new Error("Target directory is not a Git repository or git is not installed.");
  }

  // Name-only staged files excluding deleted (filter=d)
  const { stdout } = await execFileAsync("git", ["diff", "--cached", "--name-only", "--diff-filter=d"], {
    cwd: targetDir
  });

  const lines = stdout.split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
  const existingFiles: string[] = [];

  for (const relativePath of lines) {
    const fullPath = path.resolve(targetDir, relativePath);
    try {
      const stat = await fs.stat(fullPath);
      if (stat.isFile()) {
        existingFiles.push(relativePath.replace(/\\/g, "/"));
      }
    } catch {
      // Dosya silinmiş veya erişilemiyorsa atla
    }
  }

  return existingFiles;
}
