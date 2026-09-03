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

export async function getGitRoot(targetDir: string): Promise<string> {
  const { stdout } = await execFileAsync("git", ["rev-parse", "--show-toplevel"], {
    cwd: targetDir
  });
  return stdout.trim();
}

export async function getStagedFiles(targetDir: string): Promise<string[]> {
  const isRepo = await isInsideGitRepo(targetDir);
  if (!isRepo) {
    throw new Error("Target directory is not a Git repository or git is not installed.");
  }

  const gitRoot = await getGitRoot(targetDir);

  // Name-only staged files excluding deleted (filter=d)
  const { stdout } = await execFileAsync("git", ["diff", "--cached", "--name-only", "--diff-filter=d"], {
    cwd: gitRoot
  });

  const lines = stdout.split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
  const existingFiles: string[] = [];

  for (const relativeToGitRoot of lines) {
    const absoluteFilePath = path.resolve(gitRoot, relativeToGitRoot);
    try {
      const stat = await fs.stat(absoluteFilePath);
      if (stat.isFile()) {
        // targetDir'e göre göreceli yol (scanner'ın path.resolve(targetDir, ...) ile uyumlu olması için)
        const relToTarget = path.relative(targetDir, absoluteFilePath);
        existingFiles.push(relToTarget.replace(/\\/g, "/"));
      }
    } catch {
      // Dosya silinmiş veya erişilemiyorsa atla
    }
  }

  return existingFiles;
}
