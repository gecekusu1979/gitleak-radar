import { execFile } from "node:child_process";
import { promisify } from "node:util";
import path from "node:path";
import fs from "node:fs/promises";
import { type FileContent, MAX_FILE_SIZE_BYTES } from "../scanner/file-reader.js";

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

  const { stdout } = await execFileAsync("git", ["diff", "--cached", "--name-only", "--diff-filter=d", "--"], {
    cwd: gitRoot
  });

  const lines = stdout.split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
  const existingFiles: string[] = [];

  for (const relativeToGitRoot of lines) {
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

export async function readStagedFileLines(
  gitRoot: string,
  relativeToGitRoot: string
): Promise<FileContent | null> {
  const normalizedRelPath = relativeToGitRoot.replace(/\\/g, "/");
  const absolutePath = path.resolve(gitRoot, normalizedRelPath);

  // Path Traversal Koruması: Dosya yolu gitRoot dışına çıkamaz
  const relativeCheck = path.relative(gitRoot, absolutePath);
  if (relativeCheck.startsWith("..") || path.isAbsolute(relativeCheck)) {
    return null;
  }

  // Symlink Koruması: Git Index nesne modu 120000 (symlink) ise okuma
  try {
    const { stdout: lsOut } = await execFileAsync("git", ["ls-files", "-s", "--", normalizedRelPath], { cwd: gitRoot });
    if (lsOut.startsWith("120000")) {
      return null;
    }
  } catch {
    // ls-files çıktısı alınamazsa devam et
  }

  try {
    const { stdout: sizeOut } = await execFileAsync("git", ["cat-file", "-s", `:${normalizedRelPath}`], {
      cwd: gitRoot
    });
    const size = parseInt(sizeOut.trim(), 10);
    if (!Number.isNaN(size) && size > MAX_FILE_SIZE_BYTES) {
      return null;
    }

    const { stdout } = await execFileAsync("git", ["show", `:${normalizedRelPath}`], {
      cwd: gitRoot,
      encoding: "buffer",
      maxBuffer: MAX_FILE_SIZE_BYTES + 1024
    });

    const buffer = Buffer.isBuffer(stdout) ? stdout : Buffer.from(stdout);
    const checkLength = Math.min(buffer.length, 1024);
    for (let i = 0; i < checkLength; i++) {
      if (buffer[i] === 0) {
        return null;
      }
    }

    const content = buffer.toString("utf8");
    const lines = content.split(/\r?\n/);
    return {
      path: absolutePath,
      lines,
      totalLines: lines.length
    };
  } catch {
    return null;
  }
}
