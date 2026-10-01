import { execFile } from "node:child_process";
import { promisify } from "node:util";
import path from "node:path";
import fs from "node:fs/promises";
import { type FileContent, DEFAULT_MAX_FILE_SIZE_BYTES } from "../scanner/file-reader.js";

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

  const { stdout } = await execFileAsync("git", [
    "-c", "core.quotepath=off",
    "diff", "--cached", "--name-only", "-z", "--diff-filter=d", "--"
  ], {
    cwd: gitRoot
  });

  const lines = stdout.split("\0").map((s) => s.trim()).filter(Boolean);
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
  relativeToGitRoot: string,
  maxSizeBytes: number = DEFAULT_MAX_FILE_SIZE_BYTES
): Promise<FileContent | { skipped: true; reason: string }> {
  const normalizedRelPath = relativeToGitRoot.replace(/\\/g, "/");
  const absolutePath = path.resolve(gitRoot, normalizedRelPath);

  // Path Traversal Koruması
  const relativeCheck = path.relative(gitRoot, absolutePath);
  if (relativeCheck.startsWith("..") || path.isAbsolute(relativeCheck)) {
    return { skipped: true, reason: "path-traversal" };
  }

  // Symlink Koruması: Git Index nesne modu 120000 ise okuma
  try {
    const { stdout: lsOut } = await execFileAsync("git", ["ls-files", "-s", "--", normalizedRelPath], { cwd: gitRoot });
    if (lsOut.startsWith("120000")) {
      return { skipped: true, reason: "symlink" };
    }
  } catch {
    // ls-files çıktısı alınamazsa devam et
  }

  try {
    const { stdout: sizeOut } = await execFileAsync("git", ["cat-file", "-s", `:${normalizedRelPath}`], {
      cwd: gitRoot
    });
    const size = parseInt(sizeOut.trim(), 10);
    if (!Number.isNaN(size) && size > maxSizeBytes) {
      return { skipped: true, reason: "too-large" };
    }

    const { stdout } = await execFileAsync("git", ["show", `:${normalizedRelPath}`], {
      cwd: gitRoot,
      encoding: "buffer",
      maxBuffer: maxSizeBytes + 1024
    });

    const buffer = Buffer.isBuffer(stdout) ? stdout : Buffer.from(stdout);
    const checkLength = Math.min(buffer.length, 1024);
    let nullCount = 0;
    for (let i = 0; i < checkLength; i++) {
      if (buffer[i] === 0) {
        nullCount++;
      }
    }

    if (nullCount / checkLength > 0.01) {
      return { skipped: true, reason: "binary (null-check)" };
    }

    const content = buffer.toString("utf8").replace(/\0/g, "");
    const lines = content.split(/\r?\n/);
    return {
      path: absolutePath,
      lines,
      totalLines: lines.length
    };
  } catch (err: any) {
    return { skipped: true, reason: err.message || "read-error" };
  }
}
