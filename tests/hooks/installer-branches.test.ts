import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { installPreCommitHook } from "../../src/hooks/installer.js";
import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";

describe("installPreCommitHook - branch coverage", () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "gitleak-hook-branch-"));
  });

  afterEach(async () => {
    vi.restoreAllMocks();
    try {
      await fs.rm(tempDir, { recursive: true, force: true });
    } catch {
      // ignore cleanup errors
    }
  });

  it("rejects an invalid severity level before touching the filesystem", async () => {
    const result = await installPreCommitHook(tempDir, "extreme");

    expect(result.success).toBe(false);
    expect(result.message).toContain('Invalid severity level "extreme"');
    expect(result.message).toContain("low, medium, high, critical");

    // .git was never created, and installer must not have created one either.
    const gitExists = await fs
      .stat(path.join(tempDir, ".git"))
      .then(() => true)
      .catch(() => false);
    expect(gitExists).toBe(false);
  });

  it("defaults to 'low' severity when none is provided", async () => {
    await fs.mkdir(path.join(tempDir, ".git", "hooks"), { recursive: true });

    const result = await installPreCommitHook(tempDir);
    expect(result.success).toBe(true);

    const written = await fs.readFile(path.join(tempDir, ".git", "hooks", "pre-commit"), "utf-8");
    expect(written).toContain("scan --staged --severity low");
  });

  it("trims and lowercases the severity argument", async () => {
    await fs.mkdir(path.join(tempDir, ".git", "hooks"), { recursive: true });

    const result = await installPreCommitHook(tempDir, "  CRITICAL  ");
    expect(result.success).toBe(true);

    const written = await fs.readFile(path.join(tempDir, ".git", "hooks", "pre-commit"), "utf-8");
    expect(written).toContain("scan --staged --severity critical");
  });

  it("fails when no .git directory exists at all", async () => {
    const result = await installPreCommitHook(tempDir, "low");

    expect(result.success).toBe(false);
    expect(result.message).toBe("No .git directory found. Run 'git init' first.");
  });

  it("fails when .git exists but is a file, not a directory", async () => {
    // Mirrors a Git worktree or submodule, where .git is a pointer file.
    await fs.writeFile(path.join(tempDir, ".git"), "gitdir: ../.git/worktrees/example\n");

    const result = await installPreCommitHook(tempDir, "low");

    expect(result.success).toBe(false);
    expect(result.message).toBe("Target .git is not a directory. Run 'git init' first.");
  });

  it("is idempotent: a second install leaves an already-marked hook untouched", async () => {
    await fs.mkdir(path.join(tempDir, ".git", "hooks"), { recursive: true });

    const first = await installPreCommitHook(tempDir, "high");
    expect(first.success).toBe(true);

    const hookPath = path.join(tempDir, ".git", "hooks", "pre-commit");
    const afterFirstInstall = await fs.readFile(hookPath, "utf-8");

    const second = await installPreCommitHook(tempDir, "low");
    expect(second.success).toBe(true);
    expect(second.message).toBe("GitLeak Radar pre-commit hook is already installed and up to date.");

    // Content must be byte-for-byte unchanged: no duplicate hook block, and the
    // severity from the first install (high) must NOT be overwritten by the second (low).
    const afterSecondInstall = await fs.readFile(hookPath, "utf-8");
    expect(afterSecondInstall).toBe(afterFirstInstall);
    expect(afterSecondInstall).toContain("scan --staged --severity high");
    expect(
      afterSecondInstall.split("--- GITLEAK-RADAR-HOOK-START ---").length - 1
    ).toBe(1);
  });

  it("returns a failure result when writing the hook file throws", async () => {
    await fs.mkdir(path.join(tempDir, ".git", "hooks"), { recursive: true });

    const writeFileSpy = vi.spyOn(fs, "writeFile").mockRejectedValueOnce(new Error("EACCES: permission denied"));

    const result = await installPreCommitHook(tempDir, "low");

    expect(result.success).toBe(false);
    expect(result.message).toBe("EACCES: permission denied");
    expect(writeFileSpy).toHaveBeenCalled();
  });

  it("reports failure when the hook file cannot be made executable", async () => {
    if (process.platform === "win32") {
      return;
    }
    await fs.mkdir(path.join(tempDir, ".git", "hooks"), { recursive: true });

    const hookPath = path.join(tempDir, ".git", "hooks", "pre-commit");
    const realStat = fs.stat;
    vi.spyOn(fs, "stat").mockImplementation(async (target, ...rest) => {
      const stats = await realStat(target as string, ...(rest as []));
      if (String(target) === hookPath) {
        // Simulate a filesystem that silently dropped the executable bits.
        return Object.assign(Object.create(Object.getPrototypeOf(stats)), stats, {
          mode: stats.mode & ~0o111
        });
      }
      return stats;
    });

    const result = await installPreCommitHook(tempDir, "low");

    expect(result.success).toBe(false);
    expect(result.message).toBe("Failed to set executable permissions on hook file.");
  });
});
