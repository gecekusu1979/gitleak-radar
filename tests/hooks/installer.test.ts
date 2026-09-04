import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { installPreCommitHook } from "../../src/hooks/installer.js";
import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";

describe("installPreCommitHook", () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "gitleak-hook-test-"));
    await fs.mkdir(path.join(tempDir, ".git", "hooks"), { recursive: true });
  });

  afterEach(async () => {
    try {
      await fs.rm(tempDir, { recursive: true, force: true });
    } catch {
      // ignore cleanup errors
    }
  });

  it("updates existing 0o644 hook to 0o755 and embeds severity level", async () => {
    const hookPath = path.join(tempDir, ".git", "hooks", "pre-commit");
    await fs.writeFile(hookPath, "#!/usr/bin/env sh\necho 'existing hook'\n", { mode: 0o644 });

    const result = await installPreCommitHook(tempDir, "high");
    expect(result.success).toBe(true);

    const written = await fs.readFile(hookPath, "utf-8");
    expect(written).toContain("scan --staged --severity high");

    if (process.platform !== "win32") {
      const stats = await fs.stat(hookPath);
      // Check owner executable bit
      expect(stats.mode & 0o100).not.toBe(0);
    }
  });

  it("enforces fail-closed posture by exiting with code 2 if scanner is missing", async () => {
    const hookPath = path.join(tempDir, ".git", "hooks", "pre-commit");
    const result = await installPreCommitHook(tempDir, "medium");
    expect(result.success).toBe(true);

    const written = await fs.readFile(hookPath, "utf-8");
    expect(written).toContain("Commit blocked (fail-closed)");
    expect(written).toContain("exit 2");
    expect(written).not.toContain("Skipping check");
  });
});
