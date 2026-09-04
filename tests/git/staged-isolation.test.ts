import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { promises as fs } from "node:fs";
import path from "node:path";
import os from "node:os";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { ProjectScanner } from "../../src/scanner/scanner.js";

const execFileAsync = promisify(execFile);

describe("Staged Scan - Index vs Worktree Isolation (P0 Fix)", () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "gitleak-staged-iso-"));
    await execFileAsync("git", ["init"], { cwd: tempDir });
    await execFileAsync("git", ["config", "user.name", "Test User"], { cwd: tempDir });
    await execFileAsync("git", ["config", "user.email", "test@example.com"], { cwd: tempDir });
    await execFileAsync("git", ["commit", "--allow-empty", "-m", "initial commit"], { cwd: tempDir });
  });

  afterEach(async () => {
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  it("detects secret in Git index even if deleted from working tree", async () => {
    const filePath = path.join(tempDir, "config.js");

    // 1. Secret'ı yaz ve stage et
    await fs.writeFile(filePath, 'const awsKey = "AKIA1234567890ABCDXE";\n', "utf8");
    await execFileAsync("git", ["add", "config.js"], { cwd: tempDir });

    // 2. Secret'ı çalışma alanından sil (git add yapma! INDEX'te secret var, WORKTREE temiz)
    await fs.writeFile(filePath, 'const awsKey = "CLEANED_SECRET";\n', "utf8");

    // 3. Staged tarama çalıştır
    const scanner = new ProjectScanner();
    const result = await scanner.scan({ path: tempDir, staged: true });

    // 4. Scanner diskteki temiz dosyayı değil, Git Index'teki AKIA secret'ını bulmalı
    expect(result.findings.length).toBe(1);
    expect(result.findings[0]?.ruleId).toBe("aws-access-key");
  });

  it("does not detect unstaged secret present only in working tree", async () => {
    const filePath = path.join(tempDir, "app.js");

    // 1. Temiz hali stage et
    await fs.writeFile(filePath, 'const awsKey = "CLEAN_INITIAL";\n', "utf8");
    await execFileAsync("git", ["add", "app.js"], { cwd: tempDir });

    // 2. Diske secret ekle ama stage etme
    await fs.writeFile(filePath, 'const awsKey = "AKIA1234567890ABCDXE";\n', "utf8");

    // 3. Staged tarama çalıştır
    const scanner = new ProjectScanner();
    const result = await scanner.scan({ path: tempDir, staged: true });

    // 4. Index temiz olduğu için 0 bulgu dönmeli
    expect(result.findings.length).toBe(0);
  });
});
