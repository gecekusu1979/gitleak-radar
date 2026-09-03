import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import path from "node:path";
import fs from "node:fs/promises";
import os from "node:os";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { getStagedFiles, isInsideGitRepo } from "../../src/git/staged.js";
import { loadConfig } from "../../src/config/loader.js";

const execFileAsync = promisify(execFile);

describe("Staged Scan and Config Verification", () => {
  let tempRepo: string;

  beforeEach(async () => {
    tempRepo = await fs.mkdtemp(path.join(os.tmpdir(), "gitleak-test-repo-"));
    await execFileAsync("git", ["init"], { cwd: tempRepo });
    await execFileAsync("git", ["config", "user.name", "TestUser"], { cwd: tempRepo });
    await execFileAsync("git", ["config", "user.email", "test@example.com"], { cwd: tempRepo });
  });

  afterEach(async () => {
    await fs.rm(tempRepo, { recursive: true, force: true });
  });

  it("identifies a valid git repository", async () => {
    const isRepo = await isInsideGitRepo(tempRepo);
    expect(isRepo).toBe(true);
  });

  it("resolves staged files properly from repository root", async () => {
    const testFile = path.join(tempRepo, "secret.txt");
    await fs.writeFile(testFile, "dummy content");
    await execFileAsync("git", ["add", "secret.txt"], { cwd: tempRepo });

    const staged = await getStagedFiles(tempRepo);
    expect(staged).toContain("secret.txt");
  });

  it("resolves staged files when called from a nested directory", async () => {
    const nestedDir = path.join(tempRepo, "src", "nested");
    await fs.mkdir(nestedDir, { recursive: true });
    const targetFile = path.join(nestedDir, "app.ts");
    await fs.writeFile(targetFile, "dummy app code");
    await execFileAsync("git", ["add", "."], { cwd: tempRepo });

    const stagedFromNested = await getStagedFiles(nestedDir);
    expect(stagedFromNested.length).toBe(1);
    expect(stagedFromNested[0].endsWith("app.ts")).toBe(true);
  });

  it("does not include unstaged files in staged scan", async () => {
    const stagedFile = path.join(tempRepo, "staged.txt");
    const unstagedFile = path.join(tempRepo, "unstaged.txt");
    await fs.writeFile(stagedFile, "staged content");
    await fs.writeFile(unstagedFile, "unstaged content");
    await execFileAsync("git", ["add", "staged.txt"], { cwd: tempRepo });

    const staged = await getStagedFiles(tempRepo);
    expect(staged).toContain("staged.txt");
    expect(staged).not.toContain("unstaged.txt");
  });

  it("throws error for invalid JSON config", async () => {
    const badConfigPath = path.join(tempRepo, ".gitleak-radar.json");
    await fs.writeFile(badConfigPath, "{ bad json ");
    await expect(loadConfig(tempRepo)).rejects.toThrow();
  });
});
