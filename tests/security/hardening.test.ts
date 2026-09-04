import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { promises as fs } from "node:fs";
import path from "node:path";
import os from "node:os";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { readFileLines } from "../../src/scanner/file-reader.js";
import { SecretDetector } from "../../src/detectors/detector.js";
import { DETECTION_RULES } from "../../src/detectors/rules.js";
import { readStagedFileLines } from "../../src/git/staged.js";

const execFileAsync = promisify(execFile);

describe("Self-Security Hardening Suite", () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "gitleak-hardening-"));
  });

  afterEach(async () => {
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  it("prevents symlink exploitation by refusing to follow symlinks to external files", async () => {
    const externalSecret = path.join(tempDir, "external-secret.env");
    await fs.writeFile(externalSecret, 'AWS_KEY="AKIA1234567890ABCDXE"', "utf-8");

    const repoDir = path.join(tempDir, "repo");
    await fs.mkdir(repoDir);
    const symlinkPath = path.join(repoDir, "symlink-to-secret.env");
    
    try {
      await fs.symlink(externalSecret, symlinkPath);
    } catch {
      // Windows'ta Developer Mode / Symlink izni yoksa atla
      return;
    }

    const content = await readFileLines(symlinkPath);
    expect(content).toBeNull();
  });

  it("prevents path traversal outside git repository in readStagedFileLines", async () => {
    await execFileAsync("git", ["init"], { cwd: tempDir });
    const traversalResult = await readStagedFileLines(tempDir, "../../../etc/passwd");
    expect(traversalResult).toBeNull();
  });

  it("protects against ReDoS by bounding line scan length within safe threshold", () => {
    const detector = new SecretDetector(DETECTION_RULES);
    const massiveLine = "const a = 1; " + "x".repeat(200000);

    const startTime = performance.now();
    const findings = detector.scanLine(massiveLine, 1, "bundle.min.js");
    const duration = performance.now() - startTime;

    expect(duration).toBeLessThan(50);
    expect(findings).toEqual([]);
  });
});
