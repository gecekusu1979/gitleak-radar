import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import { ProjectScanner } from "../../src/scanner/scanner.js";
import { getChangedFilesSince } from "../../src/git/incremental.js";

const execFileAsync = promisify(execFile);
const MOCK_STRIPE = ["sk", "live", "abcdef1234567890abcdef1234"].join("_");

describe("Incremental Scan (--since <ref>)", () => {
  let tempRepo: string;

  beforeEach(async () => {
    tempRepo = await fs.mkdtemp(path.join(os.tmpdir(), "gitleak-since-"));
    await execFileAsync("git", ["init"], { cwd: tempRepo });
    await execFileAsync("git", ["config", "user.name", "Test Runner"], { cwd: tempRepo });
    await execFileAsync("git", ["config", "user.email", "test@example.com"], { cwd: tempRepo });

    await fs.writeFile(path.join(tempRepo, "existing.ts"), "export const a = 1;\n", "utf-8");
    await execFileAsync("git", ["add", "."], { cwd: tempRepo });
    await execFileAsync("git", ["commit", "-m", "Initial commit"], { cwd: tempRepo });
  });

  afterEach(async () => {
    await fs.rm(tempRepo, { recursive: true, force: true });
  });

  it("identifies changed files since specified commit ref", async () => {
    await fs.writeFile(
      path.join(tempRepo, "new-secret.ts"),
      `const stripeKey = "${MOCK_STRIPE}";\n`,
      "utf-8"
    );
    await execFileAsync("git", ["add", "."], { cwd: tempRepo });
    await execFileAsync("git", ["commit", "-m", "Add new file"], { cwd: tempRepo });

    const changed = await getChangedFilesSince(tempRepo, "HEAD~1");
    expect(changed).toContain("new-secret.ts");
    expect(changed).not.toContain("existing.ts");
  });

  it("scans only modified files when --since is provided to scanner", async () => {
    await fs.writeFile(
      path.join(tempRepo, "modified.ts"),
      `const stripeKey = "${MOCK_STRIPE}";\n`,
      "utf-8"
    );

    const scanner = new ProjectScanner();
    const result = await scanner.scan({
      path: tempRepo,
      since: "HEAD"
    });

    expect(result.summary.filesScanned).toBe(1);
    expect(result.findings.length).toBe(1);
    expect(result.findings[0]!.file).toBe("modified.ts");
  });

  it("throws clear error when invalid git ref is provided", async () => {
    const scanner = new ProjectScanner();
    await expect(
      scanner.scan({
        path: tempRepo,
        since: "invalid-branch-ref-999"
      })
    ).rejects.toThrow("Failed to resolve git reference");
  });

  it("prevents flag/argument injection attacks when ref starts with dashes", async () => {
    const maliciousFile = path.join(tempRepo, "pwned.txt");
    const maliciousRef = `--output=${maliciousFile}`;

    await expect(getChangedFilesSince(tempRepo, maliciousRef)).rejects.toThrow();

    const fileExists = await fs.stat(maliciousFile).then(() => true).catch(() => false);
    expect(fileExists).toBe(false);
  });
});
