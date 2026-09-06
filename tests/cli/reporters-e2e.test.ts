import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import path from "node:path";
import fs from "node:fs/promises";
import os from "node:os";

const execFileAsync = promisify(execFile);
const cliEntry = path.resolve(process.cwd(), "dist/cli/index.js");
const MOCK_STRIPE = ["sk", "live", "abcdef1234567890abcdef1234"].join("_");

interface CliExecutionResult {
  code: number;
  stdout: string;
  stderr: string;
}

async function runCli(args: string[], env: Record<string, string> = {}): Promise<CliExecutionResult> {
  try {
    const { stdout, stderr } = await execFileAsync("node", [cliEntry, ...args], {
      env: { ...process.env, ...env }
    });
    return { code: 0, stdout, stderr };
  } catch (err: any) {
    return {
      code: typeof err.code === "number" ? err.code : 1,
      stdout: err.stdout ? String(err.stdout) : "",
      stderr: err.stderr ? String(err.stderr) : ""
    };
  }
}

describe("CLI Reporters E2E Integration", () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "gitleak-reporters-e2e-"));
  });

  afterEach(async () => {
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  it("emits GitHub Actions workflow annotations to stdout with --github-actions", async () => {
    const secretFile = path.join(tempDir, "config.ts");
    await fs.writeFile(secretFile, `export const apiKey = "${MOCK_STRIPE}";\n`, "utf-8");

    const result = await runCli(["scan", tempDir, "--github-actions"]);

    expect(result.code).toBe(1);
    expect(result.stdout).toContain("::error file=");
    expect(result.stdout).toContain("title=GitLeak Radar");
    expect(result.stdout).toContain("stripe-api-key");
  });

  it("exports valid JUnit XML report to file with --junit <file>", async () => {
    const secretFile = path.join(tempDir, "auth.ts");
    await fs.writeFile(secretFile, `export const secret = "${MOCK_STRIPE}";\n`, "utf-8");

    const xmlOutputFile = path.join(tempDir, "reports", "junit.xml");
    const result = await runCli(["scan", tempDir, "-s", "high", "--junit", xmlOutputFile]);

    expect(result.code).toBe(1);

    const fileExists = await fs.stat(xmlOutputFile).then(() => true).catch(() => false);
    expect(fileExists).toBe(true);

    const xmlContent = await fs.readFile(xmlOutputFile, "utf-8");
    expect(xmlContent).toContain('<?xml version="1.0" encoding="UTF-8"?>');
    expect(xmlContent).toContain('<testsuites name="GitLeak Radar"');
    expect(xmlContent).toContain('failures="1"');
    expect(xmlContent).toContain('Stripe API Key');
    expect(xmlContent).toContain('SecurityLeak');
  });

  it("exports valid GitLab Code Quality JSON to file with --gitlab <file>", async () => {
    const secretFile = path.join(tempDir, "service.ts");
    await fs.writeFile(secretFile, `export const secret = "${MOCK_STRIPE}";\n`, "utf-8");

    const glOutputFile = path.join(tempDir, "reports", "gl-quality.json");
    const result = await runCli(["scan", tempDir, "-s", "high", "--gitlab", glOutputFile]);

    expect(result.code).toBe(1);

    const fileExists = await fs.stat(glOutputFile).then(() => true).catch(() => false);
    expect(fileExists).toBe(true);

    const glContent = await fs.readFile(glOutputFile, "utf-8");
    const parsed = JSON.parse(glContent);

    expect(Array.isArray(parsed)).toBe(true);
    expect(parsed.length).toBe(1);
    expect(parsed[0].check_name).toBe("stripe-api-key");
    expect(parsed[0].severity).toBe("blocker");
    expect(parsed[0].fingerprint).toHaveLength(64);
  });

  it("exits with status 0 and clean JUnit report when no secrets are present", async () => {
    const cleanFile = path.join(tempDir, "index.ts");
    await fs.writeFile(cleanFile, 'export const greeting = "hello world";\n', "utf-8");

    const xmlOutputFile = path.join(tempDir, "clean-junit.xml");
    const result = await runCli(["scan", tempDir, "--junit", xmlOutputFile]);

    expect(result.code).toBe(0);

    const xmlContent = await fs.readFile(xmlOutputFile, "utf-8");
    expect(xmlContent).toContain('failures="0"');
    expect(xmlContent).toContain('name="NoSecretsDetected"');
  });
});
