import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import path from "node:path";
import fs from "node:fs/promises";
import os from "node:os";

const execFileAsync = promisify(execFile);
const cliEntry = path.resolve(process.cwd(), "dist/cli/index.js");

interface CliExecutionResult {
    code: number;
    stdout: string;
    stderr: string;
}

async function runCli(args: string[]): Promise<CliExecutionResult> {
    try {
        const { stdout, stderr } = await execFileAsync("node", [cliEntry, ...args]);
        return { code: 0, stdout, stderr };
    } catch (err: any) {
        return {
            code: typeof err.code === "number" ? err.code : 1,
            stdout: err.stdout ? String(err.stdout) : "",
            stderr: err.stderr ? String(err.stderr) : ""
        };
    }
}

describe("CLI --max-decode-depth", () => {
    let tempDir: string;

    beforeEach(async () => {
        tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "gitleak-decode-depth-e2e-"));
    });

    afterEach(async () => {
        await fs.rm(tempDir, { recursive: true, force: true });
    });

    it("is documented in scan --help", async () => {
        const result = await runCli(["scan", "--help"]);
        expect(result.stdout).toContain("--max-decode-depth");
    });

    it("rejects a non-numeric value with exit code 2", async () => {
        const result = await runCli(["scan", tempDir, "--max-decode-depth", "abc"]);
        expect(result.code).toBe(2);
        expect(result.stderr).toContain("Invalid --max-decode-depth");
    });

    it("rejects a negative value with exit code 2", async () => {
        const result = await runCli(["scan", tempDir, "--max-decode-depth", "-1"]);
        expect(result.code).toBe(2);
    });

    it("finds a Base64-hidden secret by default (no flag)", async () => {
        const encoded = Buffer.from("AKIAIOSFODNN7QAZWSXE").toString("base64");
        await fs.writeFile(path.join(tempDir, "config.env"), `token=${encoded}\n`, "utf-8");

        const result = await runCli(["scan", tempDir, "--json"]);
        expect(result.code).toBe(1);
        const parsed = JSON.parse(result.stdout);
        expect(parsed.findings.some((f: { rule: string }) => f.rule === "aws-access-key")).toBe(true);
    });

    it("suppresses the same Base64-hidden secret when --max-decode-depth 0 is passed", async () => {
        const encoded = Buffer.from("AKIAIOSFODNN7QAZWSXE").toString("base64");
        await fs.writeFile(path.join(tempDir, "config.env"), `token=${encoded}\n`, "utf-8");

        const result = await runCli(["scan", tempDir, "--max-decode-depth", "0", "--json"]);
        expect(result.code).toBe(0);
        const parsed = JSON.parse(result.stdout);
        expect(parsed.findings).toEqual([]);
    });
});
