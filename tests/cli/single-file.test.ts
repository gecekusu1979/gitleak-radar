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

async function runCli(args: string[], cwd?: string): Promise<CliExecutionResult> {
    try {
        const { stdout, stderr } = await execFileAsync("node", [cliEntry, ...args], { cwd });
        return { code: 0, stdout, stderr };
    } catch (err: any) {
        return {
            code: typeof err.code === "number" ? err.code : 1,
            stdout: err.stdout ? String(err.stdout) : "",
            stderr: err.stderr ? String(err.stderr) : ""
        };
    }
}

describe("CLI Single File Scan", () => {
    let tempDir: string;

    beforeEach(async () => {
        tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "gitleak-single-file-"));
    });

    afterEach(async () => {
        await fs.rm(tempDir, { recursive: true, force: true });
    });

    it("scans exactly the specified single file without ENOTDIR error", async () => {
        const targetFile = path.join(tempDir, "config.ts");
        const otherFile = path.join(tempDir, "other.ts");

        await fs.writeFile(targetFile, `export const SECRET = "AKIAIOSFODNN7QAZWSXE";\n`, "utf-8");
        await fs.writeFile(otherFile, `export const SECRET2 = "AKIAIOSFODNN7QAZWSX3";\n`, "utf-8");

        const result = await runCli(["scan", targetFile, "--json"]);

        expect(result.code).toBe(1);
        const parsed = JSON.parse(result.stdout);
        expect(parsed.summary.filesScanned).toBe(1);
        expect(parsed.findings.length).toBe(1);
        expect(parsed.findings[0].file).toContain("config.ts");
    });
});
