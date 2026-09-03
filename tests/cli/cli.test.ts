import { describe, it, expect } from "vitest";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import path from "node:path";

const execFileAsync = promisify(execFile);

describe("CLI Smoke Tests", () => {
  const cliEntry = path.resolve(process.cwd(), "dist/cli/index.js");

  it("returns package version on --version", async () => {
    const { stdout } = await execFileAsync("node", [cliEntry, "--version"]);
    expect(stdout.trim()).toMatch(/^\d+\.\d+\.\d+/);
  });

  it("outputs standard command list on --help", async () => {
    const { stdout } = await execFileAsync("node", [cliEntry, "--help"]);
    expect(stdout).toContain("scan");
    expect(stdout).toContain("rules");
    expect(stdout).toContain("install-hook");
  });

  it("outputs scan options on scan --help", async () => {
    const { stdout } = await execFileAsync("node", [cliEntry, "scan", "--help"]);
    expect(stdout).toContain("--severity");
    expect(stdout).toContain("--staged");
    expect(stdout).toContain("--json");
    expect(stdout).toContain("--verbose");
  });
});
