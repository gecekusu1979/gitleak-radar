import { describe, it, expect, vi } from "vitest";
import { generateJunitXml, renderJunitReport } from "../../src/reporters/junit.js";
import { type ScanResult } from "../../src/types/index.js";
import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";

describe("JUnit XML Reporter", () => {
  it("generates valid passing JUnit XML when there are no findings", () => {
    const cleanResult: ScanResult = {
      summary: {
        filesScanned: 5,
        linesScanned: 120,
        findings: 0,
        score: 100,
        tier: "Excellent",
        durationMs: 42
      },
      findings: []
    };

    const xml = generateJunitXml(cleanResult);
    expect(xml).toContain('<?xml version="1.0" encoding="UTF-8"?>');
    expect(xml).toContain('<testsuites name="GitLeak Radar"');
    expect(xml).toContain('failures="0"');
    expect(xml).toContain('<testcase classname="GitLeakRadar" name="NoSecretsDetected"');
  });

  it("generates failure testcases for findings with proper XML escaping", () => {
    const dirtyResult: ScanResult = {
      summary: {
        filesScanned: 2,
        linesScanned: 50,
        findings: 1,
        score: 40,
        tier: "Critical",
        durationMs: 15
      },
      findings: [
        {
          ruleId: "aws-access-key",
          ruleName: "AWS & Secret <Key>",
          severity: "critical",
          file: "src/auth.ts",
          line: 14,
          column: 7,
          maskedValue: "AKIA****************"
        }
      ]
    };

    const xml = generateJunitXml(dirtyResult);
    expect(xml).toContain('failures="1"');
    expect(xml).toContain('AWS &amp; Secret &lt;Key&gt;');
    expect(xml).toContain('<failure message="[CRITICAL] AWS &amp; Secret &lt;Key&gt;');
    expect(xml).toContain('SecurityLeak');
  });

  it("writes JUnit XML to disk when outputPath is provided", async () => {
    const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "gitleak-junit-"));
    const reportFile = path.join(tempDir, "junit.xml");

    const result: ScanResult = {
      summary: { filesScanned: 1, linesScanned: 10, findings: 0, score: 100, tier: "Excellent", durationMs: 5 },
      findings: []
    };

    renderJunitReport(result, reportFile);
    const content = await fs.readFile(reportFile, "utf-8");
    expect(content).toContain("<testsuites");

    await fs.rm(tempDir, { recursive: true, force: true });
  });
});
