import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import { generateFingerprint, saveBaseline, loadBaselineFingerprints, filterFindingsByBaseline } from "../../src/baseline/baseline.js";
import { type Finding } from "../../src/types/index.js";
import { ProjectScanner } from "../../src/scanner/scanner.js";

const MOCK_STRIPE = ["sk", "live", "abcdef1234567890abcdef1234"].join("_");

describe("Baseline / Allowlist Engine", () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "gitleak-baseline-"));
  });

  afterEach(async () => {
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  const mockFinding: Finding = {
    ruleId: "stripe-api-key",
    ruleName: "Stripe API Key",
    severity: "critical",
    file: "src/payments.ts",
    line: 12,
    column: 5,
    maskedValue: "sk_live_********************1234"
  };

  it("generates deterministic fingerprint regardless of OS path separators", () => {
    const windowsFinding = { ...mockFinding, file: "src\\payments.ts" };
    const posixFinding = { ...mockFinding, file: "src/payments.ts" };

    expect(generateFingerprint(windowsFinding)).toBe(generateFingerprint(posixFinding));
  });

  it("saves and loads baseline fingerprints accurately", async () => {
    const baselinePath = path.join(tempDir, ".gitleak-radar-baseline.json");
    await saveBaseline(baselinePath, [mockFinding]);

    const loadedFPs = await loadBaselineFingerprints(baselinePath);
    expect(loadedFPs.size).toBe(1);
    expect(loadedFPs.has(generateFingerprint(mockFinding))).toBe(true);
  });

  it("filters out baselined findings and retains new findings", () => {
    const newFinding: Finding = {
      ruleId: "aws-access-key",
      ruleName: "AWS Access Key",
      severity: "critical",
      file: "src/aws.ts",
      line: 4,
      column: 1,
      maskedValue: "AKIA****************"
    };

    const baselineSet = new Set([generateFingerprint(mockFinding)]);
    const result = filterFindingsByBaseline([mockFinding, newFinding], baselineSet);

    expect(result.suppressedCount).toBe(1);
    expect(result.activeFindings.length).toBe(1);
    expect(result.activeFindings[0]!.ruleId).toBe("aws-access-key");
  });

  it("creates baseline file and ignores findings in subsequent scan via ProjectScanner", async () => {
    const secretFile = path.join(tempDir, "config.js");
    await fs.writeFile(secretFile, `const key = "${MOCK_STRIPE}";\n`, "utf-8");

    const scanner = new ProjectScanner();

    // 1. İlk tarama bulguyu yakalar
    const initialResult = await scanner.scan({ path: tempDir });
    expect(initialResult.findings.length).toBe(1);

    // 2. Baseline oluştur
    const baselineFile = path.join(tempDir, ".gitleak-radar-baseline.json");
    await scanner.scan({ path: tempDir, createBaseline: baselineFile });

    // 3. Baseline varken tekrar tara -> Bulguyu susturmalı, skor 100 olmalı
    const afterBaselineResult = await scanner.scan({ path: tempDir, baselinePath: baselineFile });
    expect(afterBaselineResult.findings.length).toBe(0);
    expect(afterBaselineResult.summary.suppressedFindings).toBe(1);
    expect(afterBaselineResult.summary.score).toBe(100);
  });
});
