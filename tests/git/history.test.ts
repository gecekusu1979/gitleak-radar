import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { scan } from "../../src/scanner/scanner.js";

const execFileAsync = promisify(execFile);

describe("Git History Scanning (Hardened Engine)", () => {
  let tempRepo: string;
  const fakeStripeKey = ["sk", "live", "51AbCdEfGhIjKlMnOpQrStUvWxYz12345"].join("_");

  beforeEach(async () => {
    tempRepo = await fs.mkdtemp(path.join(os.tmpdir(), "gitleak-hist-"));
    await execFileAsync("git", ["init"], { cwd: tempRepo });
    await execFileAsync("git", ["config", "user.name", "Security Lead | Auditor"], { cwd: tempRepo });
    await execFileAsync("git", ["config", "user.email", "auditor@enterprise.local"], { cwd: tempRepo });
  });

  afterEach(async () => {
    await fs.rm(tempRepo, { recursive: true, force: true });
  });

  it("handles empty repository with zero commits gracefully without crashing", async () => {
    const result = await scan({ path: tempRepo, history: true });
    expect(result.findings.length).toBe(0);
    expect(result.summary.commitsScanned).toBe(0);
  });

  it("detects secrets committed in past history even if deleted in current HEAD", async () => {
    const filePath = path.join(tempRepo, "secret-leak.txt");

    // 1. Commit: Stripe canlı anahtarı sızdırılıyor (dinamik string)
    await fs.writeFile(filePath, `stripe = ${fakeStripeKey}\n`, "utf8");
    await execFileAsync("git", ["add", "secret-leak.txt"], { cwd: tempRepo });
    await execFileAsync("git", ["commit", "-m", "chore: add payment config"], { cwd: tempRepo });

    // 2. Commit: Sızıntı diskten siliniyor
    await fs.writeFile(filePath, "stripe = process.env.STRIPE_KEY\n", "utf8");
    await execFileAsync("git", ["add", "secret-leak.txt"], { cwd: tempRepo });
    await execFileAsync("git", ["commit", "-m", "fix: remove hardcoded key"], { cwd: tempRepo });

    // Standart tarama: Disk temiz, 0 bulgu
    const cleanScan = await scan({ path: tempRepo });
    expect(cleanScan.findings.length).toBe(0);

    // History taraması: Git veritabanındaki sızıntıyı commit hash'i ve yazar bilgisiyle yakalamalı
    const historyScan = await scan({ path: tempRepo, history: true });
    expect(historyScan.findings.length).toBe(1);
    expect(historyScan.findings[0]?.ruleId).toBe("stripe-api-key");
    expect(historyScan.findings[0]?.commit).toBeDefined();
    expect(historyScan.findings[0]?.commit?.length).toBe(40);
    expect(historyScan.findings[0]?.commitAuthor).toBe("Security Lead | Auditor");
    expect(historyScan.findings[0]?.commitDate).toBeDefined();
    expect(historyScan.summary.commitsScanned).toBe(2);
  });

  it("respects ignore patterns during history diff stream", async () => {
    const docsPath = path.join(tempRepo, "README.md");
    await fs.writeFile(docsPath, `doc example ${fakeStripeKey}\n`, "utf8");
    await execFileAsync("git", ["add", "README.md"], { cwd: tempRepo });
    await execFileAsync("git", ["commit", "-m", "docs: update"], { cwd: tempRepo });

    const scanResult = await scan({
      path: tempRepo,
      history: true,
      ignore: ["*.md"]
    });

    expect(scanResult.findings.length).toBe(0);
  });
});
