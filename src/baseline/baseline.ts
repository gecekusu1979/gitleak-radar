import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { type Finding } from "../types/index.js";

export interface BaselineEntry {
  fingerprint: string;
  ruleId: string;
  file: string;
  line: number;
}

export interface BaselineFile {
  version: "1.0";
  createdAt: string;
  totalFindings: number;
  entries: BaselineEntry[];
}

export function generateFingerprint(finding: Finding): string {
  const normalizedFile = finding.file.replace(/\\/g, "/");
    const secretIdentity = finding.secretHash ?? finding.maskedValue;
  const rawKey = `${normalizedFile}:${finding.ruleId}:${secretIdentity}`;
  return crypto.createHash("sha256").update(rawKey).digest("hex");
}

export async function saveBaseline(filePath: string, findings: Finding[]): Promise<void> {
  const entries: BaselineEntry[] = findings.map((f) => ({
    fingerprint: generateFingerprint(f),
    ruleId: f.ruleId,
    file: f.file.replace(/\\/g, "/"),
    line: f.line
  }));

  const baselineData: BaselineFile = {
    version: "1.0",
    createdAt: new Date().toISOString(),
    totalFindings: entries.length,
    entries
  };

  await fs.writeFile(filePath, JSON.stringify(baselineData, null, 2) + "\n", "utf-8");
}

export async function loadBaselineFingerprints(filePath: string): Promise<Set<string>> {
  try {
    const raw = await fs.readFile(filePath, "utf-8");
    const parsed: BaselineFile = JSON.parse(raw);
    if (!parsed.entries || !Array.isArray(parsed.entries)) {
      return new Set();
    }
    return new Set(parsed.entries.map((e) => e.fingerprint));
  } catch {
    return new Set();
  }
}

export function filterFindingsByBaseline(
  findings: Finding[],
  baselineFingerprints: Set<string>
): { activeFindings: Finding[]; suppressedCount: number } {
  if (baselineFingerprints.size === 0) {
    return { activeFindings: findings, suppressedCount: 0 };
  }

  const activeFindings: Finding[] = [];
  let suppressedCount = 0;

  for (const finding of findings) {
    const fp = generateFingerprint(finding);
    if (baselineFingerprints.has(fp)) {
      suppressedCount++;
    } else {
      activeFindings.push(finding);
    }
  }

  return { activeFindings, suppressedCount };
}
