import fs from "node:fs";
import path from "node:path";
import { type Finding, type ScanResult } from "../types/index.js";

function escapeXml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

export function generateJunitXml(result: ScanResult): string {
  const durationSec = (result.summary.durationMs / 1000).toFixed(3);
  const totalFindings = result.findings.length;
  const filesCount = result.summary.filesScanned;

  // Dosya bazlı bulguları grupla
  const findingsByFile = new Map<string, Finding[]>();
  for (const finding of result.findings) {
    const list = findingsByFile.get(finding.file) ?? [];
    list.push(finding);
    findingsByFile.set(finding.file, list);
  }

  const xmlLines: string[] = [
    '<?xml version="1.0" encoding="UTF-8"?>',
    `<testsuites name="GitLeak Radar" tests="${Math.max(filesCount, totalFindings, 1)}" failures="${totalFindings}" errors="0" time="${durationSec}">`
  ];

  if (totalFindings === 0) {
    xmlLines.push(
      `  <testsuite name="Security.SecretScanning" tests="1" failures="0" errors="0" time="${durationSec}">`,
      `    <testcase classname="GitLeakRadar" name="NoSecretsDetected" time="${durationSec}" />`,
      '  </testsuite>'
    );
  } else {
    for (const [file, findings] of findingsByFile.entries()) {
      const suiteName = escapeXml(`Security.SecretScanning.${file.replace(/[\\/]/g, ".")}`);
      xmlLines.push(
        `  <testsuite name="${suiteName}" tests="${findings.length}" failures="${findings.length}" errors="0" time="${durationSec}">`
      );

      for (const f of findings) {
        const testName = escapeXml(`${f.ruleName} at line ${f.line}:${f.column}`);
        const className = escapeXml(f.file);
        const failureMessage = escapeXml(
          `[${f.severity.toUpperCase()}] ${f.ruleName} detected: ${f.maskedValue} (${f.ruleId})`
        );
        const failureBody = escapeXml(
          `Secret finding in ${f.file}:${f.line}:${f.column}\nRule ID: ${f.ruleId}\nSeverity: ${f.severity}\nMasked Secret: ${f.maskedValue}\nRemediation: Revoke and rotate this credential immediately.`
        );

        xmlLines.push(
          `    <testcase classname="${className}" name="${testName}" time="0.001">`,
          `      <failure message="${failureMessage}" type="SecurityLeak">${failureBody}</failure>`,
          '    </testcase>'
        );
      }

      xmlLines.push('  </testsuite>');
    }
  }

  xmlLines.push('</testsuites>');
  return xmlLines.join("\n");
}

export function renderJunitReport(result: ScanResult, outputPath?: string): void {
  const xml = generateJunitXml(result);

  if (outputPath) {
    const resolvedPath = path.resolve(process.cwd(), outputPath);
    fs.mkdirSync(path.dirname(resolvedPath), { recursive: true });
    fs.writeFileSync(resolvedPath, xml + "\n", "utf-8");
  } else {
    console.log(xml);
  }
}
