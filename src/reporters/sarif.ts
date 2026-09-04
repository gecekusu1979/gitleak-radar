import fs from "node:fs";
import path from "node:path";
import chalk from "chalk";
import { type Finding, type ScanResult, type Severity } from "../types/index.js";
import { DETECTION_RULES } from "../detectors/rules.js";

export type SarifLevel = "error" | "warning" | "note";

export function mapSeverityToSarifLevel(severity: Severity): SarifLevel {
  switch (severity) {
    case "critical":
    case "high":
      return "error";
    case "medium":
      return "warning";
    case "low":
      return "note";
  }
}

export interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  defaultConfiguration: { level: SarifLevel };
  help: { text: string };
  properties: { tags: string[] };
}

export interface SarifResultLocation {
  physicalLocation: {
    artifactLocation: { uri: string; uriBaseId: string };
    region: { startLine: number; startColumn: number };
  };
}

export interface SarifResult {
  ruleId: string;
  level: SarifLevel;
  message: { text: string };
  locations: SarifResultLocation[];
  partialFingerprints?: Record<string, string>;
  properties?: Record<string, unknown>;
}

export interface SarifLog {
  $schema: string;
  version: "2.1.0";
  runs: Array<{
    tool: {
      driver: {
        name: string;
        version: string;
        informationUri: string;
        rules: SarifRule[];
      };
    };
    results: SarifResult[];
  }>;
}

export function generateSarifReport(result: ScanResult, toolVersion = "1.0.0"): SarifLog {
  const sarifRules: SarifRule[] = DETECTION_RULES.map((rule) => ({
    id: rule.id,
    name: rule.name,
    shortDescription: { text: rule.description },
    defaultConfiguration: { level: mapSeverityToSarifLevel(rule.severity) },
    help: { text: `Hardcoded secret of type '${rule.name}' was detected. Revoke and rotate this secret immediately.` },
    properties: { tags: ["security", "secret", "credentials", rule.severity] }
  }));

  const sarifResults: SarifResult[] = result.findings.map((f: Finding): SarifResult => {
    const sarifFinding: SarifResult = {
      ruleId: f.ruleId,
      level: mapSeverityToSarifLevel(f.severity),
      message: {
        text: `Secret detected by rule '${f.ruleName}' (masked: ${f.maskedValue})`
      },
      locations: [
        {
          physicalLocation: {
            artifactLocation: {
              uri: f.file.replace(/\\/g, "/"),
              uriBaseId: "%SRCROOT%"
            },
            region: {
              startLine: Math.max(1, f.line),
              startColumn: Math.max(1, f.column)
            }
          }
        }
      ]
    };

    if (f.commit) {
      sarifFinding.partialFingerprints = {
        commitHash: f.commit
      };
      sarifFinding.properties = {
        commit: f.commit,
        commitAuthor: f.commitAuthor,
        commitDate: f.commitDate
      };
    }

    return sarifFinding;
  });

  return {
    $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "GitLeak Radar",
            version: toolVersion,
            informationUri: "https://github.com/gecekusu1979/gitleak-radar",
            rules: sarifRules
          }
        },
        results: sarifResults
      }
    ]
  };
}

export function renderSarifReport(result: ScanResult, outputPath?: string, toolVersion = "1.0.0"): void {
  const sarif = generateSarifReport(result, toolVersion);
  const jsonContent = JSON.stringify(sarif, null, 2);

  if (outputPath) {
    const resolvedPath = path.resolve(process.cwd(), outputPath);
    fs.mkdirSync(path.dirname(resolvedPath), { recursive: true });
    fs.writeFileSync(resolvedPath, jsonContent, "utf-8");
    console.log(chalk.green(`✓ SARIF report saved to: ${outputPath}`));
  } else {
    console.log(jsonContent);
  }
}
