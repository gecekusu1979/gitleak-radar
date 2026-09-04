#!/usr/bin/env node
import { Command } from "commander";
import chalk from "chalk";
import ora from "ora";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { ProjectScanner } from "../scanner/scanner.js";
import { renderTerminalReport } from "../reporters/terminal.js";
import { renderJsonReport } from "../reporters/json.js";
import { DETECTION_RULES } from "../detectors/rules.js";
import { installPreCommitHook } from "../hooks/installer.js";
import { Severity } from "../types/index.js";

function getPackageVersion(): string {
  try {
    const currentDir = path.dirname(fileURLToPath(import.meta.url));
    const packagePath = path.resolve(currentDir, "../../package.json");
    if (fs.existsSync(packagePath)) {
      const raw = fs.readFileSync(packagePath, "utf-8");
      return JSON.parse(raw).version || "1.0.0";
    }
  } catch {
    // fallback
  }
  return "1.0.0";
}

const program = new Command();

program
  .name("gitleak-radar")
  .description("GitLeak Radar - Fast, local source-code secret scanner CLI.")
  .version(getPackageVersion(), "-V, --version", "Output the current version")
  .helpOption("-h, --help", "Display help for command");

program
  .command("scan")
  .description("Scan files or staged Git changes for sensitive credentials and secrets")
  .argument("[path]", "Target directory path to scan", ".")
  .option("-s, --severity <level>", "Minimum severity threshold (low, medium, high, critical)", "low")
  .option("-i, --ignore <dirs...>", "Additional directories to ignore")
  .option("-v, --verbose", "Show verbose scanning and file filter details")
  .option("--staged", "Scan only staged files in Git index")
  .option("--json", "Output results formatted as standard JSON")
  .action(async (targetPath: string, options: { severity: string; ignore?: string[]; verbose?: boolean; staged?: boolean; json?: boolean }) => {
    const validSeverities: Severity[] = ["low", "medium", "high", "critical"];
    if (!validSeverities.includes(options.severity as Severity)) {
      console.error(chalk.red(`Error: Invalid severity "${options.severity}". Valid options are: ${validSeverities.join(", ")}`));
      process.exit(2);
    }

    const scanner = new ProjectScanner();
    const spinner = options.json || options.verbose ? null : ora("Scanning for secrets...").start();

    try {
      const result = await scanner.scan({
        path: targetPath,
        severity: options.severity as Severity,
        json: options.json,
        ignore: options.ignore,
        verbose: options.verbose,
        staged: options.staged,
        onFileAction: (filePath, status) => {
          if (!options.verbose) return;
          if (status === "scanned") console.log(`${chalk.green("✓")} ${filePath}`);
          if (status === "ignored") console.log(`${chalk.gray("⊘")} ${chalk.gray(filePath)} ${chalk.italic("(ignored)")}`);
          if (status === "binary") console.log(`${chalk.yellow("⊘")} ${chalk.yellow(filePath)} ${chalk.italic("(binary)")}`);
        }
      });

      if (spinner) spinner.stop();

      if (options.json) {
        renderJsonReport(result);
      } else {
        renderTerminalReport(result, targetPath);
      }

      if (result.findings.length > 0) {
        process.exit(1);
      }
      process.exit(0);
    } catch (err: any) {
      if (spinner) spinner.stop();
      console.error(chalk.red(`Error: ${err.message || err}`));
      process.exit(2);
    }
  });

program
  .command("rules")
  .description("List all built-in credential detection rules")
  .action(() => {
    console.log(chalk.bold("\nActive Detection Rules:\n"));
    console.table(
      DETECTION_RULES.map((r) => ({
        ID: r.id,
        Name: r.name,
        Severity: r.severity.toUpperCase(),
        Description: r.description
      }))
    );
  });

program
  .command("install-hook")
  .description("Install GitLeak Radar as a Git pre-commit hook")
  .argument("[path]", "Target git repository path", ".")
  .option("-s, --severity <level>", "Minimum severity for hook scan (low, medium, high, critical)", "low")
  .action(async (targetDir: string, options: { severity: string }) => {
    const validSeverities: Severity[] = ["low", "medium", "high", "critical"];
    if (!validSeverities.includes(options.severity as Severity)) {
      console.error(chalk.red(`Error: Invalid severity "${options.severity}". Valid options are: ${validSeverities.join(", ")}`));
      process.exit(2);
    }

    const res = await installPreCommitHook(targetDir, options.severity);
    if (res.success) {
      console.log(chalk.green(`✓ ${res.message}`));
      process.exit(0);
    } else {
      console.error(chalk.red(`✗ Error: ${res.message}`));
      process.exit(2);
    }
  });

// Run
if (process.argv.length <= 2) {
  program.outputHelp();
  process.exit(0);
}

program.parse(process.argv);
