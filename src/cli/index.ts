#!/usr/bin/env node
import { Command } from "commander";
import chalk from "chalk";
import ora from "ora";
import { ProjectScanner } from "../scanner/scanner.js";
import { renderTerminalReport } from "../reporters/terminal.js";
import { renderJsonReport } from "../reporters/json.js";
import { DETECTION_RULES } from "../detectors/rules.js";
import { installPreCommitHook } from "../hooks/installer.js";
import { Severity } from "../types/index.js";

const program = new Command();

program
  .name("gitleak-radar")
  .description("Fast, local source-code secret scanner CLI.")
  .version("1.0.0");

program
  .command("scan")
  .argument("[path]", "Directory path to scan", ".")
  .option("-s, --severity <level>", "Minimum severity (low, medium, high, critical)", "low")
  .option("-i, --ignore <dirs...>", "Additional directories to ignore")
  .option("-v, --verbose", "Show detailed file inspection logs")
  .option("--json", "Output results in JSON format")
  .action(async (targetPath: string, options: { severity: string; ignore?: string[]; verbose?: boolean; json?: boolean }) => {
    const validSeverities: Severity[] = ["low", "medium", "high", "critical"];
    if (!validSeverities.includes(options.severity as Severity)) {
      console.error(chalk.red(`Invalid severity: "${options.severity}". Choose from: ${validSeverities.join(", ")}`));
      process.exit(2);
    }

    const scanner = new ProjectScanner();
    const spinner = options.json || options.verbose ? null : ora("Scanning for hardcoded secrets...").start();

    try {
      const result = await scanner.scan({
        path: targetPath,
        severity: options.severity as Severity,
        json: options.json,
        ignore: options.ignore,
        verbose: options.verbose,
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
    } catch (err) {
      if (spinner) spinner.fail("Scan failed.");
      console.error(chalk.red((err as Error).message));
      process.exit(2);
    }
  });

program
  .command("install-hook")
  .description("Install GitLeak Radar as a local Git pre-commit hook")
  .argument("[path]", "Target git repository path", ".")
  .action(async (targetDir: string) => {
    const res = await installPreCommitHook(targetDir);
    if (res.success) {
      console.log(chalk.green(`✓ ${res.message}`));
      process.exit(0);
    } else {
      console.error(chalk.red(`✗ ${res.message}`));
      process.exit(2);
    }
  });

program
  .command("rules")
  .description("List all active secret detection rules")
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

program.parse(process.argv);
