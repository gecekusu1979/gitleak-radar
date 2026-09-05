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
import { renderSarifReport } from "../reporters/sarif.js";
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
  .description("GitLeak Radar - Fast, local-first enterprise secret scanner CLI.")
  .version(getPackageVersion(), "-V, --version", "Output the current version")
  .helpOption("-h, --help", "Display help for command");

program
  .command("scan")
  .description("Scan files, staged index, or full Git history for sensitive credentials and secrets")
  .argument("[path]", "Target directory path to scan", ".")
  .option("-s, --severity <level>", "Minimum severity threshold (low, medium, high, critical)", "low")
  .option("-i, --ignore <dirs...>", "Additional directories to ignore")
  .option("-r, --rules <file>", "Path to custom rules JSON file")
  .option("-v, --verbose", "Show verbose scanning and file filter details")
  .option("--staged", "Scan only staged files in Git index")
  .option("--history", "Scan full Git commit history diffs for leaked secrets")
  .option("--json", "Output results formatted as standard JSON")
  .option("--sarif [file]", "Output results in SARIF v2.1.0 format (to stdout or file)")
  .action(
    async (
      targetPath: string,
      options: {
        severity: string;
        ignore?: string[];
        rules?: string;
        verbose?: boolean;
        staged?: boolean;
        history?: boolean;
        json?: boolean;
        sarif?: string | boolean;
      }
    ) => {
      const validSeverities: Severity[] = ["low", "medium", "high", "critical"];
      if (!validSeverities.includes(options.severity as Severity)) {
        console.error(
          chalk.red(`Error: Invalid severity "${options.severity}". Valid options are: ${validSeverities.join(", ")}`)
        );
        process.exit(2);
      }

      if (options.staged && options.history) {
        console.error(chalk.red("Error: Cannot specify both --staged and --history simultaneously."));
        process.exit(2);
      }

      const scanner = new ProjectScanner();
      const isMachineOutput = Boolean(options.json || options.sarif);
      const spinner = isMachineOutput || options.verbose ? null : ora("Scanning for secrets...").start();

      try {
        const result = await scanner.scan({
          path: targetPath,
          severity: options.severity as Severity,
          json: options.json,
          ignore: options.ignore,
          rulesPath: options.rules,
          verbose: options.verbose,
          staged: options.staged,
          history: options.history,
          onFileAction: (filePath: string, status: "scanned" | "ignored" | "binary") => {
            if (!options.verbose) return;
            if (status === "scanned") console.log(`${chalk.green("✓")} ${filePath}`);
            if (status === "ignored") console.log(`${chalk.gray("⊘")} ${chalk.gray(filePath)} ${chalk.italic("(ignored)")}`);
            if (status === "binary") console.log(`${chalk.yellow("⊘")} ${chalk.yellow(filePath)} ${chalk.italic("(binary)")}`);
          }
        });

        if (spinner) spinner.stop();

        if (options.sarif) {
          const outputPath = typeof options.sarif === "string" ? options.sarif : undefined;
          renderSarifReport(result, outputPath, getPackageVersion());
        } else if (options.json) {
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
    }
  );

program
  .command("init")
  .description("Create a default .gitleak-radar.json configuration file")
  .argument("[path]", "Directory where configuration will be created", ".")
  .action(async (targetDir: string) => {
    const configPath = path.resolve(process.cwd(), targetDir, ".gitleak-radar.json");
    if (fs.existsSync(configPath)) {
      console.log(chalk.yellow(`⚠ Configuration already exists at ${configPath}`));
      process.exit(0);
    }

    const template = {
      ignore: ["tests", "dist", "node_modules"],
      rules: {},
      customRules: [
        {
          id: "corp-api-key",
          name: "Corporate Internal API Key",
          description: "Detects internal ACME API credentials",
          severity: "high",
          regex: "ACME_[A-Za-z0-9]{32}",
          keywords: ["ACME_"]
        }
      ]
    };

    fs.writeFileSync(configPath, JSON.stringify(template, null, 2) + "\n", "utf-8");
    console.log(chalk.green(`✓ Initialized default GitLeak Radar configuration at ${configPath}`));
  });

program
  .command("rules")
  .description("List all built-in credential detection rules")
  .action(() => {
    console.log(chalk.bold("\nActive Built-in Detection Rules:\n"));
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
      console.error(
        chalk.red(`Error: Invalid severity "${options.severity}". Valid options are: ${validSeverities.join(", ")}`)
      );
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

if (process.argv.length <= 2) {
  program.outputHelp();
  process.exit(0);
}

program.parse(process.argv);
