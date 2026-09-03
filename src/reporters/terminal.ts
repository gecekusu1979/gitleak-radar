import chalk from "chalk";
import { Finding, ScanResult, Severity } from "../types/index.js";

const SEVERITY_BADGES: Record<Severity, string> = {
  critical: chalk.bgRed.bold.white(" CRITICAL "),
  high: chalk.bgHex("#FFA500").bold.black(" HIGH "),
  medium: chalk.bgYellow.bold.black(" MEDIUM "),
  low: chalk.bgBlue.bold.white(" LOW ")
};

export function renderTerminalReport(result: ScanResult, targetPath: string): void {
  console.log("\n" + chalk.bold.cyan("GitLeak Radar"));
  console.log(chalk.gray("────────────────────────────────────────"));
  console.log(`Scanning ${chalk.yellow(targetPath)}...\n`);
  console.log(`${chalk.green("✓")} Scanned ${chalk.bold(result.summary.filesScanned)} files`);
  console.log(`${chalk.green("✓")} ${chalk.bold(result.summary.linesScanned.toLocaleString())} lines\n`);

  if (result.findings.length > 0) {
    console.log(chalk.bold.underline("Findings:\n"));

    for (const item of result.findings) {
      const badge = SEVERITY_BADGES[item.severity];
      const location = chalk.gray(`${item.file}:${item.line}:${item.column}`);
      console.log(`${badge}  ${location}`);
      console.log(`   ${chalk.bold(item.ruleName)}`);
      console.log(`   Fingerprint: ${chalk.cyan(item.maskedValue)}\n`);
    }
  }

  console.log(chalk.gray("────────────────────────────────────────"));

  const scoreColor =
    result.summary.score >= 90
      ? chalk.green
      : result.summary.score >= 75
        ? chalk.yellow
        : chalk.red;

  console.log(
    `Security Score: ${scoreColor.bold(`${result.summary.score}/100`)} (${chalk.italic(result.summary.tier)})`
  );

  const stats = [
    `${result.summary.findings} findings found`,
    ...Object.entries(
      result.findings.reduce<Record<string, number>>((acc, f) => {
        acc[f.severity] = (acc[f.severity] || 0) + 1;
        return acc;
      }, {})
    ).map(([sev, count]) => `${count} ${sev}`)
  ];

  console.log(chalk.gray(stats.join("  |  ")));
  console.log(chalk.gray(`Scan completed in ${(result.summary.durationMs / 1000).toFixed(2)}s\n`));
}