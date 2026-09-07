import chalk from "chalk";
import path from "node:path";
import { DETECTION_RULES } from "../detectors/rules.js";
import { loadConfig, getEffectiveRules } from "../config/loader.js";
import { type DetectionRule } from "../types/index.js";

const REMEDIATION_GUIDES: Record<string, string[]> = {
  "aws-access-key": [
    "Immediately deactivate and delete this key in the AWS IAM Console.",
    "Inspect CloudTrail logs for unauthorized API calls using this credential.",
    "Use AWS IAM Roles or environment variables (AWS_ACCESS_KEY_ID) instead of hardcoding."
  ],
  "github-pat": [
    "Revoke the token immediately under GitHub Settings -> Developer settings -> Personal access tokens.",
    "Audit recent account activity and repository audit logs for unauthorized access.",
    "Use fine-grained PATs with minimum required repository scopes and short expiration."
  ],
  "stripe-api-key": [
    "Roll the compromised secret key from the Stripe Developers Dashboard -> API keys.",
    "Review Stripe balance, payouts, and recent charges for fraudulent activity.",
    "Store Stripe credentials in encrypted environment variables or key vaults."
  ],
  "openai-api-key": [
    "Revoke the API key immediately in the OpenAI Platform Dashboard under API keys.",
    "Review usage dashboards and set hard billing limits to avoid surprise charges.",
    "Migrate key to backend secrets management (e.g. AWS Secrets Manager, Vault)."
  ],
  "private-key": [
    "Assume any system authenticating with this key is compromised. Revoke public keys from authorized_keys / servers.",
    "Generate a new cryptographic key pair using strong parameters (e.g. Ed25519 or RSA >= 3072 bits).",
    "Never store private keys directly in source code repositories."
  ],
  "twilio-api-key": [
    "Delete the exposed API Key in the Twilio Console under Account -> API keys & tokens.",
    "Review usage logs for unauthorized calls, SMS sends, or billing charges.",
    "Store Twilio credentials in environment variables or a secrets manager, never in source."
  ],
  "sendgrid-api-key": [
    "Revoke the key immediately in the SendGrid dashboard under Settings -> API Keys.",
    "Check Activity Feed for unexpected sends that could indicate spam/phishing abuse.",
    "Scope replacement keys to only the permissions the integration actually needs."
  ],
  "npm-token": [
    "Revoke the token immediately at npmjs.com under Access Tokens.",
    "Audit recently published versions of any packages this token could publish to for tampering (supply-chain risk).",
    "Use scoped, automation-specific tokens with the minimum required permission (read-only where possible)."
  ],
  "pypi-token": [
    "Revoke the token immediately at pypi.org under Account settings -> API tokens.",
    "Audit recently published package versions for unauthorized releases (supply-chain risk).",
    "Scope future tokens to a single project instead of the full account."
  ],
  "digitalocean-token": [
    "Revoke the token immediately in the DigitalOcean control panel under API -> Personal access tokens.",
    "Review account activity for unauthorized droplets, DNS changes, or billing charges.",
    "Prefer scoped tokens and rotate them regularly."
  ],
  "discord-webhook": [
    "Delete or regenerate the webhook in the Discord channel/server settings immediately.",
    "Check the channel for spam or unexpected messages sent through the exposed webhook.",
    "Treat webhook URLs as secrets; never commit them to a public repository."
  ]
};

export async function explainRule(ruleId: string, targetPath: string = "."): Promise<void> {
  const targetDir = path.resolve(process.cwd(), targetPath);
  const config = await loadConfig(targetDir);
  const allRules: DetectionRule[] = await getEffectiveRules(config);

  const matched = allRules.find((r) => r.id.toLowerCase() === ruleId.toLowerCase());

  if (!matched) {
    console.error(chalk.red(`\n✗ Error: Rule with ID "${ruleId}" not found.`));
    console.log(chalk.gray("\nAvailable rule IDs:"));
    const available = allRules.map((r) => r.id).join(", ");
    console.log(`  ${available}\n`);
    process.exit(2);
  }

  console.log(chalk.bold("\n========================================"));
  console.log(chalk.bold.cyan(`  GitLeak Radar Rule: ${matched.name}`));
  console.log(chalk.bold("========================================\n"));

  console.log(`${chalk.bold("Rule ID:")}     ${chalk.yellow(matched.id)}`);
  console.log(`${chalk.bold("Severity:")}    ${formatSeverity(matched.severity)}`);
  console.log(`${chalk.bold("Description:")} ${matched.description}`);
  console.log(`${chalk.bold("Pattern:")}     ${chalk.gray(matched.pattern.toString())}`);

  if (matched.keywords && matched.keywords.length > 0) {
    console.log(`${chalk.bold("Keywords:")}    ${matched.keywords.join(", ")}`);
  }

  if (matched.requiresEntropy || typeof matched.minEntropy === "number") {
    console.log(`${chalk.bold("Entropy:")}     Shannon entropy validation active (min: ${matched.minEntropy ?? 3.0})`);
  }

  console.log(chalk.bold("\n🛡 Remediation Guidance:"));
  const advice = REMEDIATION_GUIDES[matched.id] || [
    "Revoke the secret immediately at the provider service.",
    "Check audit logs for any unauthorized use during the exposure window.",
    "Store all secrets in secure environment variables or a secrets manager."
  ];

  advice.forEach((step, idx) => {
    console.log(`  ${idx + 1}. ${step}`);
  });
  console.log("");
}

function formatSeverity(severity: string): string {
  switch (severity.toLowerCase()) {
    case "critical":
      return chalk.bgRed.black.bold(" CRITICAL ");
    case "high":
      return chalk.red.bold("HIGH");
    case "medium":
      return chalk.yellow.bold("MEDIUM");
    case "low":
      return chalk.blue.bold("LOW");
    default:
      return severity;
  }
}

