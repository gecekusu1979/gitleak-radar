import { describe, it, expect } from "vitest";
import { SecretDetector } from "../../src/detectors/detector.js";
import { DETECTION_RULES } from "../../src/detectors/rules.js";

describe("Expanded Detection Rules", () => {
  const detector = new SecretDetector(DETECTION_RULES);

  it("detects Stripe live secret key", () => {
    const stripeKey = ["sk", "live", "51AbCdEfGhIjKlMnOpQrStUvWxYz12345"].join("_");
    const line = `const stripeKey = "${stripeKey}";`;
    const findings = detector.scanLine(line, 1, "checkout.ts");
    expect(findings.some((f) => f.ruleId === "stripe-api-key")).toBe(true);
  });

  it("detects OpenAI project-scoped secret key", () => {
    const line = 'OPENAI_API_KEY="sk-proj-abc123XYZ456def789GHI012jkl345MNO678pqr901STU234vwx567"';
    const findings = detector.scanLine(line, 1, ".env");
    expect(findings.some((f) => f.ruleId === "openai-api-key")).toBe(true);
  });

  it("detects GitLab personal access token", () => {
    const line = "GITLAB_TOKEN=glpat-AbCdEfGhIjKlMnOpQrSt123";
    const findings = detector.scanLine(line, 1, ".gitlab-ci.yml");
    expect(findings.some((f) => f.ruleId === "gitlab-pat")).toBe(true);
  });

  it("detects Slack incoming webhook url", () => {
    const webhookUrl = "https://" + "hooks.slack.com/services/T12345678/B87654321/aBcDeFgHiJkLmNoPqRsTuVwX";
    const line = `const url = "${webhookUrl}";`;
    const findings = detector.scanLine(line, 1, "alerts.ts");
    expect(findings.some((f) => f.ruleId === "slack-webhook")).toBe(true);
  });

  it("detects Azure Storage Account Key", () => {
    const validKey = "d8G3mK9qL2pZ0vW5xY7bN1cM4rT6uJ8yaBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890AaBbCcDdEeFfGgHh==";
    const line = `DefaultEndpointsProtocol=https;AccountName=test;AccountKey=${validKey};EndpointSuffix=core.windows.net`;
    const findings = detector.scanLine(line, 1, "appsettings.json");
    expect(findings.some((f) => f.ruleId === "azure-storage-key")).toBe(true);
  });
});
