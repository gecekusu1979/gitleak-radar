import { describe, it, expect } from "vitest";
import { SecretDetector } from "../../src/detectors/detector.js";
import { DETECTION_RULES } from "../../src/detectors/rules.js";

const detector = new SecretDetector(DETECTION_RULES);

function findRuleIds(line: string): string[] {
  return detector.scanLine(line, 1, "test.ts").map((f) => f.ruleId);
}

describe("expanded detection rules", () => {
  it("detects a Twilio API Key SID", () => {
    const line = `const twilioKey = "${["SK", "0".repeat(32)].join("")}";`;
    expect(findRuleIds(line)).toContain("twilio-api-key");
  });

  it("detects a SendGrid API key", () => {
    const line = [
      "SENDGRID_API_KEY=SG.",
      "0".repeat(22),
      ".",
      "A".repeat(43)
    ].join("");
    expect(findRuleIds(line)).toContain("sendgrid-api-key");
  });

  it("detects an npm access token", () => {
    const line = "//registry.npmjs.org/:_authToken=npm_123456789012345678901234567890123456";
    expect(findRuleIds(line)).toContain("npm-token");
  });

  it("detects a PyPI upload token", () => {
    const line =
      "password = pypi-AgEIcHlwaS5vcmcAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    expect(findRuleIds(line)).toContain("pypi-token");
  });

  it("detects a DigitalOcean personal access token", () => {
    const line = `DO_TOKEN="dop_v1_${"a1".repeat(32)}"`;
    expect(findRuleIds(line)).toContain("digitalocean-token");
  });

  it("detects a Discord webhook URL", () => {
    const line =
      "https://discord.com/api/webhooks/123456789012345678/AbCdEfGhIjKlMnOpQrStUvWxYz-1234567890";
    expect(findRuleIds(line)).toContain("discord-webhook");
  });

  it("does not classify a Twilio Account SID as an API key", () => {
    const line = `const accountSid = "${["AC", "0".repeat(32)].join("")}";`;
    expect(findRuleIds(line)).not.toContain("twilio-api-key");
  });

  it("does not detect malformed provider credentials", () => {
    const line = [
      "SG.too-short.token",
      "npm_short",
      "dop_v1_invalid",
      "https://discord.com/api/webhooks/12345/"
    ].join(" ");
    expect(findRuleIds(line)).toEqual([]);
  });

  it("does not flag unrelated plain text", () => {
    const line = "const greeting = 'hello world';";
    expect(findRuleIds(line)).toEqual([]);
  });
});
