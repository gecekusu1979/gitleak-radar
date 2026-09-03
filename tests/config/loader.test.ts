import { describe, it, expect } from "vitest";
import { ConfigSchema, loadConfig } from "../../src/config/loader.js";

describe("Configuration Engine", () => {
  it("validates a compliant .gitleak-radar.json schema", () => {
    const raw = {
      ignore: ["fixtures/**", "custom-dir/**"],
      rules: { "jwt": false, "generic-password": true }
    };
    const parsed = ConfigSchema.parse(raw);
    expect(parsed.ignore).toHaveLength(2);
    expect(parsed.rules["jwt"]).toBe(false);
  });

  it("falls back to defaults on empty object", () => {
    const parsed = ConfigSchema.parse({});
    expect(parsed.ignore).toEqual([]);
    expect(parsed.rules).toEqual({});
  });

  it("gracefully returns default config when file is non-existent", async () => {
    const config = await loadConfig("/non/existent/path/99999");
    expect(config.ignore).toEqual([]);
    expect(config.rules).toEqual({});
  });

  it("rejects invalid schema structure", () => {
    const invalid = { ignore: "not-an-array" };
    expect(() => ConfigSchema.parse(invalid)).toThrow();
  });
});
