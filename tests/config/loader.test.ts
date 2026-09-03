import { describe, it, expect } from "vitest";
import { ConfigSchema } from "../../src/config/loader.js";

describe("Config Loader", () => {
  it("validates valid configuration JSON", () => {
    const raw = {
      ignore: ["fixtures/**"],
      rules: { jwt: false }
    };
    const parsed = ConfigSchema.parse(raw);
    expect(parsed.ignore).toContain("fixtures/**");
    expect(parsed.rules["jwt"]).toBe(false);
  });

  it("applies defaults when empty", () => {
    const parsed = ConfigSchema.parse({});
    expect(parsed.ignore).toEqual([]);
    expect(parsed.rules).toEqual({});
  });
});
