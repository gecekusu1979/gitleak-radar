import { describe, it, expect, vi, beforeEach } from "vitest";
import { loadConfig } from "../../src/config/loader.js";
import fs from "node:fs/promises";

vi.mock("node:fs/promises");

describe("Config Loader", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("returns default config when .gitleak-radar.json does not exist", async () => {
    vi.mocked(fs.readFile).mockRejectedValueOnce({ code: "ENOENT" });
    const config = await loadConfig(".");
    expect(config.ignore).toEqual([]);
    expect(config.rules).toEqual({});
  });

  it("loads valid configuration successfully", async () => {
    const validJson = JSON.stringify({
      ignore: ["src/test/**"],
      rules: { "aws-access-key": false }
    });
    vi.mocked(fs.readFile).mockResolvedValueOnce(validJson);
    const config = await loadConfig(".");
    expect(config.ignore).toEqual(["src/test/**"]);
    expect(config.rules["aws-access-key"]).toBe(false);
  });

  it("throws descriptive Error when an invalid rule ID is provided", async () => {
    const invalidJson = JSON.stringify({
      rules: { "aws-acces-key": false }
    });
    vi.mocked(fs.readFile).mockResolvedValueOnce(invalidJson);
    await expect(loadConfig(".")).rejects.toThrow(/Invalid \.gitleak-radar\.json/);
  });

  it("throws Error on unclosed bracket in glob pattern", async () => {
    const unclosedBracket = JSON.stringify({
      ignore: ["[unclosed/"]
    });
    vi.mocked(fs.readFile).mockResolvedValueOnce(unclosedBracket);
    await expect(loadConfig(".")).rejects.toThrow(/Invalid glob pattern/);
  });

  it("throws Error on unmatched closing brace in glob pattern", async () => {
    const unmatchedClosing = JSON.stringify({
      ignore: ["foo}"]
    });
    vi.mocked(fs.readFile).mockResolvedValueOnce(unmatchedClosing);
    await expect(loadConfig(".")).rejects.toThrow(/Invalid glob pattern/);
  });
});
