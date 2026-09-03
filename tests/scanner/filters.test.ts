import { describe, it, expect } from "vitest";
import { shouldIgnoreFile, isPlaceholderOrExample } from "../../src/scanner/file-filter.js";

describe("File Filters", () => {
  it("ignores binary and lock files", () => {
    expect(shouldIgnoreFile("image.png")).toBe(true);
    expect(shouldIgnoreFile("package-lock.json")).toBe(true);
    expect(shouldIgnoreFile("bundle.min.js")).toBe(true);
    expect(shouldIgnoreFile("src/service.ts")).toBe(false);
  });

  it("identifies dummy placeholder tokens", () => {
    expect(isPlaceholderOrExample("AKIA_YOUR_API_KEY", "aws = 'AKIA_YOUR_API_KEY'", "index.ts")).toBe(true);
    expect(isPlaceholderOrExample("change_me_token", "token = 'change_me_token'", "config.ts")).toBe(true);
  });
});
