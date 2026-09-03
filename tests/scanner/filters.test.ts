import { describe, it, expect } from "vitest";
import { shouldIgnoreFile, isPlaceholderOrExample, EXCLUDED_DIRECTORIES } from "../../src/scanner/file-filter.js";

describe("Scanner File Filters", () => {
  it("ignores binary formats", () => {
    expect(shouldIgnoreFile("image.png")).toBe(true);
    expect(shouldIgnoreFile("archive.zip")).toBe(true);
    expect(shouldIgnoreFile("executable.exe")).toBe(true);
    expect(shouldIgnoreFile("font.woff2")).toBe(true);
  });

  it("ignores lockfiles and minified bundles", () => {
    expect(shouldIgnoreFile("package-lock.json")).toBe(true);
    expect(shouldIgnoreFile("pnpm-lock.yaml")).toBe(true);
    expect(shouldIgnoreFile("yarn.lock")).toBe(true);
    expect(shouldIgnoreFile("app.bundle.min.js")).toBe(true);
  });

  it("defines standard excluded system/build directories in globs", () => {
    expect(EXCLUDED_DIRECTORIES).toContain("**/node_modules/**");
    expect(EXCLUDED_DIRECTORIES).toContain("**/.git/**");
    expect(EXCLUDED_DIRECTORIES).toContain("**/dist/**");
  });

  it("normalizes and checks source files safely", () => {
    expect(shouldIgnoreFile("src/service.ts")).toBe(false);
    expect(shouldIgnoreFile("src\\controllers\\user.ts".replace(/\\/g, "/"))).toBe(false);
  });

  it("identifies dummy placeholder tokens", () => {
    expect(isPlaceholderOrExample("AKIA_YOUR_API_KEY", "aws = 'AKIA_YOUR_API_KEY'", "index.ts")).toBe(true);
    expect(isPlaceholderOrExample("change_me_token", "token = 'change_me_token'", "config.ts")).toBe(true);
  });
});
