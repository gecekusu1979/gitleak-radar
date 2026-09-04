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

  it("defines standard excluded system/build directories in globs and does not exclude test folders", () => {
    expect(EXCLUDED_DIRECTORIES).toContain("**/node_modules/**");
    expect(EXCLUDED_DIRECTORIES).toContain("**/.git/**");
    expect(EXCLUDED_DIRECTORIES).toContain("**/dist/**");
    expect(EXCLUDED_DIRECTORIES).not.toContain("**/tests/**");
    expect(EXCLUDED_DIRECTORIES).not.toContain("**/test/**");
  });

  it("normalizes and checks source files safely", () => {
    expect(shouldIgnoreFile("src/service.ts")).toBe(false);
    expect(shouldIgnoreFile("src\\controllers\\user.ts".replace(/\\/g, "/"))).toBe(false);
  });

  it("scans tests/ and test/ directories by default", () => {
    expect(shouldIgnoreFile("tests/auth.test.ts")).toBe(false);
    expect(shouldIgnoreFile("test/helpers.ts")).toBe(false);
  });

  it("does not ignore user files named rules.ts or detector.ts outside internal detector path", () => {
    expect(shouldIgnoreFile("src/anything/rules.ts")).toBe(false);
    expect(shouldIgnoreFile("payments/detector.ts")).toBe(false);
  });

  it("identifies dummy placeholder tokens", () => {
    expect(isPlaceholderOrExample("AKIA_YOUR_API_KEY", "aws = 'AKIA_YOUR_API_KEY'", "index.ts")).toBe(true);
    expect(isPlaceholderOrExample("change_me_token", "token = 'change_me_token'", "config.ts")).toBe(true);
  });

  it("does not treat real sk_test_ credentials in normal source files as placeholders", () => {
    const realKey = "sk_test_51H8ZxKJ2eZvKYlo2CReal9999LiveKeyABC";
    expect(isPlaceholderOrExample(realKey, `const key = "${realKey}";`, "src/payments.ts")).toBe(false);
  });

  it("does not false-negative real secrets containing words like test, example, dummy, todo in source files", () => {
    const secretWithTest = "RealSecretKeyWithTestPart9923";
    const secretWithDummy = "dummySuperPasscode12345678";
    expect(isPlaceholderOrExample(secretWithTest, `key = "${secretWithTest}"`, "src/auth/service.ts")).toBe(false);
    expect(isPlaceholderOrExample(secretWithDummy, `pass = "${secretWithDummy}"`, "src/db/connection.ts")).toBe(false);
  });

  it("preserves placeholder behavior inside test fixture files", () => {
    const fixtureSecret = "mock_test_token_12345";
    expect(isPlaceholderOrExample(fixtureSecret, `testToken = "${fixtureSecret}"`, "tests/fixtures/tokens.ts")).toBe(true);
  });
});
