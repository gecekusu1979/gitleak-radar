import { describe, it, expect } from "vitest";
import { isInsideGitRepo, getStagedFiles } from "../../src/git/staged.js";

describe("Git Staged Scanner Module", () => {
  it("detects current directory as a Git repository", async () => {
    const isRepo = await isInsideGitRepo(process.cwd());
    expect(isRepo).toBe(true);
  });

  it("returns an array of strings for staged files without throwing", async () => {
    const files = await getStagedFiles(process.cwd());
    expect(Array.isArray(files)).toBe(true);
  });

  it("correctly identifies non-repo path", async () => {
    const isRepo = await isInsideGitRepo("C:/Windows/Temp");
    expect(isRepo).toBe(false);
  });
});
