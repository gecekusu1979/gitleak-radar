import { describe, it, expect, vi, beforeEach } from "vitest";
import { readFileLines, MAX_FILE_SIZE_BYTES } from "../../src/scanner/file-reader.js";
import fs from "node:fs/promises";

vi.mock("node:fs/promises");

describe("readFileLines - File Size Protection", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("returns null when file size exceeds MAX_FILE_SIZE_BYTES (10MB)", async () => {
    vi.mocked(fs.stat).mockResolvedValueOnce({
      size: MAX_FILE_SIZE_BYTES + 1
    } as any);

    const result = await readFileLines("large-file.dat");
    expect(result).toBeNull();
  });

  it("reads lines normally when file size is within limits", async () => {
    vi.mocked(fs.stat).mockResolvedValueOnce({
      size: 100
    } as any);

    vi.mocked(fs.readFile).mockResolvedValueOnce(Buffer.from("line1\nline2"));

    const result = await readFileLines("normal.ts");
    expect(result).not.toBeNull();
    expect(result?.lines).toEqual(["line1", "line2"]);
    expect(result?.totalLines).toBe(2);
  });
});
