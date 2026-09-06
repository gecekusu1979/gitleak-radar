import { describe, it, expect } from "vitest";
import { parseByteSize } from "../../src/scanner/file-reader.js";

describe("Byte Size Parser (parseByteSize)", () => {
  it("correctly parses human-readable sizes", () => {
    expect(parseByteSize("10MB")).toBe(10 * 1024 * 1024);
    expect(parseByteSize("500KB")).toBe(500 * 1024);
    expect(parseByteSize("1GB")).toBe(1024 * 1024 * 1024);
    expect(parseByteSize("2048")).toBe(2048);
    expect(parseByteSize(4096)).toBe(4096);
  });

  it("handles case-insensitive and whitespace formats", () => {
    expect(parseByteSize(" 5 mb ")).toBe(5 * 1024 * 1024);
    expect(parseByteSize("100k")).toBe(100 * 1024);
  });

  it("throws descriptive error on invalid formats", () => {
    expect(() => parseByteSize("invalid-size")).toThrow("Invalid max file size");
    expect(() => parseByteSize("-10MB")).toThrow("Invalid max file size");
    expect(() => parseByteSize(0)).toThrow("Invalid max file size");
  });
});
