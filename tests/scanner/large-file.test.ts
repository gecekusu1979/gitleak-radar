import { describe, it, expect, vi } from 'vitest';
import fs from 'node:fs';
import { readTextFileSafe, MAX_FILE_SIZE_BYTES } from '../../src/scanner/file-reader.js';

describe('Large File Protection', () => {
  it('skips reading files exceeding MAX_FILE_SIZE_BYTES', () => {
    vi.spyOn(fs, 'statSync').mockReturnValue({ size: MAX_FILE_SIZE_BYTES + 1024 } as any);
    const result = readTextFileSafe('huge_file.log');
    expect(result.skipped).toBe(true);
    expect(result.content).toBeNull();
    expect(result.reason).toContain('exceeds maximum size');
    vi.restoreAllMocks();
  });

  it('reads normal files within limit', () => {
    vi.spyOn(fs, 'statSync').mockReturnValue({ size: 1024 } as any);
    vi.spyOn(fs, 'readFileSync').mockReturnValue('clean code content');
    const result = readTextFileSafe('normal_file.ts');
    expect(result.skipped).toBe(false);
    expect(result.content).toBe('clean code content');
    vi.restoreAllMocks();
  });
});
