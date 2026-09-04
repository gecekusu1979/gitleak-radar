import { describe, it, expect } from "vitest";
import {
  calculateShannonEntropy,
  detectCharset,
  isHighEntropyToken
} from "../../src/detectors/entropy.js";

describe("Shannon Entropy Engine", () => {
  it("computes zero entropy for empty string or uniform characters", () => {
    expect(calculateShannonEntropy("")).toBe(0);
    expect(calculateShannonEntropy("aaaaaaaaaa")).toBe(0);
  });

  it("calculates expected entropy range for standard tokens", () => {
    // 16 karakterlik hex anahtarı (yüksek çeşitlilik)
    const hexSecret = "4a8f9b2c1d0e3f7a8b9c0d1e2f3a4b5c";
    const hexEntropy = calculateShannonEntropy(hexSecret);
    expect(hexEntropy).toBeGreaterThan(3.2);

    // Düşük entropili kod değişkeni (örn: getApplicationName)
    const englishWord = "getApplicationName";
    const wordEntropy = calculateShannonEntropy(englishWord);
    expect(wordEntropy).toBeLessThan(3.8);
  });

  it("correctly identifies character sets", () => {
    expect(detectCharset("deadbeef1234567890abcdef")).toBe("hex");
    expect(detectCharset("a8Fh92kLmPq7X9zZa+4/==")).toBe("base64");
    expect(detectCharset("complex-pass!@#123")).toBe("ascii");
  });

  it("flags high-entropy candidate tokens while ignoring low-entropy natural strings", () => {
    // Gerçekçi rastgele secret token
    const randomToken = "c7e8a9f0b1c2d3e4f5a6b7c8d9e0f1a2";
    expect(isHighEntropyToken(randomToken)).toBe(true);

    // Yeterince uzun ama düşük entropili İngilizce metin / method adı
    const nonSecret = "processUserAuthenticationRequest";
    expect(isHighEntropyToken(nonSecret)).toBe(false);

    // Çok kısa rastgele token (minTokenLength = 16 altında kalmalı)
    expect(isHighEntropyToken("a9F#zQ")).toBe(false);
  });
});
