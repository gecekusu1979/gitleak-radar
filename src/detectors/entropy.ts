/**
 * Verilen metnin Shannon entropisini hesaplar (bit cinsinden).
 */
export function calculateShannonEntropy(data: string): number {
  if (!data || data.length === 0) {
    return 0;
  }

  const frequencies = new Map<string, number>();
  for (const char of data) {
    frequencies.set(char, (frequencies.get(char) ?? 0) + 1);
  }

  let entropy = 0;
  const len = data.length;

  for (const count of frequencies.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }

  return entropy;
}

export type CharsetCategory = "hex" | "base64" | "ascii";

/**
 * Verilen dizginin karakter kumesini siniflandirir.
 */
export function detectCharset(token: string): CharsetCategory {
  if (/^[0-9a-fA-F]+$/.test(token)) {
    return "hex";
  }
  if (/^[a-zA-Z0-9+/=_-]+$/.test(token)) {
    return "base64";
  }
  return "ascii";
}

export interface EntropyThresholds {
  hex: number;
  base64: number;
  ascii: number;
  minTokenLength: number;
}

export const DEFAULT_ENTROPY_THRESHOLDS: EntropyThresholds = {
  hex: 3.0,          // 0-9, a-f icin rastgelelik esigi (maks 4.0)
  base64: 4.2,       // Base64 ve token karakter kumesi icin esik (maks 6.0)
  ascii: 4.5,        // Genel ASCII icin esik
  minTokenLength: 16 // Yanlis pozitifleri onlemek icin minimum token uzunlugu
};

/**
 * Token'in karakter kumesine gore yuksek entropiye sahip bir secret adayi olup olmadigini belirler.
 */
export function isHighEntropyToken(
  token: string,
  thresholds: EntropyThresholds = DEFAULT_ENTROPY_THRESHOLDS
): boolean {
  if (token.length < thresholds.minTokenLength) {
    return false;
  }

  const charset = detectCharset(token);
  const entropy = calculateShannonEntropy(token);

  switch (charset) {
    case "hex":
      return entropy >= thresholds.hex;
    case "base64":
      return entropy >= thresholds.base64;
    case "ascii":
      return entropy >= thresholds.ascii;
  }
}
