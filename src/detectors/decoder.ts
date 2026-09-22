export interface DecodedCandidate {
  text: string;
  offset: number;
}

const ENCODED_TOKEN = /[A-Za-z0-9+/_-]{16,}={0,2}/g;
const URL_TOKEN = /(?:%[0-9a-f]{2}){2,}[A-Za-z0-9%._~!$&'()*+,;=:@/?-]*/gi;
const MAX_DECODED_LENGTH = 8192;

/** Hiçbir çağrı yerinde --max-decode-depth geçilmezse kullanılan varsayılan derinlik. */
export const DEFAULT_MAX_DECODE_DEPTH = 2;

function addCandidate(
  candidates: DecodedCandidate[],
  seen: Set<string>,
  text: string,
  offset: number
): void {
  if (text && text.length <= MAX_DECODED_LENGTH && !seen.has(text)) {
    seen.add(text);
    candidates.push({ text, offset });
  }
}

function tryBase64Decode(value: string): string | null {
  try {
    const decoded = Buffer.from(value, "base64").toString("utf-8");
    // Anlamsız binary çıktıyı filtrele: çoğu karakter yazdırılabilir olmalı
    const printable = decoded.split("").filter((c) => c.charCodeAt(0) >= 32).length;
    if (printable / decoded.length < 0.8) return null;
    return decoded;
  } catch {
    return null;
  }
}

function tryUrlDecode(value: string): string | null {
  try {
    const decoded = decodeURIComponent(value);
    if (decoded === value) return null;
    return decoded;
  } catch {
    return null;
  }
}

function tryHexDecode(value: string): string | null {
  if (!/^[0-9a-f]{16,}$/i.test(value)) return null;
  try {
    const decoded = Buffer.from(value, "hex").toString("utf-8");
    const printable = decoded.split("").filter((c) => c.charCodeAt(0) >= 32).length;
    if (printable / decoded.length < 0.8) return null;
    return decoded;
  } catch {
    return null;
  }
}

function decodeToken(value: string): string[] {
  const results: string[] = [];

  const b64 = tryBase64Decode(value);
  if (b64) results.push(b64);

  const url = tryUrlDecode(value);
  if (url) results.push(url);

  const hex = tryHexDecode(value);
  if (hex) results.push(hex);

  return results;
}

/**
 * Tek bir regex'in tüm eşleşmelerini candidate.text üzerinde bir kez tarar ve
 * her eşleşmeyi decodeToken() ile çözüp sonuçları candidates/next dizilerine ekler.
 *
 * Önceki sürümde URL_TOKEN taraması ENCODED_TOKEN döngüsünün İÇİNE yerleşikti;
 * bu, bir satırdaki her ENCODED_TOKEN eşleşmesi için candidate.text'in tamamını
 * baştan tarayıp O(N²) gereksiz iş yapıyordu (N = satırdaki encoded-token sayısı).
 * Bu yardımcı, her regex'i candidate başına yalnızca bir kez, kardeş (sequential)
 * döngüler halinde çalıştırarak aynı sonuçları üretir.
 */
function collectMatches(
  pattern: RegExp,
  candidate: DecodedCandidate,
  candidates: DecodedCandidate[],
  seen: Set<string>,
  next: DecodedCandidate[]
): void {
  pattern.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(candidate.text)) !== null) {
    for (const decoded of decodeToken(match[0])) {
      const offset = candidate.offset + match.index;
      addCandidate(candidates, seen, decoded, offset);
      next.push({ text: decoded, offset });
    }
  }
}

export function recursivelyDecodeLine(
  line: string,
  maxDepth: number = DEFAULT_MAX_DECODE_DEPTH
): DecodedCandidate[] {
  const candidates: DecodedCandidate[] = [];
  if (maxDepth <= 0) {
    return candidates;
  }

  const seen = new Set<string>();
  let frontier: DecodedCandidate[] = [{ text: line, offset: 0 }];

  for (let depth = 1; depth <= maxDepth; depth++) {
    const next: DecodedCandidate[] = [];
    for (const candidate of frontier) {
      collectMatches(ENCODED_TOKEN, candidate, candidates, seen, next);
      collectMatches(URL_TOKEN, candidate, candidates, seen, next);
    }
    frontier = next;
    if (frontier.length === 0) break;
  }

  return candidates;
}
