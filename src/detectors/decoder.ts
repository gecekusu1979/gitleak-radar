export interface DecodedCandidate {
  text: string;
  offset: number;
}

const ENCODED_TOKEN = /[A-Za-z0-9+\/_-]{16,}={0,2}/g;
const URL_TOKEN = /(?:%[0-9a-f]{2}){2,}[A-Za-z0-9%._~!$&'()*+,;=:@/?-]*/gi;
/** Tekli %XX dahil, en az bir yüzde-encode edilmiş token'ı yakalar */
const SINGLE_PERCENT_TOKEN = /(?:%[0-9a-f]{2})+[A-Za-z0-9%._~!$&'()*+,;=:@/?-]*/gi;
const BYTE_ARRAY_TOKEN = /(?:\[|\bBuffer\.from\(\[)((?:(?:\d{2,3}|0x[0-9a-fA-F]{2})\s*,\s*){15,}(?:\d{2,3}|0x[0-9a-fA-F]{2}))\]/g;
const REVERSED_PREFIX_TOKEN = /\b[A-Za-z0-9_\-]{15,80}(?:_phg|-_taplg|_evil_ks|_-xox|AIKA)\b/gi;
const BASE58_TOKEN = /[1-9A-HJ-NP-Za-km-z]{30,256}/g;
const ASCII85_TOKEN = /<~[!-u]+~>/g;
const MAX_DECODED_LENGTH = 8192;

/** Hiçbir çağrı yerinde --max-decode-depth geçilmezse kullanılan varsayılan derinlik. */
export const DEFAULT_MAX_DECODE_DEPTH = 3;

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

function getPrintableCount(str: string): number {
  let count = 0;
  for (let i = 0; i < str.length; i++) {
    const c = str.charCodeAt(i);
    if ((c >= 32 && c <= 126) || c === 9 || c === 10 || c === 13) {
      count++;
    }
  }
  return count;
}

function tryBase64Decode(value: string): string | null {
  try {
    const pad = value.length % 4 ? '='.repeat(4 - (value.length % 4)) : '';
    const normalizedB64 = value.replace(/-/g, '+').replace(/_/g, '/') + pad;
    const decoded = Buffer.from(normalizedB64, "base64").toString("utf-8");
    const printable = getPrintableCount(decoded);
    if (decoded.length > 0 && printable / decoded.length < 0.8) return null;
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
    const printable = getPrintableCount(decoded);
    if (decoded.length > 0 && printable / decoded.length < 0.8) return null;
    return decoded;
  } catch {
    return null;
  }
}

function tryBase32Decode(value: string): string | null {
  const clean = value.replace(/=+$/, "").toUpperCase();
  if (clean.length < 16 || !/^[A-Z2-7]+$/.test(clean)) return null;

  let bits = 0;
  let valueAccumulator = 0;
  const decoded: number[] = [];

  for (let i = 0; i < clean.length; i++) {
    const charValue = clean.charCodeAt(i);
    // A-Z => 0-25 (A=65), 2-7 => 26-31 (2=50)
    const val = charValue <= 90 && charValue >= 65 ? charValue - 65 :
      charValue <= 55 && charValue >= 50 ? charValue - 24 : -1;
    if (val === -1) return null;

    valueAccumulator = (valueAccumulator << 5) | val;
    bits += 5;
    if (bits >= 8) {
      decoded.push((valueAccumulator >> (bits - 8)) & 255);
      bits -= 8;
    }
  }

  try {
    const str = Buffer.from(decoded).toString("utf-8");
    const printable = getPrintableCount(str);
    if (str.length > 0 && printable / str.length < 0.8) return null;
    return str;
  } catch {
    return null;
  }
}

function tryByteArrayDecode(value: string): string | null {
  const match = value.match(/(?:\[|\bBuffer\.from\(\[)((?:(?:\d{2,3}|0x[0-9a-fA-F]{2})\s*,\s*){15,}(?:\d{2,3}|0x[0-9a-fA-F]{2}))\]/);
  if (!match || !match[1]) return null;
  const parts = match[1].split(',').map(s => s.trim());
  const decoded = Buffer.alloc(parts.length);
  for (let i = 0; i < parts.length; i++) {
    const p = parts[i] || "";
    const n = p.startsWith('0x') ? parseInt(p, 16) : parseInt(p, 10);
    if (isNaN(n) || n < 0 || n > 255) return null;
    decoded[i] = n;
  }
  try {
    const str = decoded.toString("utf-8");
    const printable = getPrintableCount(str);
    if (str.length > 0 && printable / str.length < 0.8) return null;
    return str;
  } catch {
    return null;
  }
}

function tryReversedDecode(value: string): string | null {
  if (!/[A-Za-z0-9_\-]{15,80}(?:_phg|-_taplg|_evil_ks|_-xox|AIKA)\b/i.test(value)) return null;
  return value.split("").reverse().join("");
}

function tryBase58Decode(value: string): string | null {
  if (!/^[1-9A-HJ-NP-Za-km-z]{30,256}$/.test(value)) return null;
  if (new Set(value).size < 15) return null;

  const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  let num = 0n;
  for (let i = 0; i < value.length; i++) {
    const charIndex = ALPHABET.indexOf(value[i]!);
    if (charIndex === -1) return null;
    num = num * 58n + BigInt(charIndex);
  }

  let hex = num.toString(16);
  if (hex.length % 2 !== 0) hex = '0' + hex;

  let leadingZeroes = 0;
  while (leadingZeroes < value.length && value[leadingZeroes] === '1') {
    leadingZeroes++;
  }

  try {
    const buf = Buffer.concat([
      Buffer.alloc(leadingZeroes, 0),
      Buffer.from(hex, 'hex')
    ]);
    const decoded = buf.toString('utf-8');
    const printable = getPrintableCount(decoded);
    if (decoded.length > 0 && printable / decoded.length < 0.8) return null;
    return decoded;
  } catch {
    return null;
  }
}

function tryAscii85Decode(value: string): string | null {
  if (!/^<~[!-u]+~>$/.test(value)) return null;

  const payload = value.slice(2, -2);
  let decoded = Buffer.alloc(Math.ceil(payload.length * 4 / 5));
  let decIndex = 0;

  let val = 0;
  let count = 0;

  for (let i = 0; i < payload.length; i++) {
    const char = payload[i]!;
    if (char === 'z') {
      if (count !== 0) return null;
      decoded.writeUInt32BE(0, decIndex);
      decIndex += 4;
      continue;
    }

    const code = char.charCodeAt(0) - 33;
    if (code < 0 || code > 84) return null;

    val = val * 85 + code;
    count++;

    if (count === 5) {
      decoded.writeUInt32BE(val, decIndex);
      decIndex += 4;
      val = 0;
      count = 0;
    }
  }

  if (count > 0) {
    if (count === 1) return null;
    for (let i = count; i < 5; i++) {
      val = val * 85 + 84;
    }
    const buf = Buffer.alloc(4);
    buf.writeUInt32BE(val, 0);
    buf.copy(decoded, decIndex, 0, count - 1);
    decIndex += count - 1;
  }

  decoded = decoded.slice(0, decIndex);

  try {
    const str = decoded.toString('utf-8');
    const printable = getPrintableCount(str);
    if (str.length > 0 && printable / str.length < 0.8) return null;
    return str;
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

  const b32 = tryBase32Decode(value);
  if (b32) results.push(b32);

  const byteArr = tryByteArrayDecode(value);
  if (byteArr) results.push(byteArr);

  const reversed = tryReversedDecode(value);
  if (reversed) results.push(reversed);

  const b58 = tryBase58Decode(value);
  if (b58) results.push(b58);

  const a85 = tryAscii85Decode(value);
  if (a85) results.push(a85);

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
      collectMatches(SINGLE_PERCENT_TOKEN, candidate, candidates, seen, next);
      collectMatches(BYTE_ARRAY_TOKEN, candidate, candidates, seen, next);
      collectMatches(REVERSED_PREFIX_TOKEN, candidate, candidates, seen, next);
      collectMatches(BASE58_TOKEN, candidate, candidates, seen, next);
      collectMatches(ASCII85_TOKEN, candidate, candidates, seen, next);
    }
    frontier = next;
    if (frontier.length === 0) break;
  }

  return candidates;
}
