export interface DecodedCandidate {
  text: string;
  offset: number;
}

const ENCODED_TOKEN = /[A-Za-z0-9+/_-]{16,}={0,2}/g;
const URL_TOKEN = /(?:%[0-9a-f]{2}){2,}[A-Za-z0-9%._~!$&'()*+,;=:@/?-]*/gi;
const MAX_DECODED_LENGTH = 8192;
const MAX_DEPTH = 2;

function addCandidate(
  candidates: DecodedCandidate[],
  seen: Set<string>,
  text: string,
  offset: number
): void {
  if (!text || text.length > MAX_DECODED_LENGTH || !/[^\x00-\x7f]/.test(text) && !/[A-Za-z]/.test(text)) {
    return;
  }
  const key = `${offset}:${text}`;
  if (!seen.has(key)) {
    seen.add(key);
    candidates.push({ text, offset });
  }
}

function decodeBase64(value: string): string | null {
  if (value.length % 4 === 1 || !/^[A-Za-z0-9+/_-]+={0,2}$/.test(value)) {
    return null;
  }
  try {
    const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
    const decoded = Buffer.from(normalized, "base64").toString("utf8");
    if (!decoded || decoded.includes("\uFFFD") || !/^[\x09\x0a\x0d\x20-\x7e]+$/.test(decoded)) {
      return null;
    }
    return decoded;
  } catch {
    return null;
  }
}

function decodeHex(value: string): string | null {
  if (value.length < 16 || value.length % 2 !== 0 || !/^[0-9a-f]+$/i.test(value)) {
    return null;
  }
  try {
    const decoded = Buffer.from(value, "hex").toString("utf8");
    return /^[\x09\x0a\x0d\x20-\x7e]+$/.test(decoded) ? decoded : null;
  } catch {
    return null;
  }
}

function decodeToken(value: string): string[] {
  const decoded: string[] = [];
  const urlDecoded = (() => {
    try {
      const result = decodeURIComponent(value);
      return result !== value ? result : null;
    } catch {
      return null;
    }
  })();
  if (urlDecoded) decoded.push(urlDecoded);
  const base64Decoded = decodeBase64(value);
  if (base64Decoded) decoded.push(base64Decoded);
  const hexDecoded = decodeHex(value);
  if (hexDecoded) decoded.push(hexDecoded);
  return decoded;
}

export function recursivelyDecodeLine(line: string): DecodedCandidate[] {
  const candidates: DecodedCandidate[] = [];
  const seen = new Set<string>();
  let frontier: DecodedCandidate[] = [{ text: line, offset: 0 }];

  for (let depth = 1; depth <= MAX_DEPTH; depth++) {
    const next: DecodedCandidate[] = [];
    for (const candidate of frontier) {
      ENCODED_TOKEN.lastIndex = 0;
      let match: RegExpExecArray | null;
      while ((match = ENCODED_TOKEN.exec(candidate.text)) !== null) {
        for (const decoded of decodeToken(match[0])) {
          const offset = candidate.offset + match.index;
          addCandidate(candidates, seen, decoded, offset);
          next.push({ text: decoded, offset });
        }
        URL_TOKEN.lastIndex = 0;
        while ((match = URL_TOKEN.exec(candidate.text)) !== null) {
          for (const decoded of decodeToken(match[0])) {
            const offset = candidate.offset + match.index;
            addCandidate(candidates, seen, decoded, offset);
            next.push({ text: decoded, offset });
          }
        }
      }
    }
    frontier = next;
  }

  return candidates;
}
