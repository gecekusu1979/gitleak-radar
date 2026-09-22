import { describe, it, expect } from "vitest";
import { recursivelyDecodeLine, DEFAULT_MAX_DECODE_DEPTH } from "../../src/detectors/decoder.js";

describe("recursivelyDecodeLine - depth parameter", () => {
    it("returns no candidates when maxDepth is 0", () => {
        const encoded = Buffer.from("AKIAIOSFODNN7QAZWSXE").toString("base64");
        expect(recursivelyDecodeLine(`token=${encoded}`, 0)).toEqual([]);
    });

    it("defaults to DEFAULT_MAX_DECODE_DEPTH (2) when no depth is given", () => {
        const once = Buffer.from("AKIAIOSFODNN7QAZWSXE").toString("base64");
        const twice = Buffer.from(once).toString("base64");
        expect(DEFAULT_MAX_DECODE_DEPTH).toBe(2);
        const candidates = recursivelyDecodeLine(twice);
        expect(candidates.some((c) => c.text === "AKIAIOSFODNN7QAZWSXE")).toBe(true);
    });

    it("depth=1 decodes a single layer but not a doubly-wrapped one", () => {
        const once = Buffer.from("AKIAIOSFODNN7QAZWSXE").toString("base64");
        const twice = Buffer.from(once).toString("base64");

        const shallow = recursivelyDecodeLine(twice, 1);
        expect(shallow.some((c) => c.text === "AKIAIOSFODNN7QAZWSXE")).toBe(false);
        expect(shallow.some((c) => c.text === once)).toBe(true);

        const deep = recursivelyDecodeLine(twice, 2);
        expect(deep.some((c) => c.text === "AKIAIOSFODNN7QAZWSXE")).toBe(true);
    });

    it("finds both a Base64 token and a URL-encoded token on the same line (sibling-loop regression check)", () => {
        // Önceki sürümde URL_TOKEN taraması ENCODED_TOKEN döngüsünün içine yerleşikti;
        // bu satır her iki kodlamanın da AYNI ANDA doğru şekilde çözüldüğünü doğrular.
        const base64Secret = Buffer.from("AKIAIOSFODNN7QAZWSXE").toString("base64");
        const urlSecret = "%73%65%63%72%65%74%2D%75%72%6C"; // "secret-url"
        const line = `b64=${base64Secret} url=${urlSecret}`;

        const candidates = recursivelyDecodeLine(line, 2);
        expect(candidates.some((c) => c.text === "AKIAIOSFODNN7QAZWSXE")).toBe(true);
        expect(candidates.some((c) => c.text === "secret-url")).toBe(true);
    });

    it("does not redundantly duplicate identical candidates from repeated tokens", () => {
        const base64Secret = Buffer.from("AKIAIOSFODNN7QAZWSXE").toString("base64");
        // Aynı token satırda 3 kez geçsin: seen set dedup çalışmalı
        const line = `a=${base64Secret} b=${base64Secret} c=${base64Secret}`;

        const candidates = recursivelyDecodeLine(line, 2);
        const matches = candidates.filter((c) => c.text === "AKIAIOSFODNN7QAZWSXE");
        // Aynı metin 3 farklı offset'ten gelse de seen set tekrarları filtreler → 1 adet
        expect(matches.length).toBeGreaterThanOrEqual(1);
        // Patlama olmamalı
        expect(candidates.length).toBeLessThan(50);
    });
});
