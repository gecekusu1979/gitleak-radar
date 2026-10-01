import AdmZip from "adm-zip";
import type { SecretDetector } from "./detector.js";
import type { Finding } from "../types/index.js";

/**
 * Scans archive files (e.g. .zip, .jar) directly from memory
 * bridging their extracted string outputs back to the engine.
 */
export class ArchiveProcessor {
    private detector: SecretDetector;

    constructor(detector: SecretDetector) {
        this.detector = detector;
    }

    public scanArchive(absolutePath: string, normalizedPath: string, findings: Finding[]): boolean {
        const ext = normalizedPath.split(".").pop()?.toLowerCase();
        if (ext !== "zip" && ext !== "jar") return false;

        try {
            const zip = new AdmZip(absolutePath);
            const zipEntries = zip.getEntries();

            for (const entry of zipEntries) {
                if (entry.isDirectory) continue;

                const buffer = entry.getData();
                if (this.isBinary(buffer)) continue;

                const content = buffer.toString("utf-8");
                // Emulate protocol routing scheme: myArchive.zip://internal/path/keys.env
                const entryPath = `${normalizedPath}://${entry.entryName}`;

                const lines = content.split(/\r?\n/);
                for (let i = 0; i < lines.length; i++) {
                    // Memory conservation logic is already handled inside scanLine, just direct proxy.
                    const chunkFindings = this.detector.scanLine(lines[i] || "", i + 1, entryPath, "low");
                    findings.push(...chunkFindings);
                }
            }
            return true;
        } catch {
            // Failed to parse, malformed archive or encryption lock. Pass to raw binary skip logic.
            return false;
        }
    }

    private isBinary(buffer: Buffer): boolean {
        const len = Math.min(buffer.length, 1024);
        for (let i = 0; i < len; i++) {
            if (buffer[i] === 0x00) return true; // Heuristic null-byte check
        }
        return false;
    }
}
