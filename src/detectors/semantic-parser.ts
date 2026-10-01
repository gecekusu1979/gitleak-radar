import yaml from "yaml";
import type { SecretDetector } from "./detector.js";
import type { Finding } from "../types/index.js";

/**
 * Iterates through structured objects to extract deeply nested keys and values.
 */
function traverseObject(obj: any, path: string, onKeyValue: (key: string, value: string, path: string) => void) {
    if (!obj || typeof obj !== "object") return;
    for (const [k, v] of Object.entries(obj)) {
        const currentPath = path ? `${path}.${k}` : k;
        if (typeof v === "string") {
            onKeyValue(k, v, currentPath);
        } else if (typeof v === "object") {
            traverseObject(v, currentPath, onKeyValue);
        }
    }
}

/**
 * Parses files structurally to detect bypassed secrets in JSON, YAML, or ENV arrays.
 */
export class SemanticParser {
    private detector: SecretDetector;

    constructor(detector: SecretDetector) {
        this.detector = detector;
    }

    public parseAndScan(content: string, filePath: string, findings: Finding[]): boolean {
        const ext = filePath.split(".").pop()?.toLowerCase();

        try {
            if (ext === "json") {
                const obj = JSON.parse(content);
                this.scanStruct(obj, filePath, findings);
                return true;
            } else if (ext === "yaml" || ext === "yml") {
                const obj = yaml.parse(content);
                this.scanStruct(obj, filePath, findings);
                return true;
            } else if (ext === "env") {
                this.scanEnv(content, filePath, findings);
                return true;
            }
        } catch {
            // Structural parsing failed, falback to naive regex scanner
        }

        return false;
    }

    private scanEnv(content: string, filePath: string, findings: Finding[]) {
        // Basic dotenv approximation
        const lines = content.split(/\r?\n/);
        lines.forEach((line, index) => {
            const trimmed = line.trim();
            if (!trimmed || trimmed.startsWith("#")) return;
            const eqIdx = trimmed.indexOf("=");
            if (eqIdx !== -1) {
                const key = trimmed.slice(0, eqIdx).trim();
                let value = trimmed.slice(eqIdx + 1).trim();
                if (value.startsWith('"') && value.endsWith('"')) value = value.slice(1, -1);
                else if (value.startsWith("'") && value.endsWith("'")) value = value.slice(1, -1);

                // Feed reconstructed valid format to line scanner to ensure rules map
                const syntheticLine = `${key}: ${value}`;
                const syntheticFindings = this.detector.scanLine(syntheticLine, index + 1, filePath, "low");
                syntheticFindings.forEach(f => findings.push({ ...f, rawSecret: value }));
            }
        });
    }

    private scanStruct(obj: any, filePath: string, findings: Finding[]) {
        traverseObject(obj, "", (key, value, __) => {
            const syntheticLine = `${key}: ${value}`;
            // Dummy line number 1 because structural tree drops line info.
            const syntheticFindings = this.detector.scanLine(syntheticLine, 1, filePath, "low");
            syntheticFindings.forEach(f => findings.push({ ...f, rawSecret: value }));
        });
    }
}
