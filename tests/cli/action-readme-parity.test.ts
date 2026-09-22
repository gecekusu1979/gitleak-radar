import { describe, it, expect } from "vitest";
import fs from "node:fs/promises";
import path from "node:path";

const rootDir = process.cwd();
const actionPath = path.resolve(rootDir, "action.yml");
const readmePath = path.resolve(rootDir, "README.md");

describe("action.yml and README.md Parity", () => {
    it("ensures default values in action.yml and README.md are perfectly aligned", async () => {
        const actionContents = await fs.readFile(actionPath, "utf-8");
        const readmeContents = await fs.readFile(readmePath, "utf-8");

        // Parse action.yml inputs manually using regex to avoid external yaml parsers
        const actionInputs = new Map<string, string>();

        let inInputs = false;
        let currentInput = "";

        for (const line of actionContents.split("\n")) {
            if (line.startsWith("inputs:")) {
                inInputs = true;
                continue;
            }
            if (inInputs && line.match(/^[a-zA-Z]/)) {
                break; // Left inputs section
            }

            if (inInputs) {
                const matchName = line.match(/^  ([a-zA-Z0-9_-]+):/);
                if (matchName) {
                    currentInput = matchName[1];
                }
                const matchDefault = line.match(/^    default:\s*(?:'([^']*)'|"([^"]*)"|([^#\s]*))/);
                if (matchDefault && currentInput) {
                    const matchedVal = matchDefault[1] ?? matchDefault[2] ?? matchDefault[3];
                    actionInputs.set(currentInput, matchedVal === "" ? "empty" : matchedVal); // Treat empty string as "empty" token for README matches
                }
            }
        }

        // Action github-token default is empty string - map it properly
        expect(actionInputs.get("path")).toBe(".");
        expect(actionInputs.get("version")).toBe("1.5.1");

        // Build map from README Table
        const readmeTablePrefix = "| Input | Default | Purpose |";
        const lines = readmeContents.split("\n");
        const tableIndex = lines.findIndex(l => l.includes(readmeTablePrefix));
        expect(tableIndex).toBeGreaterThan(-1);

        const readmeInputs = new Map<string, string>();
        for (let i = tableIndex + 2; i < lines.length; i++) {
            const line = lines[i];
            if (!line.startsWith("|") || !line.includes("`")) break;

            const cols = line.split("|").map(col => col.trim());
            const inputMatch = cols[1]?.match(/`([a-zA-Z0-9_-]+)`/);
            const inputName = inputMatch ? inputMatch[1] : null;

            let defaultVal = cols[2];
            // if it has backticks extract it
            if (defaultVal.includes("`")) {
                const defaultMatch = defaultVal.match(/`([^`]+)`/);
                defaultVal = defaultMatch ? defaultMatch[1] : defaultVal;
            }
            if (inputName) {
                readmeInputs.set(inputName, defaultVal);
            }
        }

        const monitoredFields = [
            "path", "version", "severity", "since", "staged", "history", "baseline", "rules",
            "upload-sarif", "upload-artifact", "artifact-name", "fail-on-findings", "pr-comment", "github-token"
        ];

        for (const field of monitoredFields) {
            if (field === "github-token") continue; // Documented outside the main table
            expect(readmeInputs.has(field)).toBe(true);
            expect(actionInputs.get(field)).toBe(readmeInputs.get(field));
        }
    });
});
