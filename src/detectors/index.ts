/**
 * src/detectors/index.ts
 *
 * Public API entry point for the detectors subpath export (`gitleak-radar/detectors`).
 * Consumers can import SecretDetector and DETECTION_RULES for programmatic line-by-line scanning.
 *
 * Note: SecretDetector uses node:crypto for allowlist hashing.
 * It is therefore NOT compatible with Edge Runtime / browser environments.
 * Use DETECTION_RULES alone if you need a runtime-agnostic solution.
 */

export { SecretDetector, MAX_LINE_LENGTH } from "./detector.js";
export { DETECTION_RULES } from "./rules.js";
export type { DetectionRule, Finding, Severity } from "../types/index.js";
export { SeverityOrder } from "../types/index.js";
