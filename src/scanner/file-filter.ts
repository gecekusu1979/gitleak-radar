import path from "node:path";

export const EXCLUDED_DIRECTORIES = [
  "**/node_modules/**",
  "**/.git/**",
  "**/dist/**",
  "**/build/**",
  "**/.next/**",
  "**/coverage/**",
  "**/vendor/**"
];

export const EXCLUDED_EXTENSIONS = new Set([
  ".exe", ".dll", ".so", ".dylib", ".bin",
  ".zip", ".tar", ".gz", ".7z", ".rar",
  ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".webp",
  ".mp4", ".mp3", ".wav", ".avi", ".mov",
  ".pdf", ".woff", ".woff2", ".ttf", ".eot",
  ".lock"
]);

export const EXCLUDED_FILENAMES = new Set([
  "package-lock.json",
  "pnpm-lock.yaml",
  "yarn.lock",
  "composer.lock"
]);

const PLACEHOLDERS = [
  "your_api_key",
  "change_me",
  "example",
  "test",
  "xxxx",
  "********",
  "my_secret",
  "placeholder",
  "dummy",
  "todo"
];

const OBVIOUS_PLACEHOLDER_SUBSTRINGS = [
  "your_api_key",
  "change_me",
  "xxxx",
  "********",
  "my_secret",
  "placeholder"
];

export function shouldIgnoreFile(filePath: string): boolean {
  const normalizedPath = filePath.replace(/\\/g, "/");
  const ext = path.extname(filePath).toLowerCase();
  const basename = path.basename(filePath);

  // Only ignore gitleak-radar's internal detector rule and engine definitions
  if (
    normalizedPath === "src/detectors/rules.ts" ||
    normalizedPath.endsWith("/src/detectors/rules.ts") ||
    normalizedPath === "src/detectors/detector.ts" ||
    normalizedPath.endsWith("/src/detectors/detector.ts")
  ) {
    return true;
  }

  if (EXCLUDED_EXTENSIONS.has(ext)) return true;
  if (EXCLUDED_FILENAMES.has(basename)) return true;
  if (basename.endsWith(".min.js") || basename.endsWith(".min.css")) return true;

  return false;
}

export function isPlaceholderOrExample(
  extractedValue: string,
  lineContext: string,
  filePath?: string
): boolean {
  const normalizedValue = extractedValue.toLowerCase();
  const normalizedLine = lineContext.toLowerCase();
  const normalizedPath = filePath ? filePath.toLowerCase().replace(/\\/g, "/") : "";

  const isTestOrDoc =
    normalizedPath.includes("test") ||
    normalizedPath.includes("fixture") ||
    normalizedPath.includes("mock") ||
    normalizedPath.includes("example") ||
    normalizedPath.endsWith(".md") ||
    normalizedPath.endsWith(".mdx");

  if (isTestOrDoc) {
    if (PLACEHOLDERS.some((p) => normalizedValue.includes(p))) {
      return true;
    }
  } else {
    // Normal production source files: strict equality for common words, substring only for unambiguous markers
    if (PLACEHOLDERS.some((p) => normalizedValue === p)) {
      return true;
    }
    if (OBVIOUS_PLACEHOLDER_SUBSTRINGS.some((p) => normalizedValue.includes(p))) {
      return true;
    }
  }

  const uniqueChars = new Set(extractedValue.split(""));
  if (uniqueChars.size <= 2 && extractedValue.length > 6) {
    return true;
  }

  if (normalizedLine.includes("e.g.") || normalizedLine.includes("example:")) {
    return true;
  }

  return false;
}
