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

  if (EXCLUDED_EXTENSIONS.has(ext)) return true;
  if (EXCLUDED_FILENAMES.has(basename)) return true;
  if (basename.endsWith(".min.js") || basename.endsWith(".min.css")) return true;

  return false;
}

const KNOWN_CANONICAL_PLACEHOLDERS = new Set([
  "akiaiosfodnn7example" // AWS'in resmi dokümantasyonunda kullandığı örnek Access Key ID
]);

export function isPlaceholderOrExample(
  extractedValue: string,
  lineContext: string,
  filePath?: string
): boolean {
  const normalizedValue = extractedValue.toLowerCase();
  const normalizedLine = lineContext.toLowerCase();

  if (KNOWN_CANONICAL_PLACEHOLDERS.has(normalizedValue)) {
    return true;
  }

  const normalizedPath = filePath ? filePath.toLowerCase().replace(/\\/g, "/") : "";
  const pathSegments = normalizedPath.split("/");
  const pathBasename = pathSegments[pathSegments.length - 1] || "";
  const TEST_OR_DOC_SEGMENTS = new Set([
    "test", "tests", "__tests__",
    "fixture", "fixtures",
    "mock", "mocks", "__mocks__",
    "example", "examples"
  ]);

  const isTestOrDoc =
    normalizedPath.endsWith(".md") ||
    normalizedPath.endsWith(".mdx") ||
    pathSegments.some((segment) => TEST_OR_DOC_SEGMENTS.has(segment)) ||
    /\.(test|spec|fixture|mock)\.[^./]+$/.test(pathBasename);

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
  if (isTestOrDoc && uniqueChars.size <= 2 && extractedValue.length > 6) {
    return true;
  }

  if (normalizedLine.includes("e.g.") || normalizedLine.includes("example:")) {
    return true;
  }

  return false;
}

/**
 * Hem dahili hariç tutulanları hem de özel desenleri (glob/uzantı/dizin) doğrular.
 */
export function shouldIgnorePath(filePath: string, customIgnores: string[] = []): boolean {
  if (shouldIgnoreFile(filePath)) {
    return true;
  }

  const normalized = filePath.replace(/\\/g, "/");

  for (const pattern of customIgnores) {
    if (!pattern) continue;
    const clean = pattern.replace(/^\*\*\//, "").replace(/\/\*\*$/, "");

    if (clean.startsWith("*.")) {
      const ext = clean.slice(1);
      if (normalized.endsWith(ext)) {
        return true;
      }
    }

    if (
      normalized === clean ||
      normalized.startsWith(`${clean}/`) ||
      normalized.endsWith(`/${clean}`) ||
      normalized.includes(`/${clean}/`)
    ) {
      return true;
    }
  }

  return false;
}
