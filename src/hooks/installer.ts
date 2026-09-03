import fs from "node:fs/promises";
import path from "node:path";

export async function installPreCommitHook(targetDir: string = "."): Promise<{ success: boolean; message: string }> {
  const gitDir = path.resolve(targetDir, ".git");
  const hooksDir = path.join(gitDir, "hooks");
  const hookFile = path.join(hooksDir, "pre-commit");

  try {
    const stat = await fs.stat(gitDir);
    if (!stat.isDirectory()) {
      return { success: false, message: "Target .git is not a directory. Run 'git init' first." };
    }
  } catch {
    return { success: false, message: "No .git directory found. Run 'git init' first." };
  }

  const hookMarker = "# --- GITLEAK-RADAR-HOOK-START ---";
  const hookScriptBody = `
${hookMarker}
if command -v gitleak-radar >/dev/null 2>&1; then
  SCANNER_CMD="gitleak-radar"
elif command -v npx >/dev/null 2>&1; then
  SCANNER_CMD="npx --no-install gitleak-radar"
else
  echo "⚠️ GitLeak Radar not found in PATH or npx. Skipping check."
  exit 0
fi

echo "🕵️  GitLeak Radar: Scanning staged files..."
$SCANNER_CMD scan --staged
SCAN_EXIT=$?

if [ $SCAN_EXIT -eq 1 ]; then
  echo ""
  echo "❌ Commit blocked: Sensitive credentials detected in staged changes."
  echo "Please unstage or mask secrets before committing."
  exit 1
elif [ $SCAN_EXIT -eq 2 ]; then
  echo ""
  echo "⚠️ GitLeak Radar encountered an error during scan."
  exit 2
fi
# --- GITLEAK-RADAR-HOOK-END ---
`;

  try {
    await fs.mkdir(hooksDir, { recursive: true });
    let existingContent = "";
    try {
      existingContent = await fs.readFile(hookFile, "utf-8");
    } catch {
      existingContent = "#!/usr/bin/env sh\n";
    }

    if (existingContent.includes(hookMarker)) {
      return { success: true, message: "GitLeak Radar pre-commit hook is already installed and up to date." };
    }

    const updatedContent = `${existingContent.trimEnd()}\n${hookScriptBody.trim()}\n`;
    await fs.writeFile(hookFile, updatedContent, { mode: 0o755 });
    return { success: true, message: "Pre-commit hook successfully installed at .git/hooks/pre-commit" };
  } catch (err) {
    return { success: false, message: (err as Error).message };
  }
}
