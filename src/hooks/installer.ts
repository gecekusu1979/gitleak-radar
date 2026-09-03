import fs from "node:fs/promises";
import path from "node:path";

export async function installPreCommitHook(targetDir: string = "."): Promise<{ success: boolean; message: string }> {
  const gitDir = path.resolve(targetDir, ".git");
  const hooksDir = path.join(gitDir, "hooks");
  const hookFile = path.join(hooksDir, "pre-commit");

  try {
    await fs.access(gitDir);
  } catch {
    return { success: false, message: "No .git directory found. Run 'git init' first." };
  }

  const hookScript = `#!/usr/bin/env sh
# GitLeak Radar pre-commit hook
echo "🕵️  GitLeak Radar: Scanning for secrets before commit..."
npx gitleak-radar scan .

STATUS=$?
if [ $STATUS -ne 0 ]; then
  echo ""
  echo "❌ Commit blocked: Sensitive credentials detected."
  echo "Remove or mask secrets before committing."
  exit 1
fi
`;

  try {
    await fs.mkdir(hooksDir, { recursive: true });
    await fs.writeFile(hookFile, hookScript, { mode: 0o755 });
    return { success: true, message: "Pre-commit hook installed at .git/hooks/pre-commit" };
  } catch (err) {
    return { success: false, message: (err as Error).message };
  }
}
