# 🕵️ GitLeak Radar

> Lightweight, high-velocity source code secret and credential leak scanner for local dev & CI/CD pipelines.

[![CI](https://github.com/gecekusu1979/gitleak-radar/actions/workflows/ci.yml/badge.svg)](https://github.com/gecekusu1979/gitleak-radar/actions)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.3+-3178C6.svg)](https://www.typescriptlang.org/)

```text
GitLeak Radar
────────────────────────────────────────
Scanning ./my-project...

✓ Scanned 184 files
✓ 42,381 lines

Findings:

 CRITICAL   .env:4:1
   AWS Access Key
   Fingerprint: AKIA********MPLE

 HIGH       config/database.ts:18:14
   Database Connection String
   Fingerprint: post********root

────────────────────────────────────────
Security Score: 45/100 (Critical)
2 findings found  |  1 critical  |  1 high
Scan completed in 0.42s
```

## Features

- **Zero Raw Value Exposure:** Masking logic prevents leaks via CI build logs, terminals, or shared screens.
- **Deterministic False-Positive Filtering:** Suppresses placeholder tokens (`CHANGE_ME`, `example`, test fixtures) and lockfiles.
- **Staged Git Changes Scanner (`--staged`):** Rapid verification of Git staging area prior to commits.
- **Pre-commit Gate:** Native Git hook prevents committing sensitive credentials before they reach remotes.
- **Zero Runtime Bloat:** Self-contained CLI, zero cloud telemetry, instant execution.

## Installation

```bash
# Global installation
npm install -g gitleak-radar

# Or execute ad-hoc via npx
npx gitleak-radar scan .
```

## CLI Usage

```bash
# Scan working directory
gitleak-radar scan .

# Scan ONLY staged files in Git index
gitleak-radar scan --staged

# Verbose mode (inspect each file resolution)
gitleak-radar scan . --verbose

# Filter by minimum severity
gitleak-radar scan ./src --severity high

# Ignore specific folders
gitleak-radar scan . --ignore fixtures dist

# Machine-readable JSON output for CI pipelines
gitleak-radar scan . --json

# List active detection rules
gitleak-radar rules

# Install automated Git pre-commit hook
gitleak-radar install-hook
```

## Configuration (`.gitleak-radar.json`)

Customize scanner behavior directly in your project root:

```json
{
  "ignore": [
    "fixtures/**",
    "examples/**"
  ],
  "rules": {
    "jwt": false,
    "generic-password": false
  }
}
```

## Exit Codes

| Exit Code | Description |
| --- | --- |
| `0` | Scan succeeded with zero findings matching threshold |
| `1` | One or more secret leaks were detected |
| `2` | Configuration error, invalid arguments, or filesystem access failure |

## Contributing & Development

```bash
# Clone & install
git clone https://github.com/gecekusu1979/gitleak-radar.git
cd gitleak-radar
pnpm install

# Test, typecheck, and build
pnpm typecheck
pnpm test
pnpm build
```

To verify the package contents before publishing:

```bash
pnpm pack --dry-run
```

## v1.0.0 Production & Release Report

```text
SECURITY AUDIT
Critical: 0
High: 0
Medium: 0
Low: 0
- Secret masking is active in all JSON and terminal reporters.
- Git commands use execFile with argument arrays to prevent shell injection.
- Only project source code is tracked; sensitive paths and personal data are excluded.

TESTS
Passed: 26
Failed: 0
- Detector tests: 7 passed
- Scanner/Filter tests: 5 passed
- Config tests: 4 passed
- Scorer tests: 4 passed
- Git staged tests: 3 passed
- CLI smoke tests: 3 passed

BUILD
Typecheck: PASS
Test: PASS
Build: PASS

PACKAGE
npm pack: PASS (Only dist/, README.md, and LICENSE are included; tests and logs are filtered.)

DOCUMENTATION
README: PASS (GPLv3 license, --staged command, .gitleak-radar.json, and CI usage are documented.)

RELEASE STATUS
Ready for v1.0.0: YES
```

## License

This project is licensed under the terms of the GNU General Public License v3.0 (GPLv3) - see the [LICENSE](LICENSE) file for details.