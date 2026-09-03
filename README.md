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

## Why GitLeak Radar?

- **Zero Raw Value Exposure:** Masking logic prevents leakage via CI build logs, terminals, or shared screens.
- **Deterministic Heuristics:** Employs false-positive suppression against placeholders (`CHANGE_ME`, `example`, test fixtures) and lockfiles.
- **Pre-commit Gate:** Native Git hook prevents committing sensitive credentials before they reach remotes.
- **Zero Runtime Bloat:** Self-contained CLI with minimal dependencies, no cloud backends, no telemetry.

## Installation

```bash
# Global installation
npm install -g gitleak-radar

# Or execute ad-hoc via npx
npx gitleak-radar scan .
```

## Usage

```bash
# Scan working directory
gitleak-radar scan .

# Verbose mode (inspect each file resolution)
gitleak-radar scan . --verbose

# Filter by minimum severity threshold
gitleak-radar scan ./src --severity high

# Ignore specific folders
gitleak-radar scan . --ignore tests fixtures

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

## License

GNU GPLv3 (Custom Restrictive) © 2026 gecekusu1979