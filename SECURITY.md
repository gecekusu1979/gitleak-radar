# Security Policy

GitLeak Radar is a local-first secret scanner. It is designed to help detect
credentials before they are committed or published, but it is not a guarantee
that every secret will be detected. Treat findings as sensitive and rotate any
credential that may have been exposed.

## Supported Versions

We actively provide security patches and updates for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 1.4.x   | :white_check_mark: |
| 1.3.x   | :x:                |
| < 1.3   | :x:                |

## Reporting a Vulnerability

We take the security of GitLeak Radar and its users seriously. Please do **not**
open a public issue for an unpatched vulnerability.

Preferred reporting channels:

1. **GitHub Private Vulnerability Reporting:** Open the repository's
   **Security** tab and select **Report a vulnerability**.
2. **Private maintainer contact:** Contact
   [@gecekusu1979](https://github.com/gecekusu1979) privately if private
   reporting is unavailable.

### What to include in your report:
- A clear description of the vulnerability and potential impact.
- Step-by-step instructions or proof-of-concept to reproduce the behavior.
- Any suggested fixes or mitigations.
- The affected version, commit, command, workflow, or action input.
- Whether the issue can expose plaintext credentials, `GITHUB_TOKEN`, or CI
  environment variables. Do not include real secrets in the report.

### Response timeline

- **Initial response:** Within 48 hours.
- **Status update:** Within 7 days, or sooner for actively exploited issues.
- **Fix and disclosure:** Coordinated with the reporter based on severity and
  downstream release requirements.

## Secure usage guidance

- Pin the npm package and GitHub Action to a reviewed release instead of a
  floating version or branch.
- Use a least-privilege token for optional PR comments and do not pass
  untrusted pull-request data into shell commands.
- Treat SARIF, JSON, JUnit, and GitLab reports as potentially sensitive even
  though findings are masked by default.
- Rotate exposed credentials immediately; removing a finding from a report does
  not remove it from Git history, logs, caches, or artifacts.
