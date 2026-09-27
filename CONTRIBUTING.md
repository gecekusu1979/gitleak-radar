# Contributing to GitLeak-Radar

We welcome contributions from the community! This document provides guidelines for contributing.

## Getting Started

1. Fork the repository on GitHub.
2. Clone your fork locally.
3. Install dependencies using `pnpm install`.
4. Ensure your Node version is `>=18.0.0`.

## Testing

Before submitting a pull request, ensure that all tests pass:

```bash
pnpm test
```

## Adding New Rules

When adding new detection rules:
- Update `src/detectors/rules.ts`
- Ensure `requiresEntropy` is used carefully on generic rules.
- Add corresponding test cases in `tests/detectors/detector.test.ts`.

## Submitting Pull Requests

1. Create a new branch from `main`.
2. Commit your changes with clear, descriptive messages.
3. Push to your fork and submit a PR to the `main` branch of this repository.

Thank you for helping secure our source code ecosystem!
