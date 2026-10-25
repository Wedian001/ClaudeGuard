# Contributing

Thanks for taking the time to improve Claude Guard.

## Before you start

- Search existing issues and pull requests first.
- For security problems, **do not open a public issue** — see [SECURITY.md](SECURITY.md).
- For large changes, open an issue to discuss the approach before writing code.

## Development

Requirements: macOS 26+, Swift 6 toolchain (Command Line Tools is enough), no third-party dependencies. Use `./scripts/test.sh` — it passes the Swift Testing plugin path automatically on CLT-only installations.

```bash
./scripts/test.sh
swift build
swift run claude-guard selftest
```

To produce a runnable app bundle:

```bash
./scripts/bundle_app.sh
open dist/ClaudeGuard.app
```

## Pull requests

- Keep the change focused; avoid unrelated refactors.
- Add or update tests when behaviour changes. Run `./scripts/test.sh` before submitting.
- Preserve **fail-closed** semantics: new checks must default to blocking when data is missing or a probe fails.
- Do not add third-party runtime dependencies.
- Do not commit real IP addresses, tokens, cookies, personal paths, or machine-specific identifiers. Use fixtures such as `203.0.113.10` and `testuser`.
- Update [README.md](README.md) if user-facing behaviour, CLI flags, or build steps change.

## Commit messages

Use short imperative subjects, for example:

```
Fix IPv6 canary timeout handling
Add --json to close-check
```
