# Security Policy

## Supported versions

Security fixes are applied to the latest release and `main`.

## Reporting a vulnerability

Please **do not** open a public issue for security problems. Use GitHub's private
[Security Advisories](https://github.com/Wedian001/ClaudeGuard/security/advisories/new)
for this repository.

Helpful reports include:

- macOS version, Claude Guard version, and steps to reproduce;
- whether the issue is in the app, the CLI, or the build scripts;
- impact assessment (for example: can a probe be tricked into allowing a direct connection?);
- relevant logs or a proof of concept, with IPs and tokens redacted.

You can expect an initial response within a few days. This is a volunteer project,
so no bounty is offered.

## Scope

Claude Guard runs locally, with the current user's privileges. It does not
require root and does not modify Claude's installation. In-scope examples:

- bypassing the fail-closed gate;
- credential or session data leakage in probes, logs, or history;
- command injection or unsafe process handling;
- build or release artifacts that do not match the sources.
