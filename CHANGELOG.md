# CHANGELOG — gha-audit

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/); versioning follows [SemVer](https://semver.org/).

## [1.0.0] — 2026-11-12

### Added

- **Scanner** with 12 rules across four families:
  - injection: `gha-script-injection-run` (attacker-influenced context in `run:`)
  - secrets: `gha-secret-in-workflow-env`, `gha-secret-in-job-env`
  - pinning: `gha-unpinned-action`, `gha-unpinned-action-floating`
  - triggers/checkout: `gha-pr-target-checkout-head`, `gha-pr-target-checkout-credentials`,
    `gha-self-hosted-on-untrusted-trigger`, `gha-pull-request-fork-with-secrets`
  - credentials: `gha-hardcoded-credential`, `gha-credentials-persisted`
  - hygiene: `gha-missing-permissions`
- **Expression classifier** with an explicit whitelist of safe contexts
  (`github.repository`, `github.sha`, `github.actor`, `github.run_id`, …):
  attacker-controlled content → `critical`; `inputs`/refs → `high`.
- **Four idempotent fixers**: `envify`, `scope-secrets` (move/drop/keep), `pin`, `permissions`.
- **Four output formats**: `human`, `json`, `sarif` (SARIF 2.1.0), `markdown`.
- **Scope guard**: `.gha-audit-scope` allow-list file, `$HOME` boundary, and
  `origin`-owner vs `gh` login match; `--i-own-this` override; exit code `3`.
- **Exit-code contract**: `0` clean · `1` error · `2` findings ≥ `--fail-on` · `3` scope refusal.
- **Baseline drift detection**: `gha-audit verify baseline.json <path>` using stable fingerprints.
- CLI subcommands: `scan`, `fix`, `verify`, `rules` — runnable as `gha-audit` or `python3 -m gha_audit`.
- 22 unit tests (stdlib `unittest`, no test dependencies).
- Trilingual documentation: English, Arabic, Turkish.

### Security

- Fixers never widen exposure: `scope-secrets` keeps a secret only when it cannot be
  narrowed safely, and `envify` rewrites only expressions the classifier marks unsafe.
- `fix` is a dry-run by default; `--apply` is required to write.

[1.0.0]: https://github.com/aoodiakdiro0001-ops/gha-audit/releases/tag/v1.0.0
