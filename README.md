# gha-audit

**GitHub Actions Security Audit Toolkit** — offline, zero-dependency workflow auditing with safe automatic fixes.

[English](README.md) · [العربية](README.ar.md) · [Türkçe](README.tr.md)

```
$ gha-audit scan .
gha-audit 1.0.0 — GitHub Actions Security Audit Toolkit
target : .
files  : 9 workflow file(s)

██████ CRITICAL (2)
  ● .github/workflows/ci.yml:41
    Untrusted GitHub context interpolated into run:
    Expression `github.event.comment.body` reaches the shell and carries attacker-influenced data

summary: 2 critical, 5 high, 3 medium, 1 low
$ echo $?
2
```

## Why

A GitHub Actions workflow is code that runs with your repository's secrets — and most of it is YAML that nobody reviews like code. The classic failures this toolkit catches:

- **Script injection** — `${{ github.event.comment.body }}` (or any attacker-influenced context) interpolated straight into `run:`, giving anyone who can open an issue or PR remote code execution on your runners.
- **Secret over-exposure** — a secret declared at workflow level is handed to every job and step, including steps that run untrusted code.
- **Unpinned actions** — `uses: actions/checkout@v4` can be moved under you; a tag is not a commit.
- **`pull_request_target` + checkout of PR code** — the combination that has burned countless maintainers.
- **Missing least-privilege `permissions:`** — the default token is more powerful than your workflow needs.

## Features

- **12 rules** across injection, secrets, pinning, triggers and permissions — each with a plain-language explanation and a concrete fix.
- **4 output formats**: `human` (colored terminal), `json`, `sarif` (GitHub code scanning / VS Code), `markdown` (reports).
- **4 idempotent fixers** that rewrite workflows safely:
  - `envify` — moves `${{ github.* }}` out of `run:` bodies into a step-level `env:`
  - `scope-secrets` — shrinks a workflow/job secret env to the single step that reads it (move / drop / keep)
  - `pin` — rewrites `uses: owner/repo@vN` to a full commit SHA, keeping the tag as a comment
  - `permissions` — inserts an explicit least-privilege `permissions:` block
- **Zero dependencies** — Python 3.8+ standard library only, no PyYAML, no network required (except `pin`'s SHA resolution, which is opt-out via `--no-resolve`).
- **Scope guard** — refuses to scan a target outside your ownership boundary unless you pass `--i-own-this`.
- **CI-friendly exit codes**: `0` clean · `1` error · `2` findings at/above `--fail-on` · `3` refused by scope guard.

## Install

```bash
pip install gha-audit        # or: pipx install gha-audit
```

From source:

```bash
git clone https://github.com/aoodiakdiro0001-ops/gha-audit
cd gha-audit && pip install .
```

No install at all:

```bash
python3 -m gha_audit scan .
```

## Quick start

```bash
# scan a repository (exit 2 if anything at/above high is found)
gha-audit scan .

# see what would change, then apply
gha-audit fix .                          # dry-run diff
gha-audit fix . --apply                  # write changes

# scope secrets to the steps that read them
gha-audit fix . --rules scope-secrets --apply

# pin every action to a commit SHA (uses git ls-remote; --no-resolve to skip)
gha-audit fix . --rules pin --apply

# machine-readable outputs
gha-audit scan . --format json  > report.json
gha-audit scan . --format sarif > report.sarif   # upload to code scanning
gha-audit scan . --format markdown > report.md

# baseline / drift detection in CI
gha-audit scan . --format json --fail-on none > baseline.json
gha-audit verify baseline.json .

# list the rule catalogue
gha-audit rules
```

### Scope guard

The toolkit only reads local files, but a shared machine can hold repositories that belong to someone else. Before any scan it checks that you own the target:

1. `--i-own-this` — you asserted ownership on the command line (recorded in the report);
2. a `.gha-audit-scope` file in the target or any parent directory may list allowed path prefixes;
3. otherwise the target must be inside `$HOME` and, if it is a git checkout, its `origin` owner must match the authenticated `gh` account.

Anything else → `✗ refused to scan`, exit code `3`. This mirrors the same boundary used by the companion bug-bounty tooling: **never point a scanner at a target you do not own.**

## Rules

| ID | Severity | What it catches |
|---|---|---|
| `gha-script-injection-run` | critical/high | Attacker-influenced context interpolated into `run:` |
| `gha-secret-in-workflow-env` | high | Secret exposed to every job and step |
| `gha-secret-in-job-env` | medium | Secret exposed to every step of a job |
| `gha-unpinned-action-floating` | high | Action pinned to `main` / `master` / `latest` |
| `gha-pr-target-checkout-head` | critical | `pull_request_target` checks out untrusted PR code |
| `gha-pr-target-checkout-credentials` | high | `pull_request_target` checkout keeps credentials |
| `gha-self-hosted-on-untrusted-trigger` | high | Self-hosted runner executes an untrusted trigger |
| `gha-hardcoded-credential` | critical | Hard-coded token/password in the workflow |
| `gha-pull-request-fork-with-secrets` | medium | Untrusted trigger combined with privileged checkout |
| `gha-unpinned-action` | medium | Action not pinned to a full commit SHA |
| `gha-missing-permissions` | low | No explicit `permissions:` block |
| `gha-credentials-persisted` | low | Checkout persists the token in the workspace |

Run `gha-audit rules` for the full descriptions, or `gha-audit rules --format markdown` for documentation-ready output.

## Severity & exit codes

| Code | Meaning |
|---|---|
| `0` | Clean, or fixes applied |
| `1` | Internal / usage error |
| `2` | Findings at or above `--fail-on` (default `high`) |
| `3` | Refused: target outside the ownership boundary |

Expression classification: contexts that carry **attacker-controlled content** (issue/comment bodies, titles, `head_ref`, commit messages) are `critical`; `inputs` and refs are `high`; safe whitelisted contexts (`github.repository`, `github.sha`, `github.actor`, …) are never flagged.

## Development

```bash
python3 -m unittest discover -s tests    # 22 tests, stdlib only
```

The CI workflow in `.github/workflows/ci.yml` runs the test suite and audits this repository with `gha-audit` itself.

## License

MIT © 2026 Baran Avisat — see [LICENSE](LICENSE).

## Support

- Bugs and feature requests: [GitHub Issues](https://github.com/aoodiakdiro0001-ops/gha-audit/issues)
- Email: baranavisat@gmail.com
- See [SUPPORT.md](SUPPORT.md)

---
© 2026 Baran Avisat. Free and open source (MIT).
