# SUPPORT — gha-audit

Thanks for using gha-audit.

## Get help

| Channel | Use for |
|---|---|
| [GitHub Issues](https://github.com/aoodiakdiro0001-ops/gha-audit/issues) | Bugs, false positives/negatives, feature requests |
| Email — baranavisat@gmail.com | Security reports and private matters |
| `gha-audit rules --format markdown` | Self-serve rule documentation |

## Reporting a security issue

Please report security issues in gha-audit itself **privately by email** to
baranavisat@gmail.com rather than in a public issue. Include:

1. the affected version (`gha-audit --version`);
2. a minimal workflow file that reproduces the problem;
3. expected vs. actual behavior (ideally with `--format json` output).

You will get an acknowledgement as soon as possible. Do not disclose the issue
publicly until a fix is released.

## Reporting a false positive

A false positive costs everyone time. When reporting one:

- attach the **workflow file** (redact real secrets) and the exact command;
- run with `-v` and include the `id:` fingerprint line;
- state which rule fired and why you believe the code is safe.

## Reporting a missed finding (false negative)

- attach the workflow snippet that should have been flagged;
- name the rule you expected (see `gha-audit rules`).

## Before you open an issue

1. Update to the latest version (`pip install -U gha-audit`).
2. Re-run with `--no-color` to rule out terminal artifacts.
3. Search [existing issues](https://github.com/aoodiakdiro0001-ops/gha-audit/issues).

## Scope note

gha-audit only reads local files and only scans targets inside your ownership
boundary (see the scope guard in README.md). Report vulnerabilities **in the
repositories you audit** to their own maintainers — this toolkit does not
replace a bug-bounty program and must never be pointed at targets you do not own.

---
© 2026 Baran Avisat · MIT
