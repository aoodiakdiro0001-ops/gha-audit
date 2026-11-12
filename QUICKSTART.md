# QUICKSTART — gha-audit

Five commands, in order.

## 1. Scan

```bash
gha-audit scan .
```

- Exit `0` = clean · exit `2` = something at/above `high` · exit `3` = scope refused.
- Add `-v` to see snippets, the suggested fix and a stable fingerprint per finding.

## 2. Preview fixes

```bash
gha-audit fix .                       # dry-run: unified diff, nothing written
```

## 3. Apply fixes

```bash
gha-audit fix . --apply                       # all default fixers (envify)
gha-audit fix . --rules envify,scope-secrets,permissions --apply
gha-audit fix . --rules pin --apply           # resolves tags -> SHA (needs network)
```

Every fixer is idempotent: run it twice, the second run changes nothing.

## 4. Re-scan to confirm

```bash
gha-audit scan .
```

## 5. Wire it into CI

```yaml
# .github/workflows/audit.yml
name: gha-audit
on: [push, pull_request]
permissions:
  contents: read
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install gha-audit
      - run: gha-audit scan . --fail-on high
      - run: gha-audit scan . --format sarif --output gha-audit.sarif --fail-on none
        if: always()
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: gha-audit.sarif
```

### Baseline / drift mode

```bash
gha-audit scan . --format json --fail-on none > baseline.json   # commit this
gha-audit verify baseline.json .                                # fails only on NEW findings
```

### One-liners

```bash
gha-audit scan . --format json | jq '.counts'        # counts only
gha-audit scan . --severity critical                 # show critical only
gha-audit scan . --fail-on none --output report.md   # markdown report, never fails
```

---
© 2026 Baran Avisat · MIT
