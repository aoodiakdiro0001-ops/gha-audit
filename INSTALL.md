# INSTALL — gha-audit

## Requirements

- Python **3.8+** (standard library only — no third-party packages)
- Optional, for `fix --rules pin`: `git` on `PATH` (uses `git ls-remote`; skip with `--no-resolve`)
- Optional, for the scope guard's owner check: [`gh` CLI](https://cli.github.com/) authenticated (`gh auth login`)

## From PyPI

```bash
pip install gha-audit
# or, isolated:
pipx install gha-audit
```

## From source

```bash
git clone https://github.com/aoodiakdiro0001-ops/gha-audit
cd gha-audit
pip install .
```

Editable (development) install:

```bash
pip install -e .
```

## Without installing

```bash
git clone https://github.com/aoodiakdiro0001-ops/gha-audit
cd gha-audit
python3 -m gha_audit scan .
```

## Verify

```bash
gha-audit --version      # gha-audit 1.0.0
gha-audit rules          # 12 rules listed
python3 -m unittest discover -s tests   # 22 tests, OK
```

## Uninstall

```bash
pip uninstall gha-audit
```

## Troubleshooting

| Symptom | Fix |
|---|---|
| `command not found: gha-audit` | Use `python3 -m gha_audit ...`, or ensure `~/.local/bin` (pipx) is on `PATH` |
| `✗ refused to scan: outside home directory` | You are scanning outside `$HOME` — pass `--i-own-this` if you own it, or add a `.gha-audit-scope` file |
| `✗ refused to scan: repository owner ... does not match` | The checkout belongs to another account — pass `--i-own-this` only if you really own it |
| `pin` makes no changes | Network/`git ls-remote` unavailable — that is expected offline; re-run with connectivity |
| Colored output in CI logs | Add `--no-color` |

---
© 2026 Baran Avisat · MIT
