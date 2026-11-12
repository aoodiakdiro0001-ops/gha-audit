# -*- coding: utf-8 -*-
"""
gha-audit reporters — human, json, sarif, markdown.

All reporters consume the same `Report` object so `--format` never changes
the findings themselves, only their rendering.  SARIF 2.1.0 output plugs
straight into GitHub code scanning / VS Code SARIF viewers.
"""
import json
import platform
import sys
from typing import Dict, List

from . import __version__
from .rules import RULES, SEVERITY_ORDER
from .scanner import Report

SEV_COLOR = {
    "critical": "\033[1;31m",
    "high": "\033[31m",
    "medium": "\033[33m",
    "low": "\033[36m",
    "info": "\033[2m",
}
RESET = "\033[0m"
BOLD = "\033[1m"


def _colorize(enabled: bool):
    def c(sev: str, text: str) -> str:
        if not enabled:
            return text
        return "%s%s%s" % (SEV_COLOR.get(sev, ""), text, RESET)
    return c


def _rule_of(f) -> str:
    return RULES[f.rule_id].title if f.rule_id in RULES else f.rule_id


def render_human(report: Report, color: bool = None, verbose: bool = False) -> str:
    if color is None:
        color = sys.stdout.isatty()
    c = _colorize(color)
    counts = report.counts()
    out: List[str] = []
    out.append("%sgha-audit %s%s — GitHub Actions Security Audit Toolkit"
               % (BOLD if color else "", __version__, RESET if color else ""))
    out.append("target : %s" % report.target)
    out.append("files  : %d workflow file(s)" % report.files_scanned)
    out.append("")

    if not report.findings:
        out.append(c("info", "✔ no findings — the workflows look clean"))
        return "\n".join(out)

    for sev in SEVERITY_ORDER:
        group = [f for f in report.findings if f.severity == sev]
        if not group:
            continue
        out.append(c(sev, "%s %s (%d)" % ("█" * 6, sev.upper(), len(group))))
        for f in group:
            out.append("  %s %s:%d" % (c(sev, "●"), f.file, f.line))
            out.append("    %s" % _rule_of(f))
            out.append("    %s" % f.message)
            if verbose:
                out.append("    snippet: %s" % f.snippet.strip()[:160])
                out.append("    fix    : %s" % f.remediation)
                out.append("    id     : %s" % f.fingerprint)
        out.append("")
    out.append("summary: " + ", ".join(
        c(s, "%d %s" % (counts[s], s))
        for s in SEVERITY_ORDER if counts[s]))
    return "\n".join(out)


def render_json(report: Report) -> str:
    return json.dumps({
        "tool": "gha-audit",
        "version": __version__,
        "target": report.target,
        "files_scanned": report.files_scanned,
        "counts": report.counts(),
        "findings": [f.as_dict() for f in report.findings],
    }, indent=2, ensure_ascii=False)


SARIF_LEVEL = {"critical": "error", "high": "error",
               "medium": "warning", "low": "note", "info": "note"}


def render_sarif(report: Report) -> str:
    rules, seen = [], set()
    results = []
    for f in report.findings:
        if f.rule_id not in seen:
            seen.add(f.rule_id)
            r = RULES[f.rule_id]
            rules.append({
                "id": r.id,
                "name": r.title.replace(" ", ""),
                "shortDescription": {"text": r.title},
                "fullDescription": {"text": r.description},
                "help": {"text": r.remediation,
                         "markdown": "**Fix:** %s" % r.remediation},
                "properties": {"security-severity": {
                    "critical": "9.5", "high": "7.5",
                    "medium": "5.0", "low": "3.0", "info": "1.0"}[r.severity],
                    "tags": ["security", r.cwe or ""]},
            })
        results.append({
            "ruleId": f.rule_id,
            "level": SARIF_LEVEL[f.severity],
            "message": {"text": "%s (%s)" % (f.message, f.rule_id)},
            "partialFingerprints": {"ghaAuditFingerprint": f.fingerprint},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.file},
                    "region": {"startLine": f.line,
                               "snippet": {"text": f.snippet.strip()[:400]}},
                }
            }],
        })
    doc = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "gha-audit",
                "version": __version__,
                "informationUri": "https://github.com/aoodiakdiro0001-ops/gha-audit",
                "rules": rules,
            }},
            "results": results,
        }],
    }
    return json.dumps(doc, indent=2, ensure_ascii=False)


def render_markdown(report: Report) -> str:
    counts = report.counts()
    out: List[str] = []
    out.append("# gha-audit report")
    out.append("")
    out.append("| | |")
    out.append("|---|---|")
    out.append("| Tool | gha-audit %s |" % __version__)
    out.append("| Target | `%s` |" % report.target)
    out.append("| Files scanned | %d |" % report.files_scanned)
    out.append("| Findings | %d |" % len(report.findings))
    for s in SEVERITY_ORDER:
        if counts[s]:
            out.append("| %s | %d |" % (s.capitalize(), counts[s]))
    out.append("")
    if not report.findings:
        out.append("✅ **No findings.**")
        return "\n".join(out)
    out.append("## Findings")
    out.append("")
    out.append("| Severity | Rule | File:Line | Message |")
    out.append("|---|---|---|---|")
    for f in sorted(report.findings,
                    key=lambda x: (SEVERITY_ORDER.index(x.severity), x.file, x.line)):
        msg = f.message.replace("|", "\\|")
        out.append("| %s | `%s` | `%s:%d` | %s |" %
                   (f.severity, f.rule_id, f.file, f.line, msg))
    out.append("")
    out.append("## Remediation")
    out.append("")
    seen = set()
    for f in report.findings:
        if f.rule_id in seen:
            continue
        seen.add(f.rule_id)
        r = RULES[f.rule_id]
        out.append("- **%s** — %s" % (r.title, r.remediation))
    out.append("")
    out.append("---")
    out.append("*Generated by gha-audit %s on %s/%s.*" % (
        __version__, platform.system(), platform.machine()))
    return "\n".join(out)


RENDERERS = {
    "human": render_human,
    "json": render_json,
    "sarif": render_sarif,
    "markdown": render_markdown,
}


def render(report: Report, fmt: str, **kwargs) -> str:
    fn = RENDERERS[fmt]
    if fmt == "human":
        return fn(report, **kwargs)
    return fn(report)
