# -*- coding: utf-8 -*-
"""
gha-audit command line interface.

    gha-audit scan   <path...>   scan workflows (exit 2 when >= threshold)
    gha-audit fix    <path...>   rewrite workflows safely (dry-run by default)
    gha-audit verify <baseline>  diff a new scan against a stored baseline
    gha-audit rules              list the rule catalogue

Exit codes
----------
  0  clean (or fixes applied)
  1  internal / usage error
  2  findings at or above the severity threshold
  3  refused: target outside the ownership boundary
"""
import argparse
import json
import os
import sys
from typing import List, Optional

from . import __version__
from .fixers import FIXERS, apply_fixers
from .report import render
from .rules import RULES, SEVERITY_ORDER, all_rules, severity_at_least
from .scanner import scan
from .scope import ScopeError, check_scope

EXIT_OK, EXIT_ERROR, EXIT_FINDINGS, EXIT_SCOPE = 0, 1, 2, 3


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="gha-audit",
        description="GitHub Actions Security Audit Toolkit — offline, "
                    "zero-dependency workflow auditing.")
    p.add_argument("--version", action="version",
                   version="gha-audit %s" % __version__)
    sub = p.add_subparsers(dest="command")

    s = sub.add_parser("scan", help="scan workflow files")
    s.add_argument("paths", nargs="+")
    s.add_argument("--format", choices=["human", "json", "sarif", "markdown"],
                   default="human")
    s.add_argument("--severity", default="all",
                   help="minimum severity to report: %s (default: all)"
                        % "/".join(SEVERITY_ORDER + ("all",)))
    s.add_argument("--fail-on", default="high",
                   help="exit 2 when a finding at/above this severity exists "
                        "(default: high; use 'none' to never fail)")
    s.add_argument("--exclude", action="append", default=[],
                   help="regex applied to file paths (repeatable)")
    s.add_argument("--output", help="write the report to this file")
    s.add_argument("--no-color", action="store_true")
    s.add_argument("--verbose", "-v", action="store_true")
    s.add_argument("--i-own-this", action="store_true",
                   help="assert you own every target (logged in the report)")
    s.add_argument("--allow-foreign", action="store_true",
                   help="skip the ownership check (still local files only)")

    f = sub.add_parser("fix", help="rewrite workflows to remove findings")
    f.add_argument("paths", nargs="+")
    f.add_argument("--rules", default="envify",
                   help="comma list: %s (default: envify)"
                        % ",".join(sorted(FIXERS)))
    f.add_argument("--apply", action="store_true",
                   help="write changes to disk (default: dry-run diff)")
    f.add_argument("--no-resolve", action="store_true",
                   help="skip `pin`'s network resolution (git ls-remote)")
    f.add_argument("--i-own-this", action="store_true")

    v = sub.add_parser("verify", help="compare a scan against a baseline")
    v.add_argument("baseline", help="baseline JSON produced by `scan --format json`")
    v.add_argument("paths", nargs="+")
    v.add_argument("--i-own-this", action="store_true")
    v.add_argument("--allow-foreign", action="store_true")

    r = sub.add_parser("rules", help="list the rule catalogue")
    r.add_argument("--format", choices=["human", "json", "markdown"],
                   default="human")
    return p


def _filter_by_severity(report, minimum: str):
    if minimum in ("all", "none"):
        return report
    report.findings = [f for f in report.findings
                       if severity_at_least(f.severity, minimum)]
    return report


def _scope_guard(paths, args) -> int:
    try:
        decision = check_scope(
            paths,
            i_own_this=getattr(args, "i_own_this", False),
            allow_foreign=getattr(args, "allow_foreign", False),
        )
    except ScopeError as exc:                       # pragma: no cover
        print("scope error: %s" % exc, file=sys.stderr)
        return EXIT_SCOPE
    if not decision.allowed:
        print("✗ refused to scan: %s" % decision.reason, file=sys.stderr)
        print("  (use --i-own-this if you really own these targets)",
              file=sys.stderr)
        return EXIT_SCOPE
    return EXIT_OK


def cmd_scan(args) -> int:
    rc = _scope_guard(args.paths, args)
    if rc != EXIT_OK:
        return rc
    report = scan(args.paths, exclude=args.exclude)
    report = _filter_by_severity(report, args.severity)
    text = render(report, args.format,
                  color=not args.no_color, verbose=args.verbose)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(text)
        print("report written to %s" % args.output, file=sys.stderr)
    else:
        print(text)
    worst = report.worst()
    if worst and severity_at_least(worst, args.fail_on):
        return EXIT_FINDINGS
    return EXIT_OK


def cmd_fix(args) -> int:
    rc = _scope_guard(args.paths, args)
    if rc != EXIT_OK:
        return rc
    which = [w.strip() for w in args.rules.split(",") if w.strip()]
    unknown = [w for w in which if w not in FIXERS]
    if unknown:
        print("unknown fixer(s): %s (available: %s)"
              % (", ".join(unknown), ", ".join(sorted(FIXERS))), file=sys.stderr)
        return EXIT_ERROR
    from .scanner import discover
    files = discover(args.paths)
    if not files:
        print("no workflow files found", file=sys.stderr)
        return EXIT_OK
    changed = 0
    for path in files:
        res = apply_fixers(path, which, apply=args.apply,
                           resolve=not args.no_resolve)
        if res.changed:
            changed += 1
            header = "[%s] %s" % ("APPLIED" if res.applied else "DRY-RUN", path)
            print(header)
            print(res.diff)
            print("")
    if not changed:
        print("nothing to fix in %d file(s)" % len(files))
    elif not args.apply:
        print("dry run — re-run with --apply to write %d file(s)" % changed)
    return EXIT_OK


def cmd_verify(args) -> int:
    rc = _scope_guard(args.paths, args)
    if rc != EXIT_OK:
        return rc
    try:
        with open(args.baseline, "r", encoding="utf-8") as fh:
            base = json.load(fh)
    except (OSError, ValueError) as exc:
        print("cannot read baseline: %s" % exc, file=sys.stderr)
        return EXIT_ERROR
    baseline_fps = {f["fingerprint"] for f in base.get("findings", [])}
    report = scan(args.paths)
    current = {f.fingerprint for f in report.findings}
    new = [f for f in report.findings if f.fingerprint not in baseline_fps]
    fixed = baseline_fps - current
    print("baseline : %s (%d findings)" % (args.baseline, len(baseline_fps)))
    print("current  : %d finding(s)" % len(report.findings))
    print("new      : %d" % len(new))
    print("resolved : %d" % len(fixed))
    if new:
        print("")
        for f in new:
            print("  + %s %s:%d %s" % (f.severity, f.file, f.line, f.rule_id))
        return EXIT_FINDINGS
    return EXIT_OK


def cmd_rules(args) -> int:
    if args.format == "json":
        print(json.dumps([r.as_dict() for r in all_rules()],
                         indent=2, ensure_ascii=False))
        return EXIT_OK
    if args.format == "markdown":
        print("# gha-audit rule catalogue\n")
        for r in all_rules():
            print("## `%s` — %s (%s)\n" % (r.id, r.title, r.severity))
            print("%s\n" % r.description)
            print("**Fix:** %s\n" % r.remediation)
        return EXIT_OK
    for r in all_rules():
        print("%-34s %-8s %s" % (r.id, r.severity, r.title))
    return EXIT_OK


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return EXIT_ERROR
    try:
        return {"scan": cmd_scan, "fix": cmd_fix,
                "verify": cmd_verify, "rules": cmd_rules}[args.command](args)
    except BrokenPipeError:                          # pragma: no cover
        try:
            sys.stdout.close()
        finally:
            return EXIT_OK
    except KeyboardInterrupt:                       # pragma: no cover
        return EXIT_ERROR


if __name__ == "__main__":                           # pragma: no cover
    sys.exit(main())
