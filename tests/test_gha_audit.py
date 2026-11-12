# -*- coding: utf-8 -*-
"""Unit tests for gha-audit (stdlib unittest, no pytest required)."""
import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from gha_audit.cli import main
from gha_audit.fixers import fix_envify, fix_permissions, fix_pin, fix_scope_secrets
from gha_audit.report import render_json, render_markdown, render_sarif
from gha_audit.rules import RULES, severity_at_least
from gha_audit.scanner import classify_expression, scan
from gha_audit.scope import check_scope

VULNERABLE = """\
name: CI
on:
  issue_comment:
    types: [created]
env:
  DEPLOY_TOKEN: ${{ secrets.DEPLOY_TOKEN }}
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: greet
        run: echo "hello ${{ github.event.comment.body }}"
      - name: use input
        run: echo "${{ github.event.inputs.tag }}"
"""

FIXED = """\
name: CI
on:
  push:
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
      - name: greet
        env:
          COMMENT_BODY: "${{ github.event.comment.body }}"
        run: echo "hello $COMMENT_BODY"
"""


class TempDirCase(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="gha-audit-test-")
        self.addCleanup(shutil.rmtree, self.dir, True)

    def write(self, rel, text):
        path = os.path.join(self.dir, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        return path


class TestClassification(unittest.TestCase):
    def test_critical_contexts(self):
        for expr in ("github.event.comment.body",
                     "github.event.issue.title",
                     "github.head_ref",
                     "github.event.pull_request.head.ref",
                     "github.event.head_commit.message"):
            self.assertEqual(classify_expression(expr), "critical", expr)

    def test_high_contexts(self):
        for expr in ("github.event.inputs.tag", "github.ref_name", "github.ref"):
            self.assertEqual(classify_expression(expr), "high", expr)

    def test_safe_whitelist(self):
        for expr in ("github.repository", "github.sha", "github.run_id",
                     "github.actor", "github.token"):
            self.assertIsNone(classify_expression(expr), expr)

    def test_non_github_ignored(self):
        self.assertIsNone(classify_expression("secrets.DEPLOY_TOKEN"))
        self.assertIsNone(classify_expression("matrix.node_version"))


class TestScanner(TempDirCase):
    def test_vulnerable_workflow_flags_injection(self):
        path = self.write(".github/workflows/ci.yml", VULNERABLE)
        report = scan([self.dir])
        self.assertEqual(report.files_scanned, 1)
        rules = {f.rule_id for f in report.findings}
        self.assertIn("gha-script-injection-run", rules)
        self.assertIn("gha-secret-in-workflow-env", rules)
        self.assertIn("gha-missing-permissions", rules)
        self.assertGreater(report.counts()["critical"], 0)
        # every finding carries a stable fingerprint
        for f in report.findings:
            self.assertEqual(len(f.fingerprint), 16)
        self.assertEqual(path, report.findings[0].file)

    def test_clean_workflow_has_no_critical(self):
        self.write(".github/workflows/ci.yml", FIXED)
        report = scan([self.dir])
        self.assertEqual(report.counts()["critical"], 0,
                         [f.rule_id for f in report.findings])

    def test_floating_ref_is_high(self):
        self.write("w.yml", "on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n"
                            "    steps:\n      - uses: actions/checkout@main\n")
        report = scan([self.dir])
        ids = [f.rule_id for f in report.findings]
        self.assertIn("gha-unpinned-action-floating", ids)
        floating = [f for f in report.findings
                    if f.rule_id == "gha-unpinned-action-floating"][0]
        self.assertEqual(floating.severity, "high")

    def test_hardcoded_credential(self):
        self.write("w.yml",
                   "on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n"
                   "    steps:\n      - run: curl -H 'Authorization: "
                   "Bearer ghp_abcdefghijklmnopqrstuvwx123456' https://x\n")
        report = scan([self.dir])
        self.assertIn("gha-hardcoded-credential",
                      {f.rule_id for f in report.findings})


class TestFixers(TempDirCase):
    def test_envify_removes_expression_from_run(self):
        lines = VULNERABLE.split("\n")
        fixed, changes = fix_envify(lines)
        text = "\n".join(fixed)
        self.assertGreater(changes, 0)
        body_start = text.index("run: echo")
        run_section = text[body_start:text.index("\n", body_start)]
        self.assertNotIn("${{", run_section)
        self.assertIn("$GH_EVENT_COMMENT_BODY", run_section)
        self.assertIn("GH_EVENT_COMMENT_BODY: \"${{ github.event.comment.body }}\"",
                      text)
        # re-running is a no-op (idempotent)
        again, changes2 = fix_envify(fixed)
        self.assertEqual(changes2, 0)
        self.assertEqual("\n".join(again), text)

    def test_envify_passes_clean_file(self):
        lines = FIXED.split("\n")
        fixed, changes = fix_envify(lines)
        self.assertEqual(changes, 0)

    def test_scope_secrets_moves_env(self):
        lines = VULNERABLE.split("\n")
        fixed, changes = fix_scope_secrets(lines)
        text = "\n".join(fixed)
        self.assertGreater(changes, 0)
        # no more workflow-level env block holding the secret
        top = text.split("jobs:")[0]
        self.assertNotIn("DEPLOY_TOKEN", top)

    def test_permissions_inserted_once(self):
        lines = VULNERABLE.split("\n")
        fixed, changes = fix_permissions(lines)
        self.assertEqual(changes, 1)
        fixed2, changes2 = fix_permissions(fixed)
        self.assertEqual(changes2, 0)
        self.assertEqual(fixed2, fixed)

    def test_pin_offline_noop_without_resolve(self):
        lines = ["      - uses: actions/checkout@v4"]
        fixed, changes = fix_pin(lines, resolve=False)
        self.assertEqual(changes, 0)

    def test_pin_regex_matches_dashed_uses(self):
        # `- uses:` (step item) and `uses:` (mapping key) must both match
        from gha_audit.fixers import USES_RE
        m1 = USES_RE.match("      - uses: actions/checkout@v4")
        m2 = USES_RE.match("      uses: actions/checkout@v4")
        m3 = USES_RE.match("      - uses: 'docker/build-push-action@v5'")
        self.assertTrue(m1 and m1.group(3) == "actions/checkout@v4", m1)
        self.assertTrue(m2 and m2.group(3) == "actions/checkout@v4", m2)
        self.assertTrue(m3 and m3.group(3) == "docker/build-push-action@v5", m3)
        self.assertEqual(m1.group(2), "- ")
        self.assertIsNone(m2.group(2))


class TestEndToEnd(TempDirCase):
    def test_scan_then_fix_then_clean(self):
        self.write(".github/workflows/ci.yml", VULNERABLE)
        before = scan([self.dir])
        self.assertGreater(before.counts()["critical"], 0)

        path = os.path.join(self.dir, ".github/workflows/ci.yml")
        from gha_audit.fixers import apply_fixers
        res = apply_fixers(path, ["envify", "scope-secrets", "permissions"],
                           apply=True)
        self.assertTrue(res.changed)
        self.assertTrue(res.applied)

        after = scan([self.dir])
        self.assertEqual(after.counts()["critical"], 0,
                         [f.as_dict() for f in after.findings])
        self.assertEqual(after.counts()["high"], 0,
                         [f.as_dict() for f in after.findings])

    def test_cli_json_and_exit_codes(self):
        self.write(".github/workflows/ci.yml", FIXED)
        rc = main(["scan", self.dir, "--format", "json",
                   "--i-own-this", "--fail-on", "high"])
        self.assertEqual(rc, 0)

    def test_cli_refuses_foreign_target(self):
        # a path outside $HOME with a foreign git origin -> exit 3
        decision = check_scope(["/definitely/not/owned"], i_own_this=False)
        # non-existent path is refused too
        self.assertFalse(decision.allowed)

    def test_cli_fails_on_findings(self):
        self.write(".github/workflows/ci.yml", VULNERABLE)
        rc = main(["scan", self.dir, "--i-own-this", "--no-color",
                   "--fail-on", "critical"])
        self.assertEqual(rc, 2)

    def test_rules_command(self):
        self.assertEqual(main(["rules"]), 0)
        self.assertEqual(len(RULES), 12)


class TestReporters(TempDirCase):
    def _report(self):
        self.write(".github/workflows/ci.yml", VULNERABLE)
        return scan([self.dir])

    def test_json_roundtrip(self):
        doc = json.loads(render_json(self._report()))
        self.assertEqual(doc["tool"], "gha-audit")
        self.assertIn("findings", doc)
        self.assertTrue(doc["findings"])

    def test_sarif_shape(self):
        doc = json.loads(render_sarif(self._report()))
        self.assertEqual(doc["version"], "2.1.0")
        run = doc["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "gha-audit")
        self.assertTrue(run["results"])
        self.assertTrue(run["tool"]["driver"]["rules"])

    def test_markdown_contains_table(self):
        md = render_markdown(self._report())
        self.assertIn("| Severity |", md)
        self.assertIn("gha-audit", md)


class TestSeverity(unittest.TestCase):
    def test_ordering(self):
        self.assertTrue(severity_at_least("critical", "high"))
        self.assertTrue(severity_at_least("high", "high"))
        self.assertFalse(severity_at_least("medium", "high"))
        self.assertFalse(severity_at_least("critical", "none"))
        self.assertTrue(severity_at_least("info", "all"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
