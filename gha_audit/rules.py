# -*- coding: utf-8 -*-
"""
Rule registry for gha-audit.

Every rule carries a stable id, a severity, a human description and a
remediation hint.  Severities are: critical > high > medium > low > info.

The rules are modelled on the GitHub Actions ruleset of common SAST tools and
on the OWASP CI/CD Security top-10, but they are implemented from scratch with
zero third-party dependencies so the toolkit runs offline on any machine with
Python 3.8+.
"""
from dataclasses import dataclass
from typing import Optional, Tuple

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


@dataclass(frozen=True)
class Rule:
    id: str
    severity: str
    title: str
    title_ar: str
    description: str
    remediation: str
    cwe: Optional[str] = None

    def as_dict(self):
        return {
            "id": self.id,
            "severity": self.severity,
            "title": self.title,
            "title_ar": self.title_ar,
            "description": self.description,
            "remediation": self.remediation,
            "cwe": self.cwe,
        }


RULES = {}


def _add(rule: Rule) -> Rule:
    RULES[rule.id] = rule
    return rule


_add(Rule(
    id="gha-script-injection-run",
    severity="critical",
    title="Untrusted GitHub context interpolated into run:",
    title_ar="سياق GitHub غير الموثوق مُحقون داخل run:",
    description=(
        "A `${{ github.* }}` expression is evaluated BEFORE the shell sees the "
        "script. Any context influenced by an attacker (issue title, PR head "
        "branch, commit message, workflow input, ...) therefore becomes "
        "arbitrary code on a runner that may hold secrets."
    ),
    remediation=(
        "Bind the expression in a step-level `env:` (expression context) and "
        "reference it from the script as `$VAR`. `gha-audit fix` does this "
        "automatically."
    ),
    cwe="CWE-78",
))

_add(Rule(
    id="gha-secret-in-workflow-env",
    severity="high",
    title="Secret exposed in workflow-level env:",
    title_ar="سر مكشوف في env على مستوى Workflow:",
    description=(
        "A `secrets.*` value in the top-level `env:` block is handed to every "
        "job and every step of the workflow — including steps that run "
        "untrusted code (pull_request, third-party actions, scripts)."
    ),
    remediation=(
        "Scope the secret to the step (or at most the job) that actually uses "
        "it. `gha-audit fix --rules scope-secrets` does this automatically."
    ),
    cwe="CWE-200",
))

_add(Rule(
    id="gha-secret-in-job-env",
    severity="medium",
    title="Secret exposed at job level env:",
    title_ar="سر مكشوف في env على مستوى Job:",
    description=(
        "The secret is available to every step of the job, including any "
        "third-party action invoked by that job."
    ),
    remediation="Move the secret into the `env:` of the single step that reads it.",
    cwe="CWE-200",
))

_add(Rule(
    id="gha-unpinned-action",
    severity="medium",
    title="Action not pinned to a full commit SHA",
    title_ar="إجراء (action) غير مثبَّت على بصمة commit",
    description=(
        "A mutable tag (`v1`, `main`, ...) can be rewritten by the action "
        "maintainer — or by an attacker who compromises that account — and "
        "will execute in your CI with access to your secrets."
    ),
    remediation=(
        "Pin `uses: owner/repo@<40-hex SHA>` and keep the tag as a trailing "
        "comment. `gha-audit fix --rules pin --resolve` does this offline-safe "
        "(needs one `git ls-remote` per action)."
    ),
    cwe="CWE-829",
))

_add(Rule(
    id="gha-unpinned-action-floating",
    severity="high",
    title="Action pinned to a floating ref (main/master/latest)",
    title_ar="إجراء مثبَّت على مرجع عائم (main/master/latest)",
    description=(
        "Floating refs change on every push upstream — this is the weakest "
        "form of dependency pinning for a workflow that handles secrets."
    ),
    remediation="Pin to a full commit SHA, or at minimum to a release tag.",
    cwe="CWE-829",
))

_add(Rule(
    id="gha-pr-target-checkout-head",
    severity="critical",
    title="pull_request_target checks out untrusted PR code",
    title_ar="pull_request_target يسحب كود PR غير الموثوق",
    description=(
        "`pull_request_target` runs in the context of the BASE repository "
        "(with its secrets). Checking out the PR head and executing anything "
        "from it hands those secrets to the PR author — the classic "
        "'pwn request' pattern."
    ),
    remediation=(
        "Never check out PR head code in a `pull_request_target` workflow. "
        "Split it: do the untrusted work in a `pull_request` workflow, then "
        "let a trusted `pull_request_target` workflow consume its artifacts."
    ),
    cwe="CWE-94",
))

_add(Rule(
    id="gha-pr-target-checkout-credentials",
    severity="high",
    title="pull_request_target checkout keeps credentials",
    title_ar="سحب الكود في pull_request_target يحتفظ ببيانات الدخول",
    description=(
        "On `pull_request_target` the checkout token can write to the base "
        "repository and is persisted into `.git/credentials` of the workspace."
    ),
    remediation="Set `persist-credentials: false` on the checkout step.",
    cwe="CWE-522",
))

_add(Rule(
    id="gha-self-hosted-on-untrusted-trigger",
    severity="high",
    title="Self-hosted runner executes an untrusted trigger",
    title_ar="عامل self-hosted ينفّذ مشغّلاً غير موثوق",
    description=(
        "Triggers such as issue_comment / pull_request_target / workflow_run "
        "can be influenced by anyone. On a self-hosted runner that reaches "
        "your internal network and workspace."
    ),
    remediation=(
        "Run untrusted work on GitHub-hosted runners, or gate the job behind "
        "an explicit approval / `if:` check on the author."
    ),
    cwe="CWE-250",
))

_add(Rule(
    id="gha-hardcoded-credential",
    severity="critical",
    title="Hard-coded credential in workflow",
    title_ar="بيانات دخول مكتوبة داخل الملف",
    description=(
        "A literal token/password/API key is committed in the workflow file. "
        "Anyone with read access to the repository — and every fork — can use "
        "it, and it survives in git history."
    ),
    remediation=(
        "Move the value to repository Secrets (`${{ secrets.NAME }}`), then "
        "rotate the leaked credential — deleting the line does NOT un-leak it."
    ),
    cwe="CWE-798",
))

_add(Rule(
    id="gha-pull-request-fork-with-secrets",
    severity="medium",
    title="Untrusted trigger combined with privileged checkout",
    title_ar="مشغّل غير موثوق مع سحب كود مميز",
    description=(
        "`workflow_run` / `pull_request_target` style workflows run with "
        "repository privileges after an untrusted event; combined with a "
        "checkout of the produced code this re-creates the pwn-request risk."
    ),
    remediation=(
        "Treat artifacts/refs produced by untrusted workflows as data only; "
        "never execute them in the privileged workflow."
    ),
    cwe="CWE-94",
))

_add(Rule(
    id="gha-missing-permissions",
    severity="low",
    title="No explicit token permissions block",
    title_ar="لا يوجد حدّ صلاحيات صريح للرمز",
    description=(
        "Without `permissions:` the workflow inherits the repository default, "
        "which on older repositories is a writable default token — any "
        "compromised step can then write to the repo, create releases, ..."
    ),
    remediation=(
        "Declare least privilege explicitly, e.g. `permissions: contents: read` "
        "at workflow level and grant more only to the jobs that need it."
    ),
    cwe="CWE-250",
))

_add(Rule(
    id="gha-credentials-persisted",
    severity="low",
    title="Checkout persists the token in the workspace",
    title_ar="سحب الكود يحفظ الرمز داخل مساحة العمل",
    description=(
        "actions/checkout stores the token under `.git/credentials` unless "
        "`persist-credentials: false` is set; a later step that archives the "
        "workspace or runs untrusted code can leak it."
    ),
    remediation="Add `persist-credentials: false` to the checkout step.",
    cwe="CWE-522",
))


def get(rule_id: str) -> Rule:
    return RULES[rule_id]


def severity_at_least(sev: str, threshold: str) -> bool:
    """True when `sev` is at least as severe as `threshold`."""
    if threshold == "none":
        return False
    if threshold == "all":
        return True
    return SEVERITY_ORDER.index(sev) <= SEVERITY_ORDER.index(threshold)


def all_rules() -> Tuple[Rule, ...]:
    return tuple(RULES[k] for k in RULES)
