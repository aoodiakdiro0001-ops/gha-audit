# -*- coding: utf-8 -*-
"""
gha-audit scanner — line/structure engine for GitHub Actions workflows.

Design notes
------------
* Zero third-party dependencies: workflows are parsed with an indentation
  aware walker, so the toolkit runs offline on a bare Python 3.8+.
* Every finding carries a stable fingerprint so runs can be diffed
  (`gha-audit verify`) and baselines can be stored in CI.
* The engine only ever reads local files — see scope.py for the guard that
  decides whether you are allowed to scan a target at all.
"""
import hashlib
import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from .rules import RULES, Rule

# --------------------------------------------------------------------------- #
# expression handling
# --------------------------------------------------------------------------- #

EXPR = re.compile(r"\$\{\{(.*?)\}\}", re.S)

# Contexts that are provably safe to inline into a shell script.
SAFE_GITHUB = {
    "github.repository",
    "github.repository_owner",
    "github.sha",
    "github.run_id",
    "github.run_number",
    "github.run_attempt",
    "github.event_name",
    "github.workflow",
    "github.workflow_ref",
    "github.workflow_sha",
    "github.job",
    "github.actor",
    "github.triggering_actor",
    "github.server_url",
    "github.api_url",
    "github.graphql_url",
    "github.token",
    "github.retention_days",
}

# Substrings whose value is attacker-authored content (issue titles, commit
# messages, PR branch names, ...).  These are the classic injection sources.
CRITICAL_PATHS = (
    "github.head_ref",
    "github.event.issue",
    "github.event.comment",
    "github.event.review_comment",
    "github.event.review",
    "github.event.pull_request.title",
    "github.event.pull_request.body",
    "github.event.pull_request.head",
    "github.event.pull_request.base",
    "github.event.head_commit",
    "github.event.commits",
    "github.event.workflow_run.head",
    "github.event.workflow_run.display_title",
    "github.event.workflow_run.name",
    "github.event.discussion",
    "github.event.pages",
    "github.event.release",
    "github.event.deployment",
    "github.event.client_payload",
    "github.event.check_run",
    "github.event.check_suite",
    "github.event.registry_package",
    "github.event.github_token",
)

# Reachable, but only by a trusted actor / repo configuration — still unsafe
# inside `run:` (branch names and dispatch inputs are shell-visible strings).
HIGH_PATHS = (
    "github.event.inputs",
    "github.inputs",
    "github.ref_name",
    "github.ref",
    "github.event.workflow_dispatch",
    "github.event.workflow_call",
    "github.event.workflow",
    "github.event.repository",
    "github.ref_protected",
)

GITHUB_TOKEN_RE = re.compile(r"github(?:\.[A-Za-z_][A-Za-z0-9_]*)+")


def classify_expression(expr: str) -> Optional[str]:
    """Return 'critical' | 'high' | 'medium' | None for one `run:` expression."""
    expr = expr.strip()
    if not expr or "github." not in expr:
        return None
    if "secrets." in expr or "vars." in expr or "matrix." in expr or "env." in expr:
        # value contexts are not shell-attacker-controlled here
        if "github." not in expr.split("secrets.")[-1]:
            return None
    worst = None

    def bump(level: str):
        nonlocal worst
        order = {"medium": 1, "high": 2, "critical": 3}
        if worst is None or order[level] > order[worst]:
            worst = level

    for token in GITHUB_TOKEN_RE.findall(expr):
        if token in SAFE_GITHUB:
            continue
        # a whitelisted longer path (github.repository...) - exact match only
        if any(token == s for s in SAFE_GITHUB):
            continue
        hit = False
        for p in CRITICAL_PATHS:
            if token.startswith(p) or p.startswith(token) and token.startswith("github.event."):
                bump("critical")
                hit = True
                break
        if hit:
            continue
        for p in HIGH_PATHS:
            if token.startswith(p):
                bump("high")
                hit = True
                break
        if hit:
            continue
        if token.startswith("github.event.") or token.startswith("github."):
            bump("medium")
    return worst


# --------------------------------------------------------------------------- #
# findings
# --------------------------------------------------------------------------- #


@dataclass
class Finding:
    rule_id: str
    severity: str
    file: str
    line: int
    message: str
    snippet: str
    remediation: str
    fingerprint: str = ""

    def __post_init__(self):
        if not self.fingerprint:
            raw = "%s|%s|%s|%s" % (self.rule_id, self.file, self.line, self.snippet.strip()[:80])
            self.fingerprint = hashlib.sha1(raw.encode("utf-8", "replace")).hexdigest()[:16]

    def as_dict(self) -> Dict:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "file": self.file,
            "line": self.line,
            "message": self.message,
            "snippet": self.snippet.strip(),
            "remediation": self.remediation,
            "fingerprint": self.fingerprint,
        }


@dataclass
class Report:
    target: str
    files_scanned: int = 0
    findings: List[Finding] = field(default_factory=list)

    def counts(self) -> Dict[str, int]:
        out = {k: 0 for k in ("critical", "high", "medium", "low", "info")}
        for f in self.findings:
            out[f.severity] = out.get(f.severity, 0) + 1
        return out

    def worst(self) -> Optional[str]:
        order = ["critical", "high", "medium", "low", "info"]
        for s in order:
            if self.counts().get(s):
                return s
        return None


# --------------------------------------------------------------------------- #
# line helpers
# --------------------------------------------------------------------------- #


def indent_of(line: str) -> int:
    return len(line) - len(line.lstrip())


def is_key_line(line: str) -> Optional[Tuple[str, str]]:
    m = re.match(r"^(\s*)([A-Za-z_][\w.-]*):\s*(.*)$", line)
    if m:
        return m.group(2), m.group(3)
    return None


def find_run_blocks(lines: Sequence[str]) -> List[Tuple[int, int, int, int]]:
    """Return (run_line_index, block_start, block_end, key_indent) per `run:`.

    Handles both shapes found in real workflows:

        - name: x
          run: |          <- `run:` is its own key
        ...
        - run: |          <- `run:` is the first key of the step item
    """
    out = []
    i = 0
    while i < len(lines):
        m = re.match(r"^(\s*)(?:-\s+)?run:\s*(\|)?\s*$", lines[i])
        if m:
            lead = len(m.group(1))
            dashed = bool(re.match(r"^\s*-\s", lines[i]))
            # for `- run:` the mapping key sits two columns right of the dash,
            # and a block scalar must be indented deeper than that key
            base = lead + 2 if dashed else lead
            j = i + 1
            while j < len(lines):
                l = lines[j]
                if l.strip() == "":
                    j += 1
                    continue
                if indent_of(l) <= base:
                    break
                j += 1
            out.append((i, i + 1, j, base))
            i = j
            continue
        inline = re.match(r"^(\s*)(?:-\s+)?run:\s*(.+)$", lines[i])
        if inline and not inline.group(2).strip().startswith("{"):
            # single line run: body lives on the same line
            out.append((i, i, i + 1, len(inline.group(1))))
        i += 1
    return out


def parse_triggers(lines: Sequence[str]) -> set:
    """Collect event names from the top-level `on:` key."""
    triggers = set()
    top = None  # indent of the `on:` key
    for idx, line in enumerate(lines):
        if line.lstrip().startswith("#"):
            continue
        m = is_key_line(line)
        if m and indent_of(line) == 0:
            key, val = m
            top = None
            if key in ("on", "on:") or key == "on":
                top = 0
                if val.strip():
                    for part in re.split(r"[,\[\]\s]+", val.strip().strip("[]")):
                        part = part.strip("'\"")
                        if part:
                            triggers.add(part)
                continue
        if top is not None:
            ind = indent_of(line)
            if line.strip() == "":
                continue
            if ind <= top:
                top = None
                continue
            km = is_key_line(line)
            if km and ind == top + 2:
                triggers.add(km[0])
    return triggers


def _block_end(lines: Sequence[str], start: int, base_indent: int, stop_on_seq=False) -> int:
    """End index of the block that starts at `start` with `base_indent`."""
    j = start + 1
    while j < len(lines):
        l = lines[j]
        if l.strip() == "":
            j += 1
            continue
        ind = indent_of(l)
        if stop_on_seq and ind == base_indent and l.lstrip().startswith("- "):
            break
        if ind <= base_indent:
            break
        j += 1
    return j


def find_env_blocks(lines: Sequence[str]) -> List[Tuple[int, int, str]]:
    """(env_line_index, entries_end, scope) for every `env:` block.

    scope is 'workflow' (indent 0) or 'job' (indent > 0 but above step level).
    Step level env is reported as 'job' here too; the caller narrows it with
    the step scan.
    """
    out = []
    for i, line in enumerate(lines):
        if line.lstrip().startswith("#"):
            continue
        m = re.match(r"^(\s*)env:\s*(.*)$", line)
        if not m:
            continue
        ind = len(m.group(1))
        rest = m.group(2).strip()
        if rest.startswith("{"):
            end = i  # inline mapping on the same line
        else:
            end = _block_end(lines, i, ind)
        scope = "workflow" if ind == 0 else ("job" if ind <= 4 else "step")
        out.append((i, end, scope))
    return out


def env_entries(lines: Sequence[str], idx: int, end: int) -> List[Tuple[int, str, str]]:
    """(line_no, name, value) for entries of an env block at `idx`."""
    entries = []
    head = lines[idx]
    inline = re.match(r"^\s*env:\s*\{(.+)\}\s*$", head)
    if inline:
        for part in re.split(r",(?![^\"]*\"\s*:)", inline.group(1)):
            km = re.match(r"\s*([A-Za-z_][\w]*)\s*:\s*(.+)", part)
            if km:
                entries.append((idx, km.group(1), km.group(2).strip().strip("'\"")))
        return entries
    base = indent_of(head)
    for j in range(idx + 1, end + 1 if end < len(lines) else len(lines)):
        if j >= len(lines):
            break
        l = lines[j]
        if l.strip() == "" or l.lstrip().startswith("#"):
            continue
        if indent_of(l) <= base:
            break
        km = re.match(r"^\s*([A-Za-z_][\w-]*)\s*:\s*(.*)$", l)
        if km and indent_of(l) == base + 2:
            val = km.group(2)
            if val.strip() == "|" or val.strip() == ">":
                blk_end = _block_end(lines, j, indent_of(l))
                val = " ".join(x.strip() for x in lines[j + 1:blk_end])
            entries.append((j, km.group(1), val.strip().strip("'\"")))
    return entries


def find_steps(lines: Sequence[str]) -> List[Tuple[int, int, int]]:
    """(dash_line_index, dash_indent, block_end) for every list item in `steps:`."""
    out = []
    in_steps = False
    steps_indent = 0
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.lstrip().startswith("#"):
            i += 1
            continue
        km = is_key_line(line)
        if km and km[0] == "steps" and not km[1].strip():
            in_steps = True
            steps_indent = indent_of(line) + 2
            i += 1
            continue
        if in_steps:
            ind = indent_of(line)
            if line.strip() and ind < steps_indent - 2:
                in_steps = False
                i += 1
                continue
            if line.lstrip().startswith("- ") and ind == steps_indent:
                j = i + 1
                while j < len(lines):
                    l2 = lines[j]
                    if l2.strip() == "":
                        j += 1
                        continue
                    ind2 = indent_of(l2)
                    if ind2 < ind or (ind2 == ind and l2.lstrip().startswith("- ")):
                        break
                    j += 1
                out.append((i, ind, j))
                i = j
                continue
        i += 1
    return out


# --------------------------------------------------------------------------- #
# credentials / tokens
# --------------------------------------------------------------------------- #

TOKEN_PATTERNS = [
    re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b"),
    re.compile(r"\bBearer\s+[A-Za-z0-9._-]{20,}\b"),
]
CRED_KEY = re.compile(
    r"(?i)\b(password|passwd|pwd|token|secret|api_?key|access_?key|auth)\b\s*[:=]\s*['\"]?([A-Za-z0-9+/_.\-]{16,})"
)


def looks_like_credential(line: str) -> Optional[str]:
    """Return the matched secret material when a literal credential is found."""
    if "${{" in line or "$" in line.split("#")[0]:
        return None  # expression / variable reference -> not a literal
    for pat in TOKEN_PATTERNS:
        m = pat.search(line)
        if m:
            return m.group(0)
    m = CRED_KEY.search(line)
    if m:
        val = m.group(2)
        if val.lower() in {"true", "false", "null", "none", "required", "optional"}:
            return None
        if val.upper() in {"READONLY", "READ_WRITE", "WRITE", "READ"}:
            return None
        return m.group(0)
    return None


# --------------------------------------------------------------------------- #
# the scanner
# --------------------------------------------------------------------------- #

WORKFLOW_NAME_RE = re.compile(r"^(workflow|ci|cd|build|release|deploy|test|scan|check)", re.I)


def discover(paths: Sequence[str], exclude: Sequence[str] = ()) -> List[str]:
    """Resolve files/dirs to a list of workflow YAML files."""
    found: List[str] = []
    seen = set()

    def keep(p: str) -> bool:
        low = p.lower()
        return low.endswith((".yml", ".yaml")) and not any(
            re.search(x, low) for x in exclude
        )

    for raw in paths:
        if os.path.isfile(raw):
            if keep(raw) and raw not in seen:
                seen.add(raw)
                found.append(raw)
            continue
        if not os.path.isdir(raw):
            continue
        for root, dirs, files in os.walk(raw):
            dirs[:] = [d for d in dirs if d not in {".git", "node_modules", ".venv", "venv"}]
            for f in sorted(files):
                p = os.path.join(root, f)
                if keep(p) and p not in seen:
                    seen.add(p)
                    found.append(p)
    return found


def scan_file(path: str, report: Report) -> None:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError:
        return
    lines = text.split("\n")
    report.files_scanned += 1

    def add(rule_id: str, line_no: int, message: str, snippet: str, severity: Optional[str] = None):
        rule: Rule = RULES[rule_id]
        report.findings.append(Finding(
            rule_id=rule_id,
            severity=severity or rule.severity,
            file=path,
            line=line_no,
            message=message or rule.title,
            snippet=snippet,
            remediation=rule.remediation,
        ))

    triggers = parse_triggers(lines)
    uses_secrets = any("secrets." in l for l in lines)

    # --- 1. shell injection inside run: -----------------------------------
    for run_idx, start, end, _base in find_run_blocks(lines):
        for j in range(start, end):
            if j >= len(lines):
                break
            body = lines[j]
            if body.lstrip().startswith("#"):
                continue
            for raw_expr in EXPR.findall(body):
                level = classify_expression(raw_expr)
                if not level:
                    continue
                expr = " ".join(raw_expr.split())
                if level == "critical":
                    msg = ("Expression `%s` reaches the shell and carries attacker-"
                           "influenced data" % expr)
                elif level == "high":
                    msg = "Expression `%s` is interpolated directly into the shell script" % expr
                else:
                    msg = ("Non-whitelisted expression `%s` interpolated into the shell "
                           "script" % expr)
                add("gha-script-injection-run", j + 1, msg, body, severity=level)

    # --- 2/3. secrets in env blocks ---------------------------------------
    for idx, end, scope in find_env_blocks(lines):
        for line_no, name, value in env_entries(lines, idx, end):
            if "secrets." not in value:
                continue
            if scope == "workflow":
                add("gha-secret-in-workflow-env", line_no + 1,
                    "Secret `%s` is available to every job and step of this workflow" % name,
                    lines[line_no])
            elif scope == "job":
                add("gha-secret-in-job-env", line_no + 1,
                    "Secret `%s` is available to every step of this job" % name,
                    lines[line_no])
            # step-level env is the recommended place -> no finding

    # --- 4/5. action pinning ----------------------------------------------
    for i, line in enumerate(lines):
        if "uses:" not in line or line.lstrip().startswith("#"):
            continue
        m = re.search(r"uses:\s*['\"]?([^\s'\"]+)", line)
        if not m:
            continue
        target = m.group(1)
        if target.startswith("./") or target.startswith("docker://") or "://" in target:
            continue
        am = re.match(r"^([\w.-]+)/([\w.-]+)@(.+)$", target)
        if not am:
            continue
        ref = am.group(3)
        if re.fullmatch(r"[0-9a-f]{40}", ref):
            continue
        if ref.lower() in {"main", "master", "latest", "head", "dev", "trunk"}:
            add("gha-unpinned-action-floating", i + 1,
                "Action `%s` tracks the moving ref `%s`" % (am.group(0), ref), line)
        else:
            add("gha-unpinned-action", i + 1,
                "Action `%s` is not pinned to a commit SHA" % am.group(0), line)

    # --- 6/7. pull_request_target & privileged checkout --------------------
    privileged = {"pull_request_target", "workflow_run"}
    if privileged & triggers:
        for step_idx, dash_indent, step_end in find_steps(lines):
            step_text = "\n".join(lines[step_idx:step_end])
            if "actions/checkout" not in step_text:
                continue
            head_refs = ("github.event.pull_request.head", "github.event.workflow_run.head_",
                         "github.head_ref")
            checkout_head = any(h in step_text for h in head_refs)
            persists = re.search(r"persist-credentials:\s*false", step_text) is not None
            if "pull_request_target" in triggers and checkout_head:
                add("gha-pr-target-checkout-head", step_idx + 1,
                    "`pull_request_target` checks out the untrusted PR head with the base "
                    "repository's secrets", lines[step_idx])
            elif "pull_request_target" in triggers and not persists:
                add("gha-pr-target-checkout-credentials", step_idx + 1,
                    "`pull_request_target` checkout keeps the write token in the workspace",
                    lines[step_idx])
            elif "workflow_run" in triggers and checkout_head and not persists:
                add("gha-pull-request-fork-with-secrets", step_idx + 1,
                    "Privileged `workflow_run` workflow executes code produced by an "
                    "untrusted workflow", lines[step_idx])
            if not persists and uses_secrets:
                add("gha-credentials-persisted", step_idx + 1,
                    "Checkout persists the token in `.git/credentials` while this workflow "
                    "handles secrets", lines[step_idx])

    # --- 8. self-hosted runners -------------------------------------------
    untrusted_triggers = privileged | {
        "pull_request", "issue_comment", "issues", "discussion", "discussion_comment",
        "pull_request_review", "pull_request_review_comment", "fork", "watch",
    }
    if untrusted_triggers & triggers:
        for i, line in enumerate(lines):
            if "runs-on" not in line or line.lstrip().startswith("#"):
                continue
            if "self-hosted" in line:
                add("gha-self-hosted-on-untrusted-trigger", i + 1,
                    "Self-hosted runner serves the untrusted trigger(s): %s" %
                    ", ".join(sorted(untrusted_triggers & triggers)), line)

    # --- 9. hard-coded credentials ----------------------------------------
    for i, line in enumerate(lines):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if "secrets." in line:
            continue
        hit = looks_like_credential(line)
        if hit:
            add("gha-hardcoded-credential", i + 1,
                "Literal credential material committed in the workflow", line)

    # --- 10. missing permissions ------------------------------------------
    has_permissions = any(
        re.match(r"^\s*permissions:\s*(\{|$|\[)", l) for l in lines
    )
    if not has_permissions and any(re.match(r"^\s*jobs:\s*$", l) for l in lines):
        jobs_line = next((i for i, l in enumerate(lines) if re.match(r"^\s*jobs:\s*$", l)), 0)
        add("gha-missing-permissions", jobs_line + 1,
            "Workflow relies on the default token permissions", lines[jobs_line])


def scan(paths: Sequence[str], exclude: Sequence[str] = ()) -> Report:
    files = discover(paths, exclude)
    report = Report(target=",".join(paths))
    for f in files:
        scan_file(f, report)
    report.findings.sort(key=lambda f: (f.file, f.line, f.rule_id))
    return report
