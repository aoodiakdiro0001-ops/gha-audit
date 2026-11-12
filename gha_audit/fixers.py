# -*- coding: utf-8 -*-
"""
gha-audit fixers — safe, idempotent rewrites for GitHub Actions workflows.

Four fixers, all offline and deterministic:

  envify        move `${{ github.* }}` out of `run:` bodies into a step-level
                `env:` (the classic shell-injection fix)
  scope-secrets shrink a workflow/job level secret env to the single step
                that actually reads it
  pin           rewrite `uses: owner/repo@vN` to `owner/repo@<sha> # vN`
  permissions   insert an explicit least-privilege `permissions:` block

Every fixer is a pure function (text -> text) so `gha-audit fix --dry-run`
can print a diff without touching the disk, and `fix --apply` writes only
when the text actually changed.
"""
import os
import re
import subprocess
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from .scanner import (classify_expression, env_entries, find_env_blocks,
                      find_run_blocks, find_steps, indent_of)

EXPR = re.compile(r"\$\{\{(.*?)\}\}", re.S)
RUN_KEY = re.compile(r"^(\s*)run:\s*(\|)?\s*$")
USES_RE = re.compile(r"^(\s*)(-\s+)?uses:\s*['\"]?([^'\s\"]+)['\"]?\s*(#.*)?$")
USES_ACTION = re.compile(r"^([\w.-]+)/([\w.-]+)@(.+)$")


@dataclass
class FixResult:
    path: str
    changed: bool = False
    applied: bool = False
    description: str = ""
    diff: str = ""


def _env_name_for(expr: str, taken: set) -> str:
    """Collision-free GH_* / GH_EVENT_* name for one expression."""
    expr = " ".join(expr.split())
    base = None
    if expr.startswith("github.event."):
        parts = expr.split(".")
        base = "GH_EVENT_" + "_".join(p.upper() for p in parts[2:])
    else:
        base = "GH_" + expr.split(".", 1)[1].upper().replace(".", "_")
    base = re.sub(r"[^A-Z0-9_]", "_", base)
    name, n = base, 1
    while name in taken:
        n += 1
        name = "%s_%d" % (base, n)
    taken.add(name)
    return name


# --------------------------------------------------------------------------- #
# fixer: envify  (port of the field-tested gha_envify.py)
# --------------------------------------------------------------------------- #

def fix_envify(lines: Sequence[str]) -> Tuple[List[str], int]:
    """Rewrite run: blocks so no `${{ github.* }}` reaches the shell."""
    out = list(lines)
    edits = []          # (line_idx, replacement)
    inserts = []        # (insert_before_idx, env_lines)

    for run_idx, start, end, base in find_run_blocks(out):
        if start > end or start >= len(out):
            continue
        # Only expressions that actually reach the shell AND classify as
        # unsafe.  Safe contexts (github.sha, ...) and non-github values
        # (secrets.*, matrix.*, vars.*) stay inline on purpose.
        exprs: List[str] = []
        for l in out[start:min(end, len(out))]:
            for raw in EXPR.findall(l):
                e = " ".join(raw.split())
                if e in exprs:
                    continue
                if classify_expression(e) is None:
                    continue
                exprs.append(e)
        if not exprs:
            continue

        # locate the owning step item (`- name:` / `- uses:` / `- run:`)
        dash_idx = run_idx
        while dash_idx > 0 and not out[dash_idx].lstrip().startswith("- "):
            dash_idx -= 1
        step_ind = indent_of(out[dash_idx])
        key_ind = step_ind + 2
        step_end = dash_idx + 1
        while step_end < len(out):
            l = out[step_end]
            if l.strip() and indent_of(l) <= step_ind:
                break
            step_end += 1

        taken = set()
        for k in range(dash_idx + 1, step_end):
            km = re.match(r"^\s*([A-Za-z_][\w]*)\s*:", out[k])
            if km and indent_of(out[k]) == key_ind + 2:
                taken.add(km.group(1))
        mapping = [(e, _env_name_for(e, taken)) for e in exprs]

        for k in range(start, min(end, len(out))):
            new = out[k]
            for e, n in mapping:
                new = re.sub(r"\$\{\{\s*%s\s*\}\}" % re.escape(e), "$" + n, new)
            if new != out[k]:
                edits.append((k, new))

        entry_lines = [" " * (key_ind + 2) + '%s: "${{ %s }}"' % (n, e)
                       for e, n in mapping]

        # does this step already declare `env:`?  (block or inline mapping)
        existing = None
        inline_env = None
        for k in range(dash_idx + 1, step_end):
            if indent_of(out[k]) != key_ind:
                continue
            if re.match(r"^\s*env:\s*$", out[k]):
                existing = k
                break
            im = re.match(r"^\s*env:\s*\{(.*)\}\s*$", out[k])
            if im:
                inline_env = k
                break

        if inline_env is not None:
            m = re.match(r"^(\s*)env:\s*\{(.*)\}\s*$", out[inline_env])
            inner = m.group(2).strip().rstrip(",")
            add = ", ".join('%s: "${{ %s }}"' % (n, e) for e, n in mapping)
            edits.append((inline_env, "%senv: {%s%s}" % (
                m.group(1), inner + (", " if inner else ""), add)))
        elif existing is not None:
            inserts.append((existing + 1, entry_lines))
        elif run_idx == dash_idx:
            # `- run: |` — env must come AFTER the block scalar, never inside it
            inserts.append((step_end, [" " * key_ind + "env:"] + entry_lines))
        else:
            # put `env:` directly above the `run:` key of this step
            inserts.append((run_idx, [" " * key_ind + "env:"] + entry_lines))

    if not inserts and not edits:
        return list(lines), 0

    for idx, new in sorted(edits, key=lambda t: -t[0]):
        out[idx] = new
    for idx, env_lines in sorted(inserts, key=lambda t: -t[0]):
        out[idx:idx] = env_lines
    return out, len(edits) + len(inserts)


# --------------------------------------------------------------------------- #
# fixer: scope-secrets
# --------------------------------------------------------------------------- #

def _job_ranges(lines: Sequence[str]) -> List[Tuple[int, int, str]]:
    """(job_start, job_end, job_id) for every job under a top-level `jobs:`."""
    out = []
    jobs_idx = next((i for i, l in enumerate(lines) if re.match(r"^jobs:\s*$", l)),
                    None)
    if jobs_idx is None:
        return out
    i = jobs_idx + 1
    while i < len(lines):
        m = re.match(r"^  ([A-Za-z_][\w.-]*):\s*$", lines[i])
        if m:
            j = i + 1
            while j < len(lines):
                l = lines[j]
                if l.strip() and indent_of(l) <= 2:
                    break
                j += 1
            out.append((i, j, m.group(1)))
            i = j
            continue
        i += 1
    return out


def _step_env_op(out, steps, ref_line, name, value):
    """(insert_index, [lines]) to bind `name` inside the step owning `ref_line`."""
    s0 = s1 = None
    for a, _ind, b in steps:
        if a <= ref_line < b:
            s0, s1 = a, b
            break
    if s0 is None:
        return None
    step_ind = indent_of(out[s0])
    key_ind = step_ind + 2
    entry = " " * (key_ind + 2) + "%s: %s" % (name, value.strip())
    for k in range(s0 + 1, s1):
        if indent_of(out[k]) == key_ind and re.match(r"^\s*env:\s*$", out[k]):
            return (k + 1, [entry])
    head = [" " * key_ind + "env:", entry]
    # `- run: |` keeps its block scalar on the dash line: env goes AFTER it
    if re.match(r"^\s*-\s+run:", out[s0]):
        return (s1, head)
    return (s0 + 1, head)


def _job_env_op(out, jobs, ref_line, name, value):
    """(insert_index, [lines]) to bind `name` in the job owning `ref_line`."""
    for j0, j1, _jid in jobs:
        if j0 <= ref_line < j1:
            break
    else:
        return None
    base = indent_of(out[j0]) + 2
    entry = " " * (base + 2) + "%s: %s" % (name, value.strip())
    for k in range(j0 + 1, j1):
        if indent_of(out[k]) == base and re.match(r"^\s*env:\s*$", out[k]):
            return (k + 1, [entry])
    return (j0 + 1, [" " * base + "env:", entry])


def fix_scope_secrets(lines: Sequence[str]) -> Tuple[List[str], int]:
    """Move workflow/job level `secrets.*` env entries down to the reading step.

    A secret exposed at workflow level is handed to every job and every step,
    including steps that run untrusted code.  For each entry this fixer
    decides between three outcomes:

      move   -> one step (or one job) actually reads it: rebind it there
      drop   -> nobody reads it as an env var (dead exposure, or only an
                inline `${{ secrets.X }}` which needs no env at all)
      keep   -> referenced from a context we cannot safely narrow
    """
    out = list(lines)
    steps = find_steps(out)
    jobs = _job_ranges(out)
    env_blocks = [(i, e, s) for (i, e, s) in find_env_blocks(out)
                  if s in ("workflow", "job")]

    deletes = []          # line indices (set semantics applied later)
    inserts = []          # (index, [lines])
    keep_block = set()    # env blocks that still hold a live entry
    changes = 0

    def step_owner(k):
        for a, _ind, b in steps:
            if a <= k < b:
                return True
        return False

    for idx, end, scope in env_blocks:
        entries = env_entries(out, idx, end)
        if not entries:
            deletes.append(idx)          # empty `env:` block -> drop the key
            continue
        live = 0
        for eidx, name, value in entries:
            if "secrets." not in value:
                live += 1
                continue
            refs = []
            for k, l in enumerate(out):
                if idx <= k < end:
                    continue
                if re.search(r"\$\{\{\s*secrets\.%s\s*\}\}" % re.escape(name), l):
                    continue             # inline use needs no env binding
                if (re.search(r"\benv\.%s\b" % re.escape(name), l)
                        or re.search(r"\$\{?%s\}?(?![\w-])" % re.escape(name), l)):
                    refs.append(k)
            if not refs:
                deletes.append(eidx)     # unused or inline-only -> drop exposure
                changes += 1
                continue
            step_refs = [k for k in refs if step_owner(k)]
            other_refs = [k for k in refs if not step_owner(k)]
            if other_refs and scope == "job":
                live += 1                # job-level env read outside steps: keep
                continue
            if other_refs:
                live += 1                # workflow-level env read outside steps
                continue
            # every reader lives in a step
            owners = []
            for k in step_refs:
                op = _step_env_op(out, steps, k, name, value)
                if op and op[0] not in [o[0] for o in owners]:
                    owners.append(op)
            if len(owners) == 1:
                inserts.append(owners[0])
                deletes.append(eidx)
                changes += 1
                continue
            # several steps: rebind at the narrowest common scope = their jobs
            job_ops = []
            for k in step_refs:
                op = _job_env_op(out, jobs, k, name, value)
                if op and op[0] not in [o[0] for o in job_ops]:
                    job_ops.append(op)
            if scope == "workflow" and job_ops and len(job_ops) == len(
                    {next((j for j, _e, _i in [(a, b, c) for a, b, c in jobs]
                           if a <= k < b), None) for k in step_refs}):
                for op in job_ops:
                    inserts.append(op)
                deletes.append(eidx)
                changes += 1
                continue
            live += 1                    # cannot narrow safely -> keep
        if live == 0:
            deletes.append(idx)          # drop the now-empty `env:` key

    # apply bottom-up: a higher index never disturbs a lower one
    operations = [("ins", i, ls) for i, ls in inserts]
    operations += [("del", i, None) for i in sorted(set(deletes), reverse=True)]
    operations.sort(key=lambda t: t[1], reverse=True)
    n = 0
    while n < len(operations):
        idx = operations[n][1]
        run = []
        while n < len(operations) and operations[n][1] == idx:
            run.append(operations[n])
            n += 1
        ins_lines = []
        for kind, _i, ls in run:
            if kind == "ins":
                ins_lines.extend(ls or [])
        if ins_lines:
            out[idx:idx] = ins_lines
        for kind, _i, _ls in run:
            if kind == "del":
                target = idx + len(ins_lines) if ins_lines else idx
                if 0 <= target < len(out):
                    del out[target]
    return out, changes


# --------------------------------------------------------------------------- #
# fixer: pin
# --------------------------------------------------------------------------- #

def _resolve_sha(owner_repo: str, ref: str, cache: Dict[str, str]) -> Optional[str]:
    key = "%s@%s" % (owner_repo, ref)
    if key in cache:
        return cache[key]
    url = "https://github.com/%s" % owner_repo
    try:
        proc = subprocess.run(
            ["git", "ls-remote", url, "refs/tags/" + ref, "refs/heads/" + ref,
             "refs/tags/%s^{}" % ref],
            capture_output=True, text=True, timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    sha = None
    for line in proc.stdout.splitlines():
        parts = line.split()
        if len(parts) == 2 and not parts[1].endswith("^{}"):
            sha = parts[0]
        elif len(parts) == 2:
            sha = parts[0]      # annotated tag -> peeled object
    if sha is None and proc.stdout.strip():
        sha = proc.stdout.split()[0]
    cache[key] = sha
    return sha


def fix_pin(lines: Sequence[str], resolve: bool = True) -> Tuple[List[str], int]:
    """Pin `uses:` refs to a full 40-hex commit SHA (tag kept as a comment)."""
    if not resolve:
        return list(lines), 0
    out = list(lines)
    cache: Dict[str, str] = {}
    changes = 0
    for i, line in enumerate(out):
        m = USES_RE.match(line)
        if not m:
            continue
        indent, dash, target, comment = (m.group(1), m.group(2) or "",
                                         m.group(3), m.group(4) or "")
        am = USES_ACTION.match(target)
        if not am:
            continue
        owner_repo = "%s/%s" % (am.group(1), am.group(2))
        ref = am.group(3)
        if re.fullmatch(r"[0-9a-f]{40}", ref):
            continue
        sha = _resolve_sha(owner_repo, ref, cache)
        if not sha:
            continue
        trailing = comment if comment else ("# %s" % ref)
        out[i] = "%s%suses: %s@%s  %s" % (indent, dash, owner_repo, sha, trailing)
        changes += 1
    return out, changes


# --------------------------------------------------------------------------- #
# fixer: permissions
# --------------------------------------------------------------------------- #

def fix_permissions(lines: Sequence[str], level: str = "read") -> Tuple[List[str], int]:
    """Insert an explicit least-privilege `permissions:` block if missing."""
    if any(re.match(r"^\s*permissions:", l) for l in lines):
        return list(lines), 0
    jobs_idx = next((i for i, l in enumerate(lines) if re.match(r"^jobs:\s*$", l)), None)
    if jobs_idx is None:
        return list(lines), 0
    if level == "read":
        block = ["permissions:", "  contents: read"]
    else:
        block = ["permissions: {}"]
    # place it directly after `on:` / before `jobs:`
    insert_at = jobs_idx
    out = list(lines)
    out[insert_at:insert_at] = block + [""]
    return out, 1


# --------------------------------------------------------------------------- #
# driver
# --------------------------------------------------------------------------- #

FIXERS = {
    "envify": fix_envify,
    "scope-secrets": fix_scope_secrets,
    "pin": fix_pin,
    "permissions": fix_permissions,
}


def apply_fixers(path: str, which: Sequence[str], apply: bool = False,
                 resolve: bool = True) -> FixResult:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        original = fh.read()
    lines = original.split("\n")
    total = 0
    for name in which:
        fn = FIXERS[name]
        if name == "pin":
            lines, n = fn(lines, resolve=resolve)
        elif name == "permissions":
            lines, n = fn(lines)
        else:
            lines, n = fn(lines)
        total += n
    new_text = "\n".join(lines)
    res = FixResult(path=path, changed=new_text != original,
                    description="%s change(s) via %s" % (total, "+".join(which)))
    if res.changed:
        res.diff = _unified(original, new_text, path)
        if apply:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(new_text)
            res.applied = True
    return res


def _unified(a: str, b: str, path: str) -> str:
    import difflib
    return "\n".join(difflib.unified_diff(
        a.split("\n"), b.split("\n"),
        fromfile="a/" + path, tofile="b/" + path, lineterm="", n=2))
