# -*- coding: utf-8 -*-
"""
gha-audit scope guard — never scan what you do not own.

The toolkit only ever reads local files, but a shared machine can hold
cloned repositories that belong to someone else.  Before any scan the CLI
asks this module for permission:

  1. an explicit `--i-own-this` flag overrides everything (you asserted
     ownership in the command line, which is logged in the report);
  2. a local `.gha-audit-scope` file in the target directory may list
     allowed path prefixes (one per line, `#` comments);
  3. otherwise the target must be inside your home directory AND, when it
     is a git checkout, its `origin` URL must match the account that `gh`
     is authenticated as (or an allow-listed host).

Anything else -> ScopeError, exit code 3.
"""
import os
import re
import subprocess
from dataclasses import dataclass
from typing import List, Optional, Sequence

SCOPE_FILE = ".gha-audit-scope"


class ScopeError(Exception):
    """Raised when the target is outside the declared ownership boundary."""


@dataclass
class ScopeDecision:
    allowed: bool
    reason: str
    owner_override: bool = False


def _gh_login() -> Optional[str]:
    try:
        proc = subprocess.run(["gh", "api", "user", "--jq", ".login"],
                              capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode == 0 and proc.stdout.strip():
        return proc.stdout.strip()
    return None


def _git_origin(path: str) -> Optional[str]:
    gitdir = os.path.join(path, ".git")
    if not os.path.exists(gitdir) and not os.path.isfile(gitdir):
        # walk up to the repo root
        cur = os.path.abspath(path)
        while cur != os.path.dirname(cur):
            if os.path.isdir(os.path.join(cur, ".git")):
                path = cur
                break
            cur = os.path.dirname(cur)
        else:
            return None
    try:
        proc = subprocess.run(["git", "-C", path, "remote", "get-url", "origin"],
                              capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode == 0 and proc.stdout.strip():
        return proc.stdout.strip()
    return None


def _owner_from_url(url: str) -> Optional[str]:
    m = re.search(r"github\.com[:/]([^/]+)/", url)
    return m.group(1) if m else None


def _scope_file_allows(path: str) -> bool:
    """Honour a `.gha-audit-scope` file in the target or any parent."""
    cur = os.path.abspath(path)
    while True:
        f = os.path.join(cur, SCOPE_FILE)
        if os.path.isfile(f):
            try:
                with open(f, "r", encoding="utf-8", errors="replace") as fh:
                    for line in fh:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        prefix = os.path.expanduser(line)
                        if os.path.abspath(path).startswith(os.path.abspath(prefix)):
                            return True
            except OSError:
                pass
        parent = os.path.dirname(cur)
        if parent == cur:
            return False
        cur = parent


def check_scope(paths: Sequence[str], i_own_this: bool = False,
                allow_foreign: bool = False) -> ScopeDecision:
    """Decide whether scanning `paths` is allowed."""
    if i_own_this:
        return ScopeDecision(True, "ownership asserted with --i-own-this",
                             owner_override=True)
    home = os.path.expanduser("~")
    login = _gh_login()
    problems: List[str] = []
    for p in paths:
        ap = os.path.abspath(os.path.expanduser(p))
        if not os.path.exists(ap):
            problems.append("path does not exist: %s" % p)
            continue
        if _scope_file_allows(ap):
            continue
        if not ap.startswith(home + os.sep) and ap != home:
            if allow_foreign:
                continue
            problems.append("outside home directory: %s" % p)
            continue
        origin = _git_origin(ap)
        if origin is None:
            continue                      # plain folder inside $HOME -> yours
        owner = _owner_from_url(origin)
        if owner is None:
            continue                      # non-github remote (file://, ...)
        if login is None:
            if allow_foreign:
                continue
            problems.append(
                "git checkout of %s but `gh` is not authenticated; "
                "pass --i-own-this to assert ownership" % owner)
            continue
        if owner.lower() != login.lower() and not allow_foreign:
            problems.append(
                "repository owner `%s` does not match the authenticated "
                "GitHub account `%s`" % (owner, login))
    if problems:
        return ScopeDecision(False, "; ".join(problems))
    return ScopeDecision(True, "all targets inside the ownership boundary")
