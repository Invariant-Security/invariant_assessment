"""Guard: nothing tracked by git may carry text copied from a third-party
benchmark (recommendation titles, section numbers, page furniture, audit
commands). Checks have their own ids and descriptions; see test_check_ids.py.

Scans every file `git ls-files` lists (code, comments, docstrings, string
literals incl. evidence messages, test names, Dockerfiles, README, CI).
"""

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SELF = "tests/test_no_benchmark_text.py"

# Dependency hash/version pins are not prose.
SKIP_FILES = {SELF, "requirements.lock"}

FORBIDDEN = {
    "recommendation title": re.compile(r"\bEnsure\b"),
    "audit-section wording": re.compile(r"real audit", re.IGNORECASE),
    "benchmark section number": re.compile(r"\b\d+\.\d+\.\d+(?:\.\d+)*\b"),
    "page furniture": re.compile(r"\bPage \d+\b|Internal Only", re.IGNORECASE),
}

# Markers of benchmark audit scripts/commands (PCRE \h, awk/grep -P one-liners,
# the benchmark's l_* shell variables, its "- IF -" / "OR/IF" conditions).
COMMAND_MARKERS = re.compile(r"\\+h[*+]|\bawk -F|\bgrep -Pi?H?h?\b|\bl_[a-z]+\w*=|- IF -|OR/IF")

# Explicit, minimal allowlist: (file, matched text) pairs. Everything else fails.
ALLOW_TOKENS = {
    ("Dockerfile", "3.12.14"),  # pinned python base image tag
    ("Dockerfile", "0.0.0.0"),  # uvicorn bind address
    ("README.md", "3.12.14"),  # same base image tag, in the bump instructions
    ("pyproject.toml", "0.1.0"),  # package version
    ("tests/fixtures/docker-compose.yml", "127.0.0.1"),  # loopback-only port binding
    ("tests/fixtures/docker/ssh-target/Dockerfile", "127.0.0.1"),  # loopback comment
    ("tests/test_internal_auth.py", "127.0.0.1"),  # loopback test server
    ("tests/test_transport.py", "127.0.0.1"),  # loopback SSH fixture
}

# facts.py holds the shell probes that actually run on the target; they are
# the one place shell one-liners (grep -P, awk -F, l_* vars) must exist.
ALLOW_COMMAND_FILES = {"src/invariant_assessment/facts.py"}


def _tracked_files():
    out = subprocess.run(
        ["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True
    ).stdout.decode()
    return [f for f in out.split("\0") if f and f not in SKIP_FILES]


def _violations():
    found = []
    for rel in _tracked_files():
        try:
            text = (ROOT / rel).read_text(encoding="utf-8")
        except (UnicodeDecodeError, FileNotFoundError):
            continue  # binary or deleted-in-worktree
        for lineno, line in enumerate(text.splitlines(), 1):
            for kind, rx in FORBIDDEN.items():
                for m in rx.finditer(line):
                    if (rel, m.group(0)) not in ALLOW_TOKENS:
                        found.append(f"{rel}:{lineno}: {kind}: {m.group(0)!r}")
            if rel not in ALLOW_COMMAND_FILES and COMMAND_MARKERS.search(line):
                found.append(f"{rel}:{lineno}: audit command marker")
    return found


def test_no_benchmark_text_in_tracked_files():
    assert not _violations()


def test_allowlist_has_no_stale_entries():
    """Every allowlisted (file, token) must still occur, so the list can't rot."""
    for rel, token in ALLOW_TOKENS:
        assert token in (ROOT / rel).read_text(encoding="utf-8"), (rel, token)
