"""Check ids are our own stable identifiers: unique, snake_case, and
append-only (tests/snapshots/check_ids.txt)."""

import re
from pathlib import Path

from invariant_assessment import CHECKS

SNAPSHOT = Path(__file__).parent / "snapshots" / "check_ids.txt"


def test_ids_are_unique():
    ids = [c.id for c in CHECKS]
    assert len(ids) == len(set(ids)), sorted({i for i in ids if ids.count(i) > 1})


def test_ids_are_snake_case():
    bad = [c.id for c in CHECKS if not re.fullmatch(r"[a-z][a-z0-9_]*", c.id)]
    assert not bad, bad


def test_ids_only_grow():
    """No id from the snapshot may disappear or be renamed; a new check needs
    its id appended to the snapshot (kept sorted)."""
    snap = SNAPSHOT.read_text().split()
    current = {c.id for c in CHECKS}
    assert not set(snap) - current, f"ids removed/renamed: {sorted(set(snap) - current)}"
    assert not current - set(snap), f"new ids missing from {SNAPSHOT.name}: {sorted(current - set(snap))}"
