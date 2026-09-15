"""Unit coverage for Check.family and family_for_os() -- the OS-family
filter that run_assessment() uses to pick which subset of CHECKS applies
to a given target (see api.py). No docker/network needed: everything
here operates on CHECKS itself or synthetic data.
"""

import pytest

from invariant_assessment import CHECKS, Check, family_for_os


def test_all_existing_checks_default_to_debian_ubuntu_family():
    assert all(check.family == "debian_ubuntu" for check in CHECKS)


def test_family_for_os_debian_and_ubuntu():
    assert family_for_os("debian", "12") == "debian_ubuntu"
    assert family_for_os("ubuntu", "22.04") == "debian_ubuntu"


def test_family_for_os_unknown_raises_lookuperror():
    with pytest.raises(LookupError):
        family_for_os("windows", "2022")


def test_synthetic_second_family_is_excluded_by_filter():
    synthetic_check = Check(
        titles=["Synthetic Windows Check"],
        evaluate=lambda f: True,
        evidence=lambda f: "n/a",
        family="windows",
    )
    # Local list only -- must NOT mutate the module-level CHECKS, since
    # other test files (e.g. test_evaluators.py) iterate CHECKS directly.
    checks = CHECKS + [synthetic_check]

    debian_ubuntu_checks = [c for c in checks if c.family == "debian_ubuntu"]
    windows_checks = [c for c in checks if c.family == "windows"]

    assert synthetic_check not in debian_ubuntu_checks
    assert windows_checks == [synthetic_check]
