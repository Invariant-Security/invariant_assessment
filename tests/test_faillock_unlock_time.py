import dataclasses

import pytest
from test_evaluators import _facts

from invariant_assessment import _evaluate_faillock_unlock_time, _evidence_faillock_unlock_time

PAM = "auth [default=die] pam_faillock.so authfail {args}"


def _f(conf="", inline=None):
    facts = _facts(pam_common_auth=PAM.format(args=inline) if inline is not None else "")
    return dataclasses.replace(facts, faillock_text=conf)


@pytest.mark.parametrize(
    "conf,inline,expected",
    [
        ("", None, False),  # absent everywhere -> pam_faillock default 600
        ("unlock_time = 900", None, True),
        ("unlock_time = 0", None, True),
        ("unlock_time = 600", None, False),
        ("unlock_time = 899", None, False),
        ("", "unlock_time=900", True),
        ("", "unlock_time=600", False),
        ("unlock_time = 900", "unlock_time=600", False),
        ("unlock_time = 600", "unlock_time=900", True),  # inline overrides conf
        ("unlock_time = abc", None, False),
        ("", "unlock_time=abc", False),
        ("unlock_time = 900", "root_unlock_time=60", True),  # root_ arg is not unlock_time
        ("", "root_unlock_time=1000", False),  # still defaults to 600
    ],
)
def test_effective_unlock_time(conf, inline, expected):
    assert _evaluate_faillock_unlock_time(_f(conf, inline)) is expected


def test_any_bad_line_fails():
    facts = _facts(
        pam_common_auth=PAM.format(args="unlock_time=900") + "\n" + PAM.format(args="unlock_time=600")
    )
    assert _evaluate_faillock_unlock_time(facts) is False


def test_evidence_shows_value_and_source():
    assert _evidence_faillock_unlock_time(_f()) == "unlock_time 600 (default)"
    assert _evidence_faillock_unlock_time(_f("unlock_time = 900")) == "unlock_time 900 (faillock.conf)"
    assert _evidence_faillock_unlock_time(_f("", "unlock_time=0")) == "unlock_time 0 (common-auth inline)"
