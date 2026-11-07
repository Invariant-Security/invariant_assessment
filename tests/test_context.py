"""INV-83: /proc parser, finding classification and the no-leak guarantee (no Docker)."""

import json

import pytest

from invariant_assessment import context
from invariant_assessment.transport import TransportUnreachableError

MARK = "/opt/SEGREDO-MARCADO-9d41b7/libvuln.so.1"
V4_ANY, V4_LO, V4_ETH = "00000000", "0100007F", "0200A8C0"
V6_ANY = "0" * 32
V6_LO = "00000000000000000000000001000000"
V6_MAPPED_LO = "0000000000000000FFFF00000100007F"
V6_MAPPED_ETH = "0000000000000000FFFF00000200A8C0"


def row(addr, state, inode, port="1F90"):
    return f"   0: {addr}:{port} {'0' * len(addr)}:0000 {state} 00000000:00000000 00:00000000 00000000     0        0 {inode} 1 0\n"


def probe(net=(), procs=(), extra=""):
    """net: (file, row); procs: (files, inodes)."""
    t = "".join(f"NET {f}\n  sl  local_address ...\n{r}" for f, r in net)
    t += "PROC ok\n" + extra
    for files, socks in procs:
        t += "P\n" + "".join(f"M {f}\n" for f in files) + "".join(f"S {s}\n" for s in socks)
    return t


PKG = "DPKG ok\nPKG libvuln ok 1.0-1\nF libvuln /opt/SEGREDO-MARCADO-9d41b7/libvuln.so.1\nPKG hdrs ok 5.0\n"
FIND = {"package": "libvuln", "installed_version": "1.0-1"}


def state(text, pkg_text=PKG, finding=FIND):
    return context.classify(finding, context.parse_probe(text), context.parse_packages(pkg_text))


@pytest.mark.parametrize("net,proto_ok", [
    (("tcp", row(V4_ANY, "0A", 11)), True),
    (("tcp", row(V4_ETH, "0A", 11)), True),
    (("tcp6", row(V6_ANY, "0A", 11)), True),
    (("tcp6", row(V6_MAPPED_ETH, "0A", 11)), True),
    (("udp", row(V4_ANY, "07", 11)), True),   # UDP bound counts (fail closed)
    (("udp6", row(V6_ANY, "07", 11)), True),
    (("tcp", row(V4_LO, "0A", 11)), False),
    (("tcp6", row(V6_LO, "0A", 11)), False),
    (("tcp6", row(V6_MAPPED_LO, "0A", 11)), False),
    (("udp", row(V4_LO, "07", 11)), False),   # UDP loopback does not
    (("tcp", row(V4_ANY, "01", 11)), False),  # established, not listening
    (("udp", row(V4_ANY, "01", 11)), False),
    (("tcp", row(V4_ANY, "07", 11)), False),  # 07 is only a UDP listener state
    (("udp", row(V4_ANY, "0A", 11)), False),
])
def test_listening_rules(net, proto_ok):
    assert (state(probe([net], [([MARK], ["11"])])) == ("exposed", "listener_maps_package")) is proto_ok


def test_maps_but_does_not_listen():
    t = probe([("tcp", row(V4_ANY, "0A", 11))], [([MARK], ["99"]), (["/other"], ["11"])])  # two different processes
    assert state(t) == ("not_exposed", "not_loaded_by_listener")


def test_listens_without_mapping():
    assert state(probe([("tcp", row(V4_ANY, "0A", 11))], [(["/other.so"], ["11"])])) == ("not_exposed", "not_loaded_by_listener")


def test_unreadable_is_unknown_not_clean():
    t = probe([("tcp", row(V4_ANY, "0A", 11))], [(["/other.so"], ["11"])], extra="PROC unreadable\n")
    assert state(t) == ("unknown", "unreadable")
    assert state("NET unreadable\n" + probe()) == ("unknown", "unreadable")
    assert state("") == ("unknown", "unreadable")  # container not running / no output
    # ...but a proof of exposure survives an unreadable process elsewhere
    t = probe([("tcp", row(V4_ANY, "0A", 11))], [([MARK], ["11"])], extra="PROC unreadable\n")
    assert state(t) == ("exposed", "listener_maps_package")


def test_package_rules():
    t = probe()
    assert state(t, "DPKG absent\n") == ("unknown", "no_dpkg")
    assert state(t, PKG, {**FIND, "package": "cross-spawn"}) == ("unknown", "not_in_dpkg")  # language package
    assert state(t, PKG, {**FIND, "installed_version": "2.0"}) == ("unknown", "not_in_dpkg")  # same name, other thing
    assert state(t, PKG, {"package": "hdrs", "installed_version": "5.0"}) == ("not_exposed", "not_executable")
    assert state(t, "DPKG ok\nPKG libvuln ok 1:1.0-1\nF libvuln /x.so\n") == ("not_exposed", "not_loaded_by_listener")  # epoch ok


def test_deleted_suffix_and_unreadable_net_row():
    t = probe([("tcp", row(V4_ANY, "0A", 11))], [([MARK + " (deleted)"], ["11"])])
    assert state(t)[0] == "exposed"
    assert not context.parse_probe(probe([("tcp", "   0: garbage\n")]))["ok"]


def _main(monkeypatch, capsys, probe_text, pkg_text=PKG, raises=None):
    report = {"db_age_warning": None, "findings": [dict(FIND, cve="CVE-1")]}
    monkeypatch.setattr(context.vuln, "scan", lambda *a: report)

    class T:
        def __init__(self, **kw): pass
        def run(self, script):
            if raises:
                raise raises
            return probe_text if "NET" in script else pkg_text

    monkeypatch.setattr(context, "DockerExecTransport", T)
    rc = context.main(["--docker", "c", "--cache-dir", "/c"])
    return (rc, *capsys.readouterr())


def test_main_outputs_only_state_and_never_the_marked_path(monkeypatch, capsys):
    rc, out, err = _main(monkeypatch, capsys, probe([("tcp", row(V4_ANY, "0A", 7777123))], [([MARK], ["7777123"])]))
    assert rc == 0
    assert json.loads(out)["findings"][0]["exposure"] == "exposed"
    for leak in ("SEGREDO", "7777123", "/opt/"):
        assert leak not in out + err
    rc, out, err = _main(monkeypatch, capsys, "", raises=TransportUnreachableError(f"x {MARK}"))
    assert rc == 3 and "SEGREDO" not in out + err
    rc, out, err = _main(monkeypatch, capsys, "", raises=ValueError(MARK))
    assert rc == 4 and "SEGREDO" not in out + err


def test_usage_exit_codes(monkeypatch, capsys):
    monkeypatch.delenv("INVARIANT_TRIVY_CACHE", raising=False)
    assert context.main(["--docker", "c"]) == 2
    assert context.main([]) == 2
