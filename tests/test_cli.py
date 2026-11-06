"""`invariant assess`: effective_status, exit codes, catalog, credential hygiene.
Synthetic SystemFacts / patched transports -- no Docker needed."""

import json
import shutil
import subprocess

import pytest
from test_facts import _build_full_output

from invariant_assessment import cli
from invariant_assessment.facts import FileStat, SystemFacts
from invariant_assessment.transport import DockerExecTransport, SSHTransport, TransportUnreachableError

SNAPSHOT = cli.Path(__file__).parent / "snapshots" / "check_ids.txt"
MARKER = "SEGREDO-MARCADO-7f3a9c"


def facts(packages=("openssh-server", "sudo"), probe="BIN sshd present\nBIN sudo present\nPROC ok\nRUNNING sshd\nRUNNING sudo",
          unreadable=None, missing=None):
    return SystemFacts(os_id="debian", os_version_id="12", sshd_config={}, file_stats={},
                       installed_packages=set(packages), applicability_probe_text=probe,
                       unreadable=unreadable or {}, missing=missing or set())


ABSENT = "BIN sshd absent\nBIN sudo absent\nPROC ok"
SSHD = {"critical": False, "host_only": False, "requires": "sshd"}
SUDO = {"critical": False, "host_only": False, "requires": "sudo"}


def test_host_only_is_not_applicable_on_docker_only():
    meta = {"critical": False, "host_only": True, "requires": None}
    assert cli.effective_status("FAIL", meta, facts(), "docker") == "NOT_APPLICABLE"
    assert cli.effective_status("FAIL", meta, facts(), "local") == "FAIL"
    assert cli.effective_status("PASS", None, facts(), "docker") == "PASS"


@pytest.mark.parametrize("meta,pkg", [(SSHD, "openssh-server"), (SUDO, "sudo")])
def test_requires_absence_proved_by_all_three_signals(meta, pkg):
    assert cli.effective_status("FAIL", meta, facts(packages=("bash",), probe=ABSENT), "docker") == "NOT_APPLICABLE"


@pytest.mark.parametrize("probe,packages", [
    ("BIN sshd present\nBIN sudo absent\nPROC ok", ("bash",)),  # binary there
    ("BIN sshd absent\nBIN sudo absent\nPROC ok\nRUNNING sshd", ("bash",)),  # running
    (ABSENT, ("bash", "openssh-server")),  # package there
])
def test_requires_any_signal_present_keeps_engine_status(probe, packages):
    assert cli.effective_status("FAIL", SSHD, facts(packages=packages, probe=probe), "ssh") == "FAIL"


@pytest.mark.parametrize("kwargs", [
    {"unreadable": {"installed_packages": "dpkg not readable"}},  # dpkg unreadable
    {"packages": ()},  # no package list at all
    {"missing": {"installed_packages"}},
    {"probe": "BIN sshd absent\nBIN sudo absent\nPROC unreadable"},  # process list unreadable
    {"probe": "BIN sshd absent\nBIN sudo absent\nPROC ok\nPROC unreadable"},  # one exe not readable
    {"probe": "BIN sshd absent\nBIN sudo absent"},  # no procfs signal at all
    {"probe": "PROC ok"},  # PATH signal absent from the output
    {"unreadable": {"applicability_probe_text": "x not readable"}},
])
def test_requires_unreadable_signal_is_never_not_applicable(kwargs):
    f = facts(**{"packages": ("bash",), "probe": ABSENT, **kwargs})
    assert cli.effective_status("FAIL", SSHD, f, "ssh") == "NOT_ASSESSED"


# --- catalog ---------------------------------------------------------------------


def test_catalog_shape_and_critical_ids_exist_in_snapshot():
    checks, version = cli.load_catalog()
    ids = set(SNAPSHOT.read_text().split())
    assert len(version) == 64
    assert set(checks) == ids
    assert {i for i, m in checks.items() if m["critical"]} <= ids
    assert all(set(m) == {"critical", "host_only", "requires"} and m["requires"] in (None, "sshd", "sudo")
               for m in checks.values())


# --- exit codes ------------------------------------------------------------------


def run(capsys, *argv):
    rc = cli.main(["assess", *argv])
    out = capsys.readouterr()
    return rc, out.out, out.err


@pytest.fixture
def fake_docker(monkeypatch):
    monkeypatch.setattr(DockerExecTransport, "run", lambda self, script: _build_full_output())
    monkeypatch.setattr(cli, "_docker_image", lambda c: {"image_digest": None, "image_digest_kind": None})


@pytest.mark.parametrize("argv", [
    [],  # no target
    ["--docker", "a", "--local"],  # two targets
    ["--ssh", "u@h", "--key", "k"],  # no known-hosts nor fingerprint
    ["--ssh", "u@h", "--known-hosts", "kh"],  # no key
    ["--ssh", "u@h", "--key", "k", "--host-key-fingerprint", "SHA256:short"],
    ["--ssh", "bad", "--key", "k", "--known-hosts", "kh"],
    ["--local", "--key", "k"],
    ["--docker", "a", "--format", "xml"],
])
def test_usage_errors_exit_2(capsys, argv):
    assert run(capsys, *argv)[0] == 2


def test_success_exit_0_json_and_table(capsys, fake_docker, monkeypatch):
    monkeypatch.setenv("INVARIANT_RUN_ID", "run-42")
    rc, out, _ = run(capsys, "--docker", "c1", "--format", "json")
    d = json.loads(out)
    assert rc == 0 and d["transport"] == "docker" and d["target"] == "c1" and d["run_id"] == "run-42"
    assert {"document", "results", "invariant_version", "catalog_version", "started_at", "finished_at"} <= set(d)
    assert all(r["status"] in ("PASS", "FAIL", "NOT_ASSESSED") for r in d["results"])
    rc, out, _ = run(capsys, "--docker", "c1")
    assert rc == 0 and "EFFECTIVE" in out and "summary:" in out


def test_run_id_fallbacks(capsys, fake_docker, monkeypatch):
    for v in ("INVARIANT_RUN_ID", "BUILD_URL", "GITHUB_RUN_ID"):
        monkeypatch.delenv(v, raising=False)
    assert json.loads(run(capsys, "--docker", "c", "--format", "json")[1])["run_id"] is None
    monkeypatch.setenv("GITHUB_RUN_ID", "9")
    monkeypatch.setenv("BUILD_URL", "http://ci/1")
    assert json.loads(run(capsys, "--docker", "c", "--format", "json")[1])["run_id"] == "http://ci/1"


def test_ssh_unprivileged_warning(capsys, keys, monkeypatch):
    monkeypatch.setattr(SSHTransport, "run", lambda self, script: _build_full_output())
    rc, _, err = run(capsys, "--ssh", "bob@localhost:2222", "--key", str(keys / "id"), "--known-hosts", str(keys / "known_hosts"))
    assert rc == 0 and "not running as root" in err


def test_transport_error_exit_3(capsys, monkeypatch):
    def boom(self, script):
        raise TransportUnreachableError("docker binary not found")

    monkeypatch.setattr(DockerExecTransport, "run", boom)
    assert run(capsys, "--docker", "c")[0] == 3
    monkeypatch.setattr(DockerExecTransport, "run", lambda self, s: "sh: not found")  # no shell / no such container
    assert run(capsys, "--docker", "c")[0] == 3


def test_unexpected_error_is_4_never_1(capsys, monkeypatch):
    monkeypatch.setattr(cli, "assess", lambda a: 1 / 0)
    monkeypatch.delenv("INVARIANT_DEBUG", raising=False)
    rc, _, err = run(capsys, "--local")
    assert rc == 4 and "ZeroDivisionError" in err and "Traceback" not in err
    monkeypatch.setenv("INVARIANT_DEBUG", "1")
    assert "Traceback" in run(capsys, "--local")[2]


def test_unsupported_os_is_4(capsys, monkeypatch):
    out = _build_full_output().replace('ID=debian', 'ID=plan9')
    monkeypatch.setattr(DockerExecTransport, "run", lambda self, s: out)
    rc, o, err = run(capsys, "--docker", "c")
    assert rc == 4 and "plan9" not in o + err


@pytest.mark.parametrize("content", ["not json", "{}", '{"schema": 2, "checks": {}}',
                                     '{"schema": 1, "checks": {"a": {"critical": 1}}}', '{"schema": 1, "checks": []}'])
def test_bad_catalog_is_4(capsys, fake_docker, monkeypatch, tmp_path, content):
    p = tmp_path / "catalog.json"
    p.write_text(content)
    monkeypatch.setattr(cli, "CATALOG_PATH", p)
    rc, _, err = run(capsys, "--docker", "c")
    assert rc == 4 and "Traceback" not in err
    monkeypatch.setattr(cli, "CATALOG_PATH", tmp_path / "missing.json")
    assert run(capsys, "--docker", "c")[0] == 4


def test_unprivileged_warning(capsys, monkeypatch, fake_docker):
    monkeypatch.setattr(cli.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(cli, "LocalTransport", lambda **k: type("T", (), {"run": lambda s, sc: _build_full_output()})())
    assert "not running as root" in run(capsys, "--local")[2]
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    assert "not running as root" not in run(capsys, "--local")[2]
    assert "not running as root" not in run(capsys, "--docker", "c")[2]


def test_exe_probe_script_reads_only_exe():
    from invariant_assessment.facts import _APPLICABILITY_CMD as c
    assert "/exe" in c and "cmdline" not in c and "environ" not in c and "/comm" not in c


# --- SSH + credential hygiene --------------------------------------------------------


@pytest.fixture
def keys(tmp_path):
    if not shutil.which("ssh-keygen"):
        pytest.skip("ssh-keygen not available")
    for name, comment in (("id", MARKER), ("host", "host")):
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", comment, "-f", str(tmp_path / name)], check=True)
    pub = (tmp_path / "host.pub").read_text().split()
    (tmp_path / "known_hosts").write_text(f"[localhost]:2222 {pub[0]} {pub[1]}\n")
    return tmp_path


def no_marker(*texts):
    assert all(MARKER not in t for t in texts)


def test_ssh_known_hosts_success_hides_credential(capsys, keys, monkeypatch):
    monkeypatch.setattr(SSHTransport, "run", lambda self, script: _build_full_output())
    for fmt in ("json", "table"):
        rc, out, err = run(capsys, "--ssh", "root@localhost:2222", "--key", str(keys / "id"),
                           "--known-hosts", str(keys / "known_hosts"), "--format", fmt)
        assert rc == 0
        no_marker(out, err)


def test_ssh_known_hosts_without_entry_is_usage_error(capsys, keys):
    rc, out, err = run(capsys, "--ssh", "root@other-host", "--key", str(keys / "id"), "--known-hosts", str(keys / "known_hosts"))
    assert rc == 2
    no_marker(out, err)


def test_ssh_transport_error_hides_credential(capsys, keys):
    rc, out, err = run(capsys, "--ssh", "root@localhost:2222", "--key", str(keys / "id"),
                       "--known-hosts", str(keys / "known_hosts"))
    assert rc == 3  # nothing listens on 2222
    no_marker(out, err)


def test_ssh_unparseable_key_hides_credential(capsys, keys):
    bad = keys / "bad"
    bad.write_text(f"-----BEGIN OPENSSH PRIVATE KEY-----\n{MARKER}\n-----END OPENSSH PRIVATE KEY-----\n")
    rc, out, err = run(capsys, "--ssh", "root@localhost:2222", "--key", str(bad), "--known-hosts", str(keys / "known_hosts"))
    assert rc == 3
    no_marker(out, err)


def _probe_with_readlink_output(msg):
    """Runs the real probe script with `readlink` stubbed to fail with `msg` for every pid."""
    from invariant_assessment.facts import _APPLICABILITY_CMD as c
    stub = ('readlink() { case "$2" in /proc/self/exe) echo /usr/bin/readlink;; *) echo "' + msg + '"; return 1;; esac; }; ')
    return subprocess.run(["/bin/sh", "-c", stub + c], capture_output=True, text=True).stdout


def test_unknown_readlink_error_is_unknown_and_not_assessed():
    out = _probe_with_readlink_output("readlink: /proc/1/exe: Input/output error")
    assert "PROC unreadable" in out
    f = facts(packages=("bash",), probe=out.replace("BIN sshd present", "BIN sshd absent").replace("BIN sudo present", "BIN sudo absent"))
    assert cli.effective_status("FAIL", SSHD, f, "ssh") == "NOT_ASSESSED"


def test_no_such_file_readlink_error_is_ignored():
    out = _probe_with_readlink_output("readlink: /proc/2/exe: No such file or directory")
    assert "PROC ok" in out and "PROC unreadable" not in out
