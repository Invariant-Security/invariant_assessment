"""INV-82: KEV/EPSS enrichment, feed age/integrity (exit 4) and the offline prepare step."""

import gzip
import hashlib
import http.server
import json
import threading
from datetime import datetime, timedelta, timezone

import pytest

from invariant_assessment import enrich, prepare, vuln

NOW = datetime(2026, 11, 7, 12, 0, tzinfo=timezone.utc)
KEV = json.dumps({"catalogVersion": "2026-11-04", "vulnerabilities": [
    {"cveID": "CVE-2026-111497", "dateAdded": "2026-10-27", "knownRansomwareCampaignUse": "Unknown"},
    {"cveID": "CVE-2024-0001", "dateAdded": "2024-01-02", "knownRansomwareCampaignUse": "Known"}]}).encode()
EPSS = (b"#model_version:v2025,score_date:2026-11-07T12:55:00Z\ncve,epss,percentile\n"
        b"CVE-2026-111497,0.91000,0.99000\nCVE-2024-0001,0.00100,0.20000\nCVE-2020-9999,0.50000,0.80000\n")


def make_cache(tmp_path, age_days=0.0, kev=KEV, epss=EPSS, now=NOW):
    base = tmp_path / "feeds"
    base.mkdir()
    (base / "kev.json").write_bytes(kev)
    (base / "epss.csv").write_bytes(epss)
    ts = (now - timedelta(days=age_days)).isoformat()
    sha = lambda b: hashlib.sha256(b).hexdigest()
    (base / "manifest.json").write_text(json.dumps({
        "kev": {"fetched_at": ts, "sha256": sha(KEV), "catalogVersion": "2026-11-04"},
        "epss": {"fetched_at": ts, "sha256": sha(EPSS), "score_date": "2026-11-07"}}))
    return str(tmp_path)


F = lambda cve, sev, pkg="p": {"cve": cve, "package": pkg, "severity": sev}


def test_enrich_fields_nulls_and_order(tmp_path):
    feeds = enrich.load_feeds(make_cache(tmp_path), NOW)
    out = enrich.enrich([F("CVE-2020-9999", "CRITICAL"), F("CVE-2025-1", "CRITICAL"), F("CVE-2024-0001", "LOW"),
                         F("CVE-2026-111497", "MEDIUM"), F("CVE-2021-1", "HIGH")], feeds)
    assert [f["cve"] for f in out] == ["CVE-2026-111497", "CVE-2024-0001", "CVE-2020-9999", "CVE-2025-1", "CVE-2021-1"]
    b = out[0]
    assert (b["in_kev"], b["kev_date_added"], b["kev_known_ransomware_campaign_use"]) == (True, "2026-10-27", "Unknown")
    assert (b["epss_score"], b["epss_percentile"], b["epss_date"]) == (0.91, 0.99, "2026-11-07")
    n = out[3]  # no EPSS, not in KEV: null, never 0
    assert (n["in_kev"], n["kev_date_added"], n["epss_score"], n["epss_percentile"], n["epss_date"]) == (False, None, None, None, None)
    assert feeds["kev_catalog_version"] == "2026-11-04" and len(feeds["feeds"]["kev"]["sha256"]) == 64


@pytest.mark.parametrize("age,warns,fails", [(2.9, False, False), (3.5, True, False), (7.1, False, True)])
def test_feed_age(tmp_path, age, warns, fails):
    c = make_cache(tmp_path, age)
    if fails:
        with pytest.raises(vuln.VulnError, match="days old"):
            enrich.load_feeds(c, NOW)
    else:
        assert (enrich.load_feeds(c, NOW)["warning"] is not None) is warns


def test_missing_corrupt_or_mismatched_feed_fails_closed(tmp_path):
    with pytest.raises(vuln.VulnError, match="missing"):
        enrich.load_feeds(str(tmp_path), NOW)
    c = make_cache(tmp_path)
    (tmp_path / "feeds" / "kev.json").write_bytes(KEV + b" ")
    with pytest.raises(vuln.VulnError, match="sha256"):
        enrich.load_feeds(c, NOW)
    (tmp_path / "feeds" / "kev.json").write_bytes(KEV)
    (tmp_path / "feeds" / "manifest.json").write_text("{nope")
    with pytest.raises(vuln.VulnError, match="missing"):
        enrich.load_feeds(c, NOW)


@pytest.mark.parametrize("bad", [b"{}", b'{"catalogVersion":"x","vulnerabilities":[]}', b"nope"])
def test_parse_kev_invalid(bad):
    with pytest.raises(vuln.VulnError):
        enrich.parse_kev(bad)


@pytest.mark.parametrize("bad", [b"cve,epss,percentile\nCVE-1,0.1,0.1\n", b"#score_date:2026-11-07\nfoo,bar\n",
                                 b"#score_date:2026-11-07\ncve,epss,percentile\nCVE-1,x,y\n"])
def test_parse_epss_invalid(bad):
    with pytest.raises(vuln.VulnError):
        enrich.parse_epss(bad)


def test_main_exit_codes_and_output(tmp_path, monkeypatch, capsys):
    assert enrich.main(["img"]) == 2
    monkeypatch.setenv("INVARIANT_TRIVY_CACHE", str(tmp_path))
    assert enrich.main(["img"]) == 4  # no feeds
    c = make_cache(tmp_path, now=datetime.now(timezone.utc))
    fake = {"findings": [F("CVE-2026-111497", "HIGH"), F("CVE-2020-1", "LOW")], "db_age_warning": None}
    monkeypatch.setattr(enrich.vuln, "scan", lambda *a: dict(fake))
    assert enrich.main(["img", "--cache-dir", c]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["unique_cves_in_kev"] == 1 and out["findings"][0]["in_kev"] and out["kev_catalog_version"] == "2026-11-04"


@pytest.fixture
def server():
    gz = gzip.compress(EPSS)
    files = {"/kev.json": KEV, "/epss.csv.gz": gz, "/bad.gz": b"not gzip"}

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body = files.get(self.path)
            self.send_response(200 if body is not None else 404)
            self.end_headers()
            self.wfile.write(body or b"")

        def log_message(self, *a):
            pass

    s = http.server.HTTPServer(("localhost", 0), H)
    threading.Thread(target=s.serve_forever, daemon=True).start()
    yield f"http://localhost:{s.server_port}"
    s.shutdown()


def test_prepare_roundtrip_and_failure_preserves(tmp_path, server):
    m = prepare.prepare_feeds(str(tmp_path), server + "/kev.json", server + "/epss.csv.gz")
    assert m["kev"]["catalogVersion"] == "2026-11-04" and m["epss"]["score_date"] == "2026-11-07"
    now = datetime.now(timezone.utc)
    assert enrich.load_feeds(str(tmp_path), now)["epss"]["CVE-2026-111497"] == (0.91, 0.99)
    before = (tmp_path / "feeds" / "manifest.json").read_bytes()
    for kev, epss in [("/missing", "/epss.csv.gz"), ("/kev.json", "/bad.gz"), ("/kev.json", "/missing")]:
        with pytest.raises(vuln.VulnError):
            prepare.prepare_feeds(str(tmp_path), server + kev, server + epss)
    assert (tmp_path / "feeds" / "manifest.json").read_bytes() == before
    assert not list((tmp_path / "feeds").glob("*.tmp"))


def test_prepare_main_exit_4_on_download_failure(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(prepare, "KEV_URL", "http://localhost:9/x")
    assert prepare.main(["--cache-dir", str(tmp_path), "--feeds-only"]) == 4


def test_prepare_default_kev_url_is_cisa_github_mirror():
    assert prepare.KEV_URL == ("https://raw.githubusercontent.com/cisagov/kev-data/develop/"
                               "known_exploited_vulnerabilities.json")
