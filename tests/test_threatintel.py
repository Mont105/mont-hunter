import io
import json
import urllib.error

import pytest

from monthunter import threatintel as ti
from monthunter.cli import main
from monthunter.core import analyze_one
from monthunter.scoring import compute_risk
from monthunter.threatintel import ThreatFoxIndex, ThreatIntelError, load_auth_key, update_feed

# Synthetic feed entries in ThreatFox's documented shape (documentation-range IPs, .invalid domains).
FEED = [
    {"id": "1", "ioc": "203.0.113.7:4444", "ioc_type": "ip:port", "threat_type": "botnet_cc", "malware_printable": "FakeRAT", "confidence_level": 75, "first_seen": "2026-11-17 10:00:00 UTC"},
    {"id": "2", "ioc": "198.51.100.9:80", "ioc_type": "ip:port", "threat_type": "botnet_cc", "malware_printable": "OtherBot", "confidence_level": 50},
    {"id": "3", "ioc": "c2.evil.invalid", "ioc_type": "domain", "threat_type": "botnet_cc", "malware_printable": "FakeRAT", "confidence_level": 100},
    {"id": "4", "ioc": "http://drop.evil.invalid/a.bin", "ioc_type": "url", "threat_type": "payload_delivery", "malware_printable": "Loader", "confidence_level": 90},
    {"id": "5", "ioc": "d41d8cd98f00b204e9800998ecf8427e", "ioc_type": "md5_hash", "threat_type": "payload", "malware_printable": "EmptyFile", "confidence_level": 100},
    {"id": "6", "ioc": "ignored", "ioc_type": "weird"},
    "not-a-dict",
]


@pytest.fixture
def index():
    return ThreatFoxIndex(FEED, fetched_at=0)


def test_index_sizes(index):
    assert index.size == 5  # unknown types still counted only when they have an ioc; non-dicts skipped
    assert "203.0.113.7" in index.ip


def test_match_static_dynamic_and_hash(index):
    summary = {
        "md5": "D41D8CD98F00B204E9800998ECF8427E",
        "iocs": {"ips": ["198.51.100.9", "8.8.8.8"], "domains": ["C2.EVIL.INVALID", "ok.example.org"], "urls": ["http://drop.evil.invalid/a.bin"]},
        "dynamic": {"network_attempts": [{"ip": "203.0.113.7", "port": 4444}, {"ip": "203.0.113.7", "port": 9999}, {"ip": "1.1.1.1", "port": 53}]},
    }
    res = index.match_summary(summary)
    got = {(m["kind"], m["value"], m["where"]) for m in res["matches"]}
    assert got == {
        ("file_hash", "d41d8cd98f00b204e9800998ecf8427e", "sample"),
        ("ip", "198.51.100.9", "static"),
        ("domain", "C2.EVIL.INVALID", "static"),
        ("url", "http://drop.evil.invalid/a.bin", "static"),
        ("ip_port", "203.0.113.7:4444", "sandbox"),
        ("ip", "203.0.113.7", "sandbox"),  # same C2 IP on another port
    }
    fake = next(m for m in res["matches"] if m["value"] == "203.0.113.7:4444")
    assert fake["malware"] == "FakeRAT" and fake["confidence"] == 75


def test_no_matches_for_clean_summary(index):
    assert index.match_summary({"iocs": {"ips": ["8.8.8.8"]}})["matches"] == []


def test_risk_with_intel_matches():
    assert compute_risk({"threatintel": {"matches": [{"kind": "ip"}]}})["score"] == 40
    assert compute_risk({"threatintel": {"matches": [{"kind": "file_hash"}, {"kind": "ip"}]}})["score"] == 90


def test_load_missing_cache(tmp_path):
    with pytest.raises(ThreatIntelError, match="threatfox-update"):
        ThreatFoxIndex.load(tmp_path / "nope.json")


# --- auth key handling ---------------------------------------------------------
def test_auth_key_from_env_and_file(tmp_path, monkeypatch):
    monkeypatch.setenv(ti.KEY_ENV, "  envkey ")
    assert load_auth_key() == "envkey"
    f = tmp_path / "k"
    f.write_text("filekey\n")
    assert load_auth_key(str(f)) == "filekey"
    monkeypatch.delenv(ti.KEY_ENV)
    with pytest.raises(ThreatIntelError, match="no Auth-Key"):
        load_auth_key()


# --- update (network mocked; never touches the real API) ------------------------
class _Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_update_feed_writes_cache_without_key(tmp_path, monkeypatch):
    seen = {}

    def fake_urlopen(req, timeout=0):
        seen["url"], seen["headers"], seen["body"] = req.full_url, dict(req.header_items()), json.loads(req.data)
        return _Resp(json.dumps({"query_status": "ok", "data": FEED[:5]}).encode())

    monkeypatch.setattr(ti.urllib.request, "urlopen", fake_urlopen)
    cache = tmp_path / "c" / "tf.json"
    res = update_feed("SECRETKEY", days=3, cache_path=cache)
    assert res == {"ok": True, "iocs": 5, "cache": str(cache)}
    assert seen["url"] == ti.API_URL and seen["body"] == {"query": "get_iocs", "days": 3}
    assert seen["headers"]["Auth-key"] == "SECRETKEY"
    assert "SECRETKEY" not in cache.read_text()
    assert ThreatFoxIndex.load(cache).size == 5


@pytest.mark.parametrize("days", [0, 8])
def test_update_feed_days_bounds(tmp_path, days):
    with pytest.raises(ThreatIntelError):
        update_feed("k", days=days, cache_path=tmp_path / "x")


def test_update_feed_errors(tmp_path, monkeypatch):
    def http401(req, timeout=0):
        raise urllib.error.HTTPError(req.full_url, 401, "Unauthorized", {}, None)

    monkeypatch.setattr(ti.urllib.request, "urlopen", http401)
    with pytest.raises(ThreatIntelError, match="401"):
        update_feed("bad", cache_path=tmp_path / "x")

    monkeypatch.setattr(ti.urllib.request, "urlopen", lambda r, timeout=0: _Resp(b'{"query_status":"unauthorized"}'))
    with pytest.raises(ThreatIntelError, match="unauthorized"):
        update_feed("bad", cache_path=tmp_path / "x")
    assert not (tmp_path / "x").exists()


# --- pipeline / CLI -----------------------------------------------------------------
def test_analyze_one_with_threatfox(make_sample, tmp_path, index):
    p = make_sample("s.bin", b"beacon c2.evil.invalid and 198.51.100.9 end")
    summary = analyze_one(str(p), tmp_path / "out", threatintel=index)
    kinds = {m["kind"] for m in summary["threatintel"]["matches"]}
    assert kinds == {"domain", "ip"}
    assert summary["risk"]["score"] >= 40


def test_cli_threatfox_report_and_csv(make_sample, tmp_path):
    feed = tmp_path / "feed.json"
    feed.write_text(json.dumps({"fetched_at": 0, "data": FEED[:5]}))
    p = make_sample("s.bin", b"beacon c2.evil.invalid <script>")
    out = tmp_path / "out"
    main([str(p), "--out", str(out), "--quiet", "--threatfox", "--threatfox-feed", str(feed)])
    assert "ThreatFox" in (out / "report.html").read_text()
    assert "threatfox_domain" in (out / "iocs.csv").read_text()


def test_cli_threatfox_without_cache_errors(make_sample, tmp_path):
    p = make_sample("s.bin", b"x")
    with pytest.raises(SystemExit) as exc:
        main([str(p), "--out", str(tmp_path / "o"), "--quiet", "--threatfox", "--threatfox-feed", str(tmp_path / "none.json")])
    assert exc.value.code == 2


def test_cli_update_without_key_errors(tmp_path, monkeypatch):
    monkeypatch.delenv(ti.KEY_ENV, raising=False)
    with pytest.raises(SystemExit) as exc:
        main(["--threatfox-update", "--threatfox-feed", str(tmp_path / "f.json")])
    assert exc.value.code == 2
