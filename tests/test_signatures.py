import json

from monthunter.detectors import scan_with_json_signatures
from monthunter.utils import mh_hint_flags

REAL_SIGS = __import__("pathlib").Path(__file__).parents[1] / "monthunter" / "signatures.json"


def _write(tmp_path, rules):
    p = tmp_path / "sigs.json"
    p.write_text(json.dumps({"rules": rules}), encoding="utf-8")
    return p


def test_min_matches_threshold(tmp_path):
    p = _write(tmp_path, [{"name": "R", "severity": "HIGH", "min_matches": 2, "strings": ["alpha", "beta"]}])
    assert scan_with_json_signatures(p, ["only ALPHA here"]) == []
    hits = scan_with_json_signatures(p, ["alpha and Beta"])
    assert [h["rule_name"] for h in hits] == ["R"]
    assert hits[0]["severity"] == "HIGH"
    assert hits[0]["score"] == 2


def test_missing_or_bad_file(tmp_path):
    assert scan_with_json_signatures(tmp_path / "nope.json", ["x"]) == []
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    assert scan_with_json_signatures(bad, ["x"]) == []


def test_real_database_detects_mimikatz():
    hits = scan_with_json_signatures(REAL_SIGS, ["sekurlsa::logonpasswords"])
    assert "THREAT_CREDENTIAL_DUMPING" in [h["rule_name"] for h in hits]


def test_real_database_clean_text():
    assert scan_with_json_signatures(REAL_SIGS, ["hello world, nothing to see"]) == []


def test_hint_flags():
    flags = mh_hint_flags(["powershell -e AAAA and https://x.example.org"])
    assert flags["hint_powershell_b64"] is True
    assert flags["hint_http_activity"] is True
    assert flags["hint_lolbins"] is False
    clean = mh_hint_flags(["nothing"])
    assert not any(clean.values())


def _names(text):
    return {h["rule_name"] for h in scan_with_json_signatures(REAL_SIGS, [text])}


def test_njrat_not_triggered_by_generic_dotnet_strings():
    assert "MALWARE_FAMILY_njRAT" not in _names("System.Runtime.CompilerServices svchost.exe diablo")


def test_njrat_triggered_by_specific_strings():
    text = "SEE_MASK_NOZONECHECKS netsh firewall add allowedprogram cmd.exe /c ping 0 -n 2"
    assert "MALWARE_FAMILY_njRAT" in _names(text)


def test_redline_not_triggered_by_ordinary_browser_strings():
    text = "Login Data Web Data Cookies Local State User Data Extension os_crypt encrypted_key"
    assert "MALWARE_FAMILY_REDLINE_STEALER" not in _names(text)


def test_redline_triggered_by_stealer_strings():
    assert "MALWARE_FAMILY_REDLINE_STEALER" in _names("Discord Token Metamask Exodus os_crypt")


def test_generic_words_do_not_set_powershell_hint():
    assert mh_hint_flags(["hidden bypass window, hidden files"])["hint_powershell_b64"] is False
    assert mh_hint_flags(["powershell -w hidden -nop"])["hint_powershell_b64"] is True


def test_email_hint_needs_real_email():
    assert mh_hint_flags(["see example.com @ home"])["hint_email_refs"] is False
    assert mh_hint_flags(["a@b.example.com"])["hint_email_refs"] is True


def test_generic_windows_api_strings_do_not_trigger_wiper_or_ransomware():
    text = (
        "WriteFile CloseHandle DeviceIoControl DeleteFileW RijndaelManaged AesCryptoServiceProvider "
        "MiniDumpWriteDump WDigest s3.amazonaws.com herokuapp.com .lock .enc procdump wget -O"
    )
    assert _names(text) == set()


def test_specific_destructive_strings_still_detected():
    assert "THREAT_DESTRUCTIVE_WIPER" in _names("\\\\.\\PhysicalDrive0")
    assert "SUSP_RANSOMWARE_BEHAVIOR" in _names("wbadmin delete catalog -quiet")
