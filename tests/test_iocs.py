import base64

from monthunter.detectors import extract_iocs_from_text, recursive_decode_and_scan
from monthunter.utils import (
    mh_email_class,
    mh_extract_domains_from_urls,
    mh_extract_emails,
    mh_extract_urls,
)


def test_extract_urls_ips_domains():
    text = "GET http://evil.example.org/gate.php?id=1 and 8.8.4.4 plus c2.example.net"
    res = extract_iocs_from_text(text)
    assert "http://evil.example.org/gate.php?id=1" in res["urls"]
    assert "8.8.4.4" in res["ips"]
    assert "evil.example.org" in res["domains"]
    assert "c2.example.net" in res["domains"]


def test_invalid_ip_rejected():
    assert extract_iocs_from_text("version 999.999.1.1")["ips"] == []


def test_url_with_auth_and_port_yields_host_only():
    urls = mh_extract_urls("see https://user:pw@host.example.com:8443/path")
    assert mh_extract_domains_from_urls(urls) == ["host.example.com"]


def test_emails_and_class():
    emails = mh_extract_emails("contact Bob@Gmail.com or ops@corp.example.org")
    assert emails == ["bob@gmail.com", "ops@corp.example.org"]
    assert mh_email_class("bob@gmail.com") == "free"
    assert mh_email_class("ops@corp.example.org") == "corp_or_other"


def test_base64_hidden_iocs_found():
    payload = b"connect to http://hidden.example.org/x and 8.8.4.4 now"
    blob = b"junk " + base64.b64encode(payload) + b" junk"
    res = recursive_decode_and_scan(blob)
    assert "http://hidden.example.org/x" in res["urls"]
    assert "8.8.4.4" in res["ips"]
    assert "hidden.example.org" in res["domains"]


def test_base64_nested_two_levels():
    inner = base64.b64encode(b"beacon http://nested.example.org/a now")
    outer = base64.b64encode(inner)
    res = recursive_decode_and_scan(outer)
    assert "http://nested.example.org/a" in res["urls"]


def test_base64_non_text_ignored():
    res = recursive_decode_and_scan(base64.b64encode(bytes(range(128, 256)) * 2))
    assert res == {"ips": [], "urls": [], "domains": []}


def test_file_names_are_not_domains():
    text = "LoadLibrary kernel32.dll then payload.exe, gate.php and config.json; real host c2.example.org"
    res = extract_iocs_from_text(text)
    assert res["domains"] == ["c2.example.org"]


def test_url_host_still_reported_even_if_odd():
    res = extract_iocs_from_text("http://files.example.org/kernel32.dll")
    assert "files.example.org" in res["domains"]
    assert "kernel32.dll" not in res["domains"]
