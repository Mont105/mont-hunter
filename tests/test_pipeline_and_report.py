import csv
import json

from monthunter.cli import main
from monthunter.core import MhSession, analyze_one
from monthunter.reporting import write_html_report, write_ioc_csv

SAMPLE = (
    b"MZ\x00\x00 padding Nullsoft.NSIS "
    b"http://c2.example.org/gate.php admin@gmail.com 8.8.4.4 "
    b"sekurlsa::logonpasswords\x00"
)


def test_session_detect(make_sample, tmp_path):
    p = make_sample("s.bin", SAMPLE)
    res = MhSession(p, tmp_path / "o").detect()
    assert "nsis" in res["detected"]


def test_session_detect_missing_file(tmp_path):
    res = MhSession(tmp_path / "missing", tmp_path / "o").detect()
    assert res["errors"][0]["reason"] == "file_not_found"


def test_analyze_one(make_sample, tmp_path, load_summary):
    p = make_sample("s.bin", SAMPLE)
    out = tmp_path / "out"
    summary = analyze_one(str(p), out)
    assert "nsis" in summary["detected"]
    assert "http://c2.example.org/gate.php" in summary["iocs"]["urls"]
    assert "8.8.4.4" in summary["iocs"]["ips"]
    assert "admin@gmail.com" in summary["iocs"]["emails"]
    assert any(s["rule_name"] == "THREAT_CREDENTIAL_DUMPING" for s in summary["signatures"])
    assert summary["hints"]["threat_detected"] is True
    assert summary["iocs_extra"]["risky_urls"] == ["http://c2.example.org/gate.php"]
    assert load_summary(out, summary["sha256"])["sha256"] == summary["sha256"]


def test_analyze_one_too_big_is_skipped(make_sample, tmp_path):
    p = make_sample("big.bin", b"A" * 100)
    summary = analyze_one(str(p), tmp_path / "out", max_size=10)
    assert summary["sha256"] is None
    assert summary["meta"]["skipped"] is True


def test_reports(make_sample, tmp_path):
    p = make_sample("s.bin", SAMPLE)
    out = tmp_path / "out"
    summary = analyze_one(str(p), out)
    index = {"files": [summary]}
    write_ioc_csv(index, out)
    write_html_report(index, out)

    rows = list(csv.reader((out / "iocs.csv").open(encoding="utf-8")))
    assert rows[0] == ["sha256", "path", "type", "value", "extra"]
    types_values = {(r[2], r[3]) for r in rows[1:]}
    assert ("ip", "8.8.4.4") in types_values
    assert ("email", "admin@gmail.com") in types_values

    html = (out / "report.html").read_text(encoding="utf-8")
    assert "MontHunter" in html
    assert summary["sha256"] in html
    assert "c2.example.org" in html


def test_cli_end_to_end(make_sample, tmp_path, capsys):
    p = make_sample("s.bin", SAMPLE)
    out = tmp_path / "out"
    main([str(p), "--out", str(out), "--quiet"])
    index = json.loads((out / "index.json").read_text(encoding="utf-8"))
    assert index["files"][0]["sha256"]
    assert (out / "iocs.csv").exists()
    assert (out / "report.html").exists()


def test_html_report_escapes_values(tmp_path):
    out = tmp_path / "out"
    sha = "a" * 64
    (out / "files" / sha).mkdir(parents=True)
    evil = "<script>alert(1)</script>"
    summary = {
        "iocs": {
            "urls": ["http://x.example.org/?q=<img src=x onerror=1>"],
            "emails": [f"{evil}@example.org"],
            "domains": [evil],
        },
        "hints": {evil: evil},
    }
    (out / "files" / sha / "summary.json").write_text(json.dumps({"summary": summary}), encoding="utf-8")
    write_html_report({"files": [{"sha256": sha, "path": evil + ".exe"}]}, out)
    html = (out / "report.html").read_text(encoding="utf-8")
    assert "<script>" not in html
    assert "<img" not in html
    assert "&lt;script&gt;" in html


def test_csv_cells_neutralise_formulas(tmp_path):
    out = tmp_path / "out"
    sha = "b" * 64
    (out / "files" / sha).mkdir(parents=True)
    summary = {"iocs": {"domains": ["=cmd|' /C calc'!A0", "+1", "-2", "@SUM(A1)", "ok.example.org"]}}
    (out / "files" / sha / "summary.json").write_text(json.dumps({"summary": summary}), encoding="utf-8")
    write_ioc_csv({"files": [{"sha256": sha, "path": "=evil.exe"}]}, out)
    rows = list(csv.reader((out / "iocs.csv").open(encoding="utf-8")))[1:]
    values = [r[3] for r in rows]
    assert "'=cmd|' /C calc'!A0" in values and "'+1" in values and "'-2" in values and "'@SUM(A1)" in values
    assert "ok.example.org" in values
    assert all(r[1] == "'=evil.exe" for r in rows)
    for r in rows:
        assert not r[3].startswith(("=", "+", "-", "@"))


def test_cli_with_oversized_input_does_not_crash(make_sample, tmp_path):
    p = make_sample("big.bin", b"A" * 100)
    out = tmp_path / "out"
    main([str(p), "--out", str(out), "--quiet", "--max-size", "10"])
    assert (out / "report.html").exists()
    assert (out / "iocs.csv").exists()


def test_cli_with_missing_input_does_not_crash(tmp_path):
    out = tmp_path / "out"
    main([str(tmp_path / "nope.bin"), "--out", str(out), "--quiet"])
    assert (out / "report.html").exists()


def test_unreadable_input_is_skipped_not_raised(tmp_path):
    from monthunter.utils import read_bytes

    data, meta = read_bytes(tmp_path)  # a directory
    assert data is None and meta["skipped"] is True


def test_option_like_filename_is_handled(tmp_path):
    from monthunter.utils import mh_strings_ascii

    p = tmp_path / "-n"
    p.write_bytes(b"hello_world_string")
    assert "hello_world_string" in mh_strings_ascii(p)
