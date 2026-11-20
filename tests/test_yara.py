from pathlib import Path

import pytest

from monthunter import detectors


@pytest.fixture
def fake_yara(monkeypatch):
    """Replace the yara CLI: record invocations, never run anything."""
    calls = []

    def fake_sh(cmd, timeout=None, cwd=None, env=None):
        cmd = list(cmd)
        rules = Path(cmd[-2])
        calls.append({"cmd": cmd, "rules_text": rules.read_text(encoding="utf-8") if rules.exists() else None})
        return {"ok": True, "rc": 0, "out": f"RuleA {cmd[-1]}\n", "err": ""}

    monkeypatch.setattr(detectors, "_yara_exec", lambda: "/fake/yara")
    monkeypatch.setattr(detectors, "sh", fake_sh)
    return calls


def test_rules_file_is_passed_directly(tmp_path, fake_yara):
    rules = tmp_path / "r.yar"
    rules.write_text("rule A { condition: true }")
    target = tmp_path / "t.bin"
    target.write_bytes(b"x")
    res = detectors.yara_scan(str(rules), [target])
    assert res["ok"] and res["count"] == 1
    assert fake_yara[0]["cmd"] == ["/fake/yara", str(rules), str(target)]


def test_directory_scanned_once_not_per_file(tmp_path, fake_yara):
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "a.yar").write_text("rule A { condition: true }")
    (rules / "b.yara").write_text("rule B { condition: true }")
    (rules / "notes.txt").write_text("ignore me")
    target = tmp_path / "extracted"
    target.mkdir()
    for i in range(20):
        (target / f"f{i}").write_bytes(b"x")

    res = detectors.yara_scan(str(rules), [target])

    assert len(fake_yara) == 1  # one yara run for 20 files
    assert fake_yara[0]["cmd"][1] == "-r"
    text = fake_yara[0]["rules_text"]
    assert "a.yar" in text and "b.yara" in text and "notes.txt" not in text
    assert res["ok"] is True


def test_empty_rules_dir(tmp_path, fake_yara):
    rules = tmp_path / "rules"
    rules.mkdir()
    res = detectors.yara_scan(str(rules), [tmp_path])
    assert res["ok"] is False and fake_yara == []


def test_missing_rules_path(tmp_path, fake_yara):
    assert detectors.yara_scan(str(tmp_path / "nope"), [tmp_path])["ok"] is False


def test_yara_missing(monkeypatch, tmp_path):
    monkeypatch.setattr(detectors, "_yara_exec", lambda: None)
    assert detectors.yara_scan(str(tmp_path), [tmp_path])["ok"] is False


def test_yara_failure_is_reported(monkeypatch, tmp_path):
    rules = tmp_path / "r.yar"
    rules.write_text("garbage")
    monkeypatch.setattr(detectors, "_yara_exec", lambda: "/fake/yara")
    monkeypatch.setattr(detectors, "sh", lambda *a, **k: {"ok": False, "rc": 1, "out": "", "err": "syntax error"})
    res = detectors.yara_scan(str(rules), [rules])
    assert res["ok"] is False and "syntax error" in res["errors"][0]
