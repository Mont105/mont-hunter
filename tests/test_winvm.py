import subprocess
from pathlib import Path

import pytest

from monthunter import sandbox
from monthunter.cli import main
from monthunter.sandbox import SandboxConfig, SandboxError, analyze_winvm, parse_serial_log, run_sandbox
from monthunter.scoring import compute_risk

from .helpers import build_minimal_pe

PROC = "\n".join(
    [
        r"C:\sbx\sample.exe|C:\sbx\sample.exe",
        r"C:\Windows\System32\cmd.exe|cmd.exe /c vssadmin delete shadows /all /quiet",
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe|powershell -nop -w hidden -enc SQBFAFgA",
        r"C:\Windows\System32\schtasks.exe|schtasks /create /tn Upd /tr C:\x.exe /sc onlogon",
        r"C:\Windows\System32\conhost.exe|\??\C:\Windows\system32\conhost.exe 0x4",
        r"C:\Windows\System32\wbem\WmiPrvSE.exe|C:\Windows\system32\wbem\wmiprvse.exe -secured",
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe|powershell -File C:\mh\agent.ps1",
    ]
)
REG = "\n".join(
    [
        r"HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run|Updater=C:\Users\mh\AppData\Roaming\u.exe",
        r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce|x=C:\y.exe",
        r"IFEO|taskmgr.exe=C:\evil.exe",
        r"HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon|Shell=evil.exe",
    ]
)
SECTIONS = {
    "winproc": PROC,
    "winreg": REG,
    "winsvc": r"EvilSvc|C:\evil.exe",
    "wintask": r"\Upd|C:\x.exe ",
    "winwmi": "CommandLineEventConsumer|bad",
    "winstartup": r"C:\Users\mh\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\a.lnk",
    "winfiles": "\n".join(
        [
            r"C:\Users\mh\AppData\Roaming\u.exe|1234",
            r"C:\Users\mh\notes.txt|5",
            r"C:\Users\mh\AppData\Local\Temp\__PSScriptPolicyTest_abc.ps1|1",
            r"C:\sbx\sample.exe|99",
        ]
    ),
}


def _b(res):
    return {f["behavior"] for f in res["findings"]}


def test_analyze_winvm_behaviours():
    res = analyze_winvm(SECTIONS)
    assert _b(res) >= {
        "process_creation", "shadow_copy_deletion", "encoded_powershell", "scheduled_task_creation",
        "persistence_registry_run", "ifeo_hijack", "winlogon_hijack", "service_registered", "wmi_persistence",
        "startup_folder_drop", "dropped_executable",
    }


def test_analyze_winvm_filters_lab_noise():
    res = analyze_winvm(SECTIONS)
    text = " ".join(f["detail"] for f in res["findings"]).lower()
    assert "conhost" not in text and "wmiprvse" not in text and "agent.ps1" not in text
    assert "__psscriptpolicytest" not in text and "notes.txt" not in text
    assert not any("sample.exe" in p.lower() for p in res["new_files"])


def serial(mode="winvm"):
    def sec(n, b):
        return f"===MH_BEGIN {n}===\r\n{b}\r\n===MH_END {n}===\r\n"

    return (
        sec("outer", "outer_rc=0 outer_elapsed=200")
        + sec("meta", f"rc=0 elapsed=12 mode={mode} kind=exe")
        + "".join(sec(k, v) for k, v in SECTIONS.items())
        + "===MH_DONE===\r\n"
    )


def test_parse_serial_log_winvm():
    res = parse_serial_log(serial())
    assert res["ran"] and res["completed"] and res["network_attempts"] == []
    assert "persistence_registry_run" in _b(res)


def test_risk_scores_winvm_findings():
    res = parse_serial_log(serial())
    assert compute_risk({"dynamic": res})["score"] >= 40


# --- configuration / orchestration ----------------------------------------------------------
def test_winvm_config_needs_no_image_but_needs_the_lab(monkeypatch):
    monkeypatch.setattr(sandbox.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a, 1, b"", b""))
    monkeypatch.setattr(sandbox.shutil, "which", lambda n: f"/usr/bin/{n}")
    with pytest.raises(SandboxError, match="Windows lab not available"):
        SandboxConfig(image="", winvm=True).validate()
    monkeypatch.setattr(sandbox.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a, 0, b"", b""))
    SandboxConfig(image="", winvm=True).validate()
    with pytest.raises(SandboxError, match="image is required"):
        SandboxConfig(image="").validate()


def test_run_sandbox_routes_pe_to_winvm_and_never_touches_stdin(tmp_path, monkeypatch):
    if not sandbox.shutil.which("xorriso"):
        pytest.skip("xorriso not installed")
    monkeypatch.setattr(SandboxConfig, "validate", lambda self: None)
    calls = []

    def fake_run(cmd, **kw):
        if cmd[0] == "sudo":
            calls.append(cmd)
            return subprocess.CompletedProcess(cmd, 0, serial(), "")
        return real_run(cmd, **kw)

    real_run = subprocess.run
    monkeypatch.setattr(sandbox.subprocess, "run", fake_run)
    sample = tmp_path / "s.exe"
    sample.write_bytes(build_minimal_pe())
    res = run_sandbox(sample, SandboxConfig(image="", winvm=True, timeout=30), tmp_path / "w")
    assert res["engine"] == "winvm" and res["guest_os"] == "windows" and res["ran"]
    cmd = calls[0]
    assert cmd[:4] == ["sudo", "-n", "-u", "mhlab"] and cmd[4].endswith("/winlab.sh") and cmd[5] == "run" and cmd[-1] == "30"
    assert not list(Path("/tmp").glob("mh_winvm_*")), "staging dir must be removed"


def test_linux_sample_without_image_is_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(SandboxConfig, "validate", lambda self: None)
    s = tmp_path / "a.sh"
    s.write_text("echo hi")
    with pytest.raises(SandboxError, match="not a Windows PE"):
        run_sandbox(s, SandboxConfig(image="", winvm=True), tmp_path / "w")


def test_integrity_failure_is_reported_not_run(tmp_path, monkeypatch):
    if not sandbox.shutil.which("xorriso"):
        pytest.skip("xorriso not installed")
    monkeypatch.setattr(SandboxConfig, "validate", lambda self: None)
    real_run = subprocess.run
    monkeypatch.setattr(
        sandbox.subprocess, "run",
        lambda cmd, **kw: subprocess.CompletedProcess(cmd, 1, "", "VERIFY FAIL: checksum mismatch for x") if cmd[0] == "sudo" else real_run(cmd, **kw),
    )
    s = tmp_path / "s.exe"
    s.write_bytes(build_minimal_pe())
    res = run_sandbox(s, SandboxConfig(image="", winvm=True), tmp_path / "w")
    assert res["ran"] is False and "integrity" in res["reason"]


def test_cli_accepts_winvm_flag_without_image(tmp_path, monkeypatch):
    s = tmp_path / "a.bin"
    s.write_bytes(b"x")
    monkeypatch.setattr(sandbox.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a, 1, b"", b""))
    with pytest.raises(SystemExit) as exc:
        main([str(s), "--out", str(tmp_path / "o"), "--quiet", "--sandbox-winvm"])
    assert exc.value.code == 2  # lab not available -> clean argparse error
