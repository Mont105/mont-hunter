import os
import shutil
from pathlib import Path

import pytest

from monthunter import sandbox
from monthunter.cli import main
from monthunter.sandbox import (
    SandboxConfig,
    SandboxError,
    analyze_strace,
    build_qemu_command,
    parse_sections,
    parse_serial_log,
    run_sandbox,
)


@pytest.fixture
def image(tmp_path):
    p = tmp_path / "guest.qcow2"
    p.write_bytes(b"not a real image")
    return p


@pytest.fixture
def cfg(image, monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda name: f"/usr/bin/{name}")
    return SandboxConfig(image=str(image))


# --- isolation invariants ---------------------------------------------------
def test_qemu_command_is_isolated(cfg, tmp_path):
    cmd = build_qemu_command(cfg, tmp_path / "seed.iso", tmp_path / "sample.iso", tmp_path / "serial.log")
    joined = " ".join(cmd)
    assert cmd[cmd.index("-nic") + 1] == "none"  # no network device
    assert "snapshot=on" in joined  # base image is never written
    assert "-display" in cmd and cmd[cmd.index("-display") + 1] == "none"
    assert "-monitor" in cmd and cmd[cmd.index("-monitor") + 1] == "none"
    for forbidden in ("virtfs", "-fsdev", "9p", "-usb", "-net", "user", "hostfwd", "-chardev socket", "tap"):
        assert forbidden not in joined
    drives = [a for a in cmd if a.startswith("file=")]
    assert sum("readonly=on" in d for d in drives) == 2  # seed + sample CD-ROMs are read-only


def test_validate_limits(image, monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda name: f"/usr/bin/{name}")
    for bad in (
        dict(timeout=1),
        dict(timeout=sandbox.MAX_TIMEOUT + 1),
        dict(memory_mb=64),
        dict(memory_mb=sandbox.MAX_MEMORY_MB + 1),
        dict(cpus=0),
    ):
        with pytest.raises(SandboxError):
            SandboxConfig(image=str(image), **bad).validate()
    SandboxConfig(image=str(image)).validate()


def test_validate_missing_image_and_tools(tmp_path, monkeypatch):
    with pytest.raises(SandboxError, match="not found"):
        SandboxConfig(image=str(tmp_path / "nope")).validate()
    img = tmp_path / "i"
    img.write_bytes(b"x")
    monkeypatch.setattr(shutil, "which", lambda name: None)
    with pytest.raises(SandboxError, match="qemu"):
        SandboxConfig(image=str(img)).validate()


# --- parsing ----------------------------------------------------------------
STRACE = """\
100   10:00:00.000000 execve("/sbx/sample", ["/sbx/sample"], 0x7ff /* 20 vars */) = 0
100   10:00:00.100000 openat(AT_FDCWD, "/etc/passwd", O_RDONLY|O_CLOEXEC) = 3
100   10:00:00.200000 openat(AT_FDCWD, "/etc/shadow", O_RDONLY) = -1 EACCES (Permission denied)
100   10:00:00.300000 openat(AT_FDCWD, "/etc/cron.d/x", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 4
100   10:00:00.400000 connect(3, {sa_family=AF_INET, sin_port=htons(4444), sin_addr=inet_addr("203.0.113.7")}, 16) = -1 ENETUNREACH (Network is unreachable)
100   10:00:00.500000 connect(3, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("10.0.2.3")}, 16) = -1 ENETUNREACH (Network is unreachable)
100   10:00:00.600000 connect(3, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("127.0.0.1")}, 16) = 0
100   10:00:00.700000 execve("/usr/bin/curl", ["curl", "http://x"], 0x7ff) = 0
100   10:00:00.800000 unlink("/var/log/auth.log") = 0
100   10:00:00.900000 chmod("/tmp/x", 04755) = 0
100   10:00:01.000000 memfd_create("a", 0) = 5
100   10:00:01.100000 ptrace(PTRACE_ATTACH, 77) = 0
"""


def _behaviors(res):
    return {f["behavior"] for f in res["findings"]}


def test_analyze_strace_behaviours():
    res = analyze_strace(STRACE)
    assert _behaviors(res) >= {
        "persistence_write",
        "network_connection_attempt",
        "dns_lookup_attempt",
        "download_or_netcat_tool",
        "log_or_history_deletion",
        "setuid_bit_set",
        "fileless_memfd_exec",
        "process_tracing",
        "sensitive_file_access",
    }
    assert {"ip": "203.0.113.7", "port": 4444} in res["network_attempts"]
    details = " ".join(f["detail"] for f in res["findings"])
    assert "/etc/shadow" in details and "/etc/passwd" not in details  # plain passwd reads are noise
    assert "127.0.0.1:80" not in details  # loopback is not an external connection


def test_failed_syscalls_are_marked():
    res = analyze_strace('1  10:00:00.1 openat(AT_FDCWD, "/etc/cron.d/x", O_WRONLY|O_CREAT, 0666) = -1 ENOENT (No such file)')
    assert res["findings"][0]["detail"].endswith("(failed)")


def test_data_printed_by_write_cannot_spoof_findings():
    spoof = (
        '1  10:00:00.1 write(1, "openat(AT_FDCWD, \\"/etc/cron.d/x\\", O_WRONLY)\\n'
        'connect(3, {sa_family=AF_INET, sin_port=htons(4444), sin_addr=inet_addr(\\"8.8.8.8\\")}", 99) = 99\n'
        'openat(AT_FDCWD, "/etc/cron.d/y", O_WRONLY)  <- no pid/timestamp prefix, not a real strace line\n'
    )
    res = analyze_strace(spoof)
    assert res["findings"] == [] and res["network_attempts"] == []


def test_ld_preload_read_probe_is_not_a_finding():
    line = '1  10:00:00.1 access("/etc/ld.so.preload", R_OK) = -1 ENOENT (No such file or directory)'
    assert analyze_strace(line)["findings"] == []
    write = '1  10:00:00.1 openat(AT_FDCWD, "/etc/ld.so.preload", O_WRONLY|O_CREAT, 0644) = 3'
    assert _behaviors(analyze_strace(write)) == {"persistence_write"}


def serial_text(strace=STRACE, rc=0, done=True):
    def sec(name, body):
        return f"===MH_BEGIN {name}===\r\n{body}\r\n===MH_END {name}===\r\n"

    out = "boot noise\r\n" + sec("meta", f"rc={rc} elapsed=3") + sec("strace", strace) + sec("stdout", "hi")
    out += sec("ps_before", "  1 0 root init\n  2 0 root [kthreadd]")
    out += sec("ps_after", "  1 0 root init\n  2 0 root [kthreadd]\n 50 2 root [kworker/0:1]\n 99 1 root /tmp/dropper --x")
    out += sec("newfiles", "/tmp/dropped\n/etc/cron.d/x")
    return out + ("===MH_DONE===\r\n" if done else "")


def test_parse_serial_log_full():
    res = parse_serial_log(serial_text())
    assert res["ran"] and res["completed"] and res["exit_code"] == 0 and res["elapsed_s"] == 3
    assert res["new_processes"] == ["99 1 root /tmp/dropper --x"]  # kernel threads filtered
    assert res["new_files"] == ["/tmp/dropped", "/etc/cron.d/x"]
    assert res["stdout_tail"] == "hi"
    assert "persistence_write" in _behaviors(res)


def test_parse_serial_log_timeout_exit_code():
    assert parse_serial_log(serial_text(rc=124))["sample_timed_out"] is True


def test_parse_serial_log_no_agent_output():
    res = parse_serial_log("just kernel messages", timed_out=True)
    assert res["ran"] is False and res["timed_out"] is True and "reason" in res


def test_parse_sections_ignores_garbage():
    assert parse_sections("===MH_BEGIN a===\nx\n===MH_END b===") == {}


# --- orchestration with a fake QEMU ----------------------------------------
def test_run_sandbox_with_fake_qemu_cleans_up(cfg, tmp_path, monkeypatch):
    if not shutil.which("xorriso") and not Path("/usr/bin/xorriso").exists():
        pytest.skip("xorriso not installed")
    monkeypatch.undo()  # real shutil.which for xorriso; validation patched below
    monkeypatch.setattr(SandboxConfig, "validate", lambda self: None)
    captured = {}

    def fake_run(cmd, serial_log, wall_timeout, tmpdir):
        captured["cmd"] = cmd
        captured["isos"] = [Path(a.split(",")[0][5:]) for a in cmd if a.startswith("file=") and "cdrom" in a]
        captured["existed"] = [p.exists() for p in captured["isos"]]
        Path(serial_log).write_text(serial_text())
        return False

    monkeypatch.setattr(sandbox, "_run_qemu", fake_run)
    sample = tmp_path / "s.sh"
    sample.write_text("echo hi")
    res = run_sandbox(sample, SandboxConfig(image=str(tmp_path / "g.qcow2")), tmp_path / "work")

    assert res["ran"] and res["network"] == "none"
    assert captured["existed"] == [True, True]
    assert not any(p.exists() for p in captured["isos"])  # sample ISO removed afterwards
    assert not any(Path(tmp_path / "work").glob("mh_sbx_*"))
    assert (tmp_path / "work" / "serial.log").exists()


def test_run_sandbox_missing_sample(cfg, tmp_path, monkeypatch):
    monkeypatch.setattr(SandboxConfig, "validate", lambda self: None)
    with pytest.raises(SandboxError, match="sample not found"):
        run_sandbox(tmp_path / "nope", cfg, tmp_path / "w")


def test_cli_rejects_bad_sandbox_image(tmp_path, capsys):
    s = tmp_path / "a.bin"
    s.write_bytes(b"x")
    with pytest.raises(SystemExit) as exc:
        main([str(s), "--out", str(tmp_path / "o"), "--quiet", "--sandbox", str(tmp_path / "missing.qcow2")])
    assert exc.value.code == 2


def test_cli_requires_input_unless_prepare(tmp_path):
    with pytest.raises(SystemExit) as exc:
        main(["--out", str(tmp_path / "o"), "--quiet"])
    assert exc.value.code == 2


# --- real VM (opt-in): MH_SANDBOX_IMAGE=/path/to/prepared.qcow2 pytest ------
@pytest.mark.skipif(not os.environ.get("MH_SANDBOX_IMAGE"), reason="set MH_SANDBOX_IMAGE to run the real-VM test")
def test_real_vm_detonation_of_benign_script(tmp_path):
    sample = tmp_path / "benign.sh"
    sample.write_text(
        "#!/bin/sh\necho hello\nbash -c 'exec 3<>/dev/tcp/203.0.113.7/4444' 2>/dev/null\nrm -f /var/log/mh_fake.log\n"
    )
    res = run_sandbox(sample, SandboxConfig(image=os.environ["MH_SANDBOX_IMAGE"], timeout=30), tmp_path / "w")
    assert res["ran"] and res["completed"], res.get("serial_tail")
    assert {"ip": "203.0.113.7", "port": 4444} in res["network_attempts"]
    assert "hello" in res["stdout_tail"]
