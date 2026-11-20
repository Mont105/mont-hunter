"""Dynamic analysis in a disposable QEMU virtual machine (Linux guests).

Safety model (all enforced in code, none optional):

* The guest has **no network device** (``-nic none``).
* The guest disk is opened with ``snapshot=on``: nothing is ever written to the base image.
* No shared folders, no USB, no display, no clipboard. The sample reaches the guest as a
  read-only CD-ROM and results come back only through the serial console.
* The VM is killed after a hard wall-clock timeout and always powers off at the end.

You must supply a *prepared* guest image (see :func:`prepare_image`). Windows guests are not
supported by the built-in agent: it is a POSIX shell script driven by cloud-init.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Tuple

SERIAL_BEGIN = "===MH_BEGIN {}==="
_SECTION_RE = re.compile(r"===MH_BEGIN (\w+)===\r?\n(.*?)===MH_END \1===", re.S)

# Hard ceilings so a hostile or buggy sample cannot make the host work forever.
MAX_TIMEOUT = 900
MAX_MEMORY_MB = 8192
BOOT_GRACE = 240  # seconds allowed for boot + cloud-init on top of the sample timeout
MAX_SERIAL_BYTES = 8 * 1024 * 1024


class SandboxError(RuntimeError):
    pass


@dataclass
class SandboxConfig:
    image: str
    timeout: int = 120
    memory_mb: int = 1024
    cpus: int = 2
    qemu: str = "qemu-system-x86_64"
    guest_os: str = "auto"  # auto | linux | windows
    winvm: bool = False  # run Windows samples in the real-Windows lab (outer VM -> inner Windows VM) instead of Wine
    winlab_dir: str = "/home/mhlab/winlab"
    winlab_user: str = "mhlab"

    def validate(self) -> None:
        if self.image and not Path(self.image).is_file():
            raise SandboxError(f"guest image not found: {self.image}")
        if not self.image and not self.winvm:
            raise SandboxError("a guest image is required (or use the Windows VM lab)")
        if not 5 <= self.timeout <= MAX_TIMEOUT:
            raise SandboxError(f"timeout must be between 5 and {MAX_TIMEOUT} seconds")
        if not 256 <= self.memory_mb <= MAX_MEMORY_MB:
            raise SandboxError(f"memory must be between 256 and {MAX_MEMORY_MB} MB")
        if not 1 <= self.cpus <= 8:
            raise SandboxError("cpus must be between 1 and 8")
        if self.guest_os not in ("auto", "linux", "windows"):
            raise SandboxError("guest_os must be auto, linux or windows")
        if self.winvm:
            if shutil.which("sudo") is None:
                raise SandboxError("sudo not found (needed to run the lab as its unprivileged user)")
            chk = subprocess.run(
                ["sudo", "-n", "-u", self.winlab_user, "test", "-x", f"{self.winlab_dir}/winlab.sh"],
                capture_output=True,
            )
            if chk.returncode != 0:
                raise SandboxError(f"Windows lab not available ({self.winlab_dir}/winlab.sh as {self.winlab_user})")
            return None if not self.image else self._validate_tools()
        self._validate_tools()

    def _validate_tools(self) -> None:
        if shutil.which(self.qemu) is None:
            raise SandboxError(f"{self.qemu} not found in PATH")
        if shutil.which("xorriso") is None:
            raise SandboxError("xorriso not found in PATH (needed to build the seed/sample ISOs)")


# --------------------------------------------------------------------------
# Guest-side agent (runs inside the VM, driven by cloud-init)
# --------------------------------------------------------------------------

_GUEST_SCRIPT = r"""#!/bin/sh
# MontHunter guest agent. Output goes to the serial console only.
exec >/dev/ttyS0 2>&1
T=__TIMEOUT__
MODE=__MODE__
KIND=__KIND__
emit() { echo "===MH_BEGIN $1==="; tail -c 400000; echo; echo "===MH_END $1==="; }
mkdir -p /sbx /mnt/sample
mount -o ro /dev/disk/by-label/SAMPLE /mnt/sample || { echo "mount failed" | emit error; poweroff -f; }
touch /sbx/.marker
ps -eo pid,ppid,user,args > /sbx/ps_before
START=$(date +%s)
if [ "$MODE" = "wine" ]; then
  # Windows sample, run under Wine in a pristine pre-built prefix.
  mkdir -p /run/mh && chmod 700 /run/mh
  export XDG_RUNTIME_DIR=/run/mh WINEPREFIX=/root/.wine WINEDLLOVERRIDES='winemenubuilder.exe=d'
  export WINEDEBUG='-all,+process,+winsock'
  cp /mnt/sample/sample.bin /sbx/sample.$KIND
  cp /root/.wine/user.reg /sbx/user.reg.before 2>/dev/null
  cp /root/.wine/system.reg /sbx/system.reg.before 2>/dev/null
  if [ "$KIND" = "dll" ]; then CMD="wine rundll32 /sbx/sample.dll,DllMain"; else CMD="wine /sbx/sample.exe"; fi
  # NOTE: not wrapped in strace: "strace -f wine" takes the whole guest down. Wine's own debug channels
  # (+process, +winsock) give Win32-level visibility instead.
  echo "strace not used in wine mode" > /sbx/strace.log
  timeout -k 5 $T $CMD </dev/null >/sbx/stdout 2>/sbx/windebug.log
  RC=$?
  timeout 20 wineserver -k 2>/dev/null; sleep 2
  python3 /usr/local/bin/mh-regdiff.py /sbx/user.reg.before /root/.wine/user.reg > /sbx/winreg 2>/dev/null
  python3 /usr/local/bin/mh-regdiff.py /sbx/system.reg.before /root/.wine/system.reg >> /sbx/winreg 2>/dev/null
  find /root/.wine/drive_c -newer /sbx/.marker -type f 2>/dev/null | head -500 > /sbx/winfiles
else
  cp /mnt/sample/sample.bin /sbx/sample
  chmod 755 /sbx/sample
  if head -c 4 /sbx/sample | grep -q 'ELF' || head -c 2 /sbx/sample | grep -q '#!'; then
    CMD=/sbx/sample
  else
    CMD="sh /sbx/sample"
  fi
  if command -v strace >/dev/null 2>&1; then
    timeout -k 5 $T strace -f -tt -s 256 -o /sbx/strace.log $CMD </dev/null >/sbx/stdout 2>&1
  else
    echo "strace not installed in guest image" > /sbx/strace.log
    timeout -k 5 $T $CMD </dev/null >/sbx/stdout 2>&1
  fi
  RC=$?
fi
END=$(date +%s)
ps -eo pid,ppid,user,args > /sbx/ps_after
find / -xdev -newer /sbx/.marker -type f ! -path '/sbx/*' ! -path '/proc/*' ! -path '/sys/*' \
  ! -path '/var/log/*' ! -path '/run/*' ! -path '/var/lib/cloud/*' ! -path '/root/.wine/*' ! -path '/root/.cache/*' 2>/dev/null | head -500 > /sbx/newfiles
echo "rc=$RC elapsed=$((END-START)) mode=$MODE" | emit meta
# Only security-relevant syscalls go over the serial console (a raw strace of a chatty sample is huge).
grep -a -E ' (execve|connect|open|openat|unlink|unlinkat|chmod|fchmodat|ptrace|memfd_create)\(' /sbx/strace.log | head -20000 | emit strace
emit stdout < /sbx/stdout
emit ps_before < /sbx/ps_before
emit ps_after < /sbx/ps_after
emit newfiles < /sbx/newfiles
if [ "$MODE" = "wine" ]; then
  # Only the few relevant Wine debug lines go over the serial console (the raw log can be huge).
  grep -a -E 'CreateProcessInternalW app|winsock:(WSA)?[Cc]onnect socket|winsock:gethostbyname|winsock:getaddrinfo node' /sbx/windebug.log | head -3000 | emit windebug
  emit winreg < /sbx/winreg
  emit winfiles < /sbx/winfiles
fi
echo "===MH_DONE==="
poweroff -f
"""

# Prints registry keys/values present in the "after" Wine registry file but not in the "before" one.
_REGDIFF_SCRIPT = r"""import sys


def parse(path):
    items, key = set(), None
    try:
        fh = open(path, encoding="utf-8", errors="replace")
    except OSError:
        return items
    with fh:
        for line in fh:
            line = line.rstrip("\n")
            if line.startswith("["):
                key = line[1:].split("]")[0]
                items.add((key, ""))
            elif key is not None and line and not line.startswith(("#", "WINE REGISTRY")):
                items.add((key, line))
    return items


before, after = parse(sys.argv[1]), parse(sys.argv[2])
for key, val in sorted(after - before)[:3000]:
    print(key + "\t" + val)
"""


def _indent(text: str, n: int = 6) -> str:
    return "\n".join(" " * n + line for line in text.splitlines())


def _user_data_run(timeout: int, mode: str = "linux", kind: str = "exe") -> str:
    script = (
        _GUEST_SCRIPT.replace("__TIMEOUT__", str(int(timeout)))
        .replace("__MODE__", mode if mode in ("linux", "wine") else "linux")
        .replace("__KIND__", kind if kind in ("exe", "dll") else "exe")
    )
    return (
        "#cloud-config\n"
        "write_files:\n"
        "  - path: /usr/local/bin/mh-regdiff.py\n"
        "    permissions: '0755'\n"
        "    content: |\n"
        f"{_indent(_REGDIFF_SCRIPT)}\n"
        "  - path: /usr/local/bin/mh-run.sh\n"
        "    permissions: '0755'\n"
        "    content: |\n"
        f"{_indent(script)}\n"
        "runcmd:\n"
        "  - [ /usr/local/bin/mh-run.sh ]\n"
    )


_PREPARE_BASE = (
    "pacman -Sy --noconfirm --needed strace binutils file python > /dev/ttyS0 2>&1; "
    # Sandbox runs have no NIC: do not wait for network/time sync at boot (it blocks multi-user.target and
    # therefore cloud-init's final stage), and stop cloud-init from configuring one.
    "mkdir -p /etc/cloud/cloud.cfg.d; "
    "echo 'network: {config: disabled}' > /etc/cloud/cloud.cfg.d/99-mh-nonet.cfg; "
    "systemctl mask systemd-networkd-wait-online.service NetworkManager-wait-online.service "
    "systemd-time-wait-sync.service systemd-timesyncd.service > /dev/ttyS0 2>&1; "
)

# Windows support = Wine inside the Linux guest (no Windows licence or image needed).
# The prefix is created now, so every sandbox run starts from a ready-made, pristine prefix.
_PREPARE_WINE = (
    "pacman -S --noconfirm --needed wine wine-mono > /dev/ttyS0 2>&1; "
    "WINEPREFIX=/root/.wine WINEDEBUG=-all WINEDLLOVERRIDES='winemenubuilder.exe=d' wineboot -i > /dev/ttyS0 2>&1; "
    "WINEPREFIX=/root/.wine wineserver -w; "
    "test -f /root/.wine/user.reg && echo MH_WINE_OK > /dev/ttyS0; "
)

_PREPARE_END = "command -v strace > /dev/ttyS0 && echo MH_PREPARE_OK > /dev/ttyS0; cloud-init clean --logs; poweroff -f"


def _user_data_prepare(with_wine: bool) -> str:
    script = _PREPARE_BASE + (_PREPARE_WINE if with_wine else "") + _PREPARE_END
    return '#cloud-config\nruncmd:\n  - [ sh, -c, "' + script.replace('"', '\\"') + '" ]\n'


# --------------------------------------------------------------------------
# Host-side helpers
# --------------------------------------------------------------------------


def _make_iso(out: Path, label: str, files: Dict[str, Path | str]) -> None:
    """Build a small ISO9660 image. ``files`` maps name-in-iso -> source path or literal text."""
    staging = Path(tempfile.mkdtemp(prefix="mh_iso_", dir=out.parent))
    try:
        for name, src in files.items():
            dest = staging / name
            if isinstance(src, Path):
                shutil.copyfile(src, dest)
            else:
                dest.write_text(src, encoding="utf-8")
        res = subprocess.run(
            ["xorriso", "-as", "mkisofs", "-quiet", "-V", label, "-J", "-r", "-o", str(out), str(staging)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=60,
        )
        if res.returncode != 0:
            raise SandboxError(f"xorriso failed: {res.stderr.strip()[-300:]}")
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def detect_sample_os(path: str | Path) -> Tuple[str, str]:
    """Return ``(os, kind)``: ("windows", "exe"|"dll") for PE files, otherwise ("linux", "exe")."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(4096)
    except OSError:
        return "linux", "exe"
    if head[:2] == b"MZ" and len(head) >= 0x40:
        e_lfanew = int.from_bytes(head[0x3C:0x40], "little")
        if 0x40 <= e_lfanew <= len(head) - 24 and head[e_lfanew : e_lfanew + 4] == b"PE\x00\x00":
            characteristics = int.from_bytes(head[e_lfanew + 22 : e_lfanew + 24], "little")
            return "windows", "dll" if characteristics & 0x2000 else "exe"
    return "linux", "exe"


def _accel_args() -> List[str]:
    if os.access("/dev/kvm", os.R_OK | os.W_OK):
        return ["-machine", "q35,accel=kvm", "-cpu", "host"]
    return ["-machine", "q35,accel=tcg", "-cpu", "max"]


def build_qemu_command(cfg: SandboxConfig, seed_iso: Path, sample_iso: Path | None, serial_log: Path) -> List[str]:
    """Return the QEMU argv. Isolation flags live here and nowhere else."""
    cmd = [cfg.qemu, "-name", "monthunter-sandbox"]
    cmd += _accel_args()
    cmd += ["-m", str(cfg.memory_mb), "-smp", str(cfg.cpus)]
    cmd += ["-display", "none", "-monitor", "none", "-no-reboot", "-nodefaults", "-vga", "none"]
    cmd += ["-serial", f"file:{serial_log}"]
    cmd += ["-nic", "none"]  # no network device at all
    cmd += ["-drive", f"file={cfg.image},if=virtio,format=qcow2,snapshot=on"]  # never writes to the base image
    cmd += ["-drive", f"file={seed_iso},media=cdrom,readonly=on"]
    if sample_iso is not None:
        cmd += ["-drive", f"file={sample_iso},media=cdrom,readonly=on"]
    return cmd


def _run_qemu(cmd: List[str], serial_log: Path, wall_timeout: int, tmpdir: Path) -> bool:
    """Run QEMU; return True if it had to be killed for exceeding the wall-clock limit."""
    env = dict(os.environ, TMPDIR=str(tmpdir))  # snapshot overlay is created here, then discarded
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)
    try:
        proc.wait(timeout=wall_timeout)
        timed_out = False
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        timed_out = True
    return timed_out


def prepare_image(
    image: str,
    *,
    qemu: str = "qemu-system-x86_64",
    timeout: int = 1800,
    memory_mb: int = 2048,
    with_wine: bool = False,
) -> Dict[str, Any]:
    """Install the guest-side tooling (strace) into ``image``. This is the ONLY step that uses networking.

    It boots with QEMU user-mode (NAT) networking so pacman can download packages, and it
    persistently modifies ``image``. Run it only on a dedicated copy of the official cloud
    image, never with a sample attached; the sandbox runs themselves have no network at all.
    """
    cfg = SandboxConfig(image=image, qemu=qemu, memory_mb=memory_mb)
    cfg.validate()
    work = Path(tempfile.mkdtemp(prefix="mh_prepare_"))
    try:
        seed = work / "seed.iso"
        _make_iso(seed, "cidata", {"user-data": _user_data_prepare(with_wine), "meta-data": f"instance-id: mh-prepare-{uuid.uuid4().hex}\nlocal-hostname: mh-prepare\n"})
        serial = work / "serial.log"
        cmd = [qemu, "-name", "monthunter-prepare"] + _accel_args()
        cmd += ["-m", str(memory_mb), "-smp", "2", "-display", "none", "-monitor", "none", "-no-reboot", "-nodefaults", "-vga", "none"]
        cmd += ["-serial", f"file:{serial}"]
        cmd += ["-nic", "user,model=virtio-net-pci"]
        cmd += ["-drive", f"file={image},if=virtio,format=qcow2"]
        cmd += ["-drive", f"file={seed},media=cdrom,readonly=on"]
        timed_out = _run_qemu(cmd, serial, timeout, work)
        log = serial.read_text(encoding="utf-8", errors="replace") if serial.exists() else ""
        ok = "MH_PREPARE_OK" in log and (not with_wine or "MH_WINE_OK" in log)
        return {"ok": ok and not timed_out, "timed_out": timed_out, "log_tail": log[-1500:]}
    finally:
        shutil.rmtree(work, ignore_errors=True)


# --------------------------------------------------------------------------
# Result parsing (pure functions, unit-testable without a VM)
# --------------------------------------------------------------------------

_PERSISTENCE_PATHS = (
    "/etc/cron",
    "/var/spool/cron",
    "/etc/systemd/system",
    "/usr/lib/systemd/system",
    "/etc/rc.local",
    "/etc/init.d",
    "/etc/ld.so.preload",
    "/.bashrc",
    "/.profile",
    "/.ssh/authorized_keys",
    "/.config/autostart",
)
_SENSITIVE_PATHS = ("/etc/shadow", "/etc/passwd", "/etc/sudoers", "/.ssh/id_", "/.bash_history")
_LOG_PATHS = ("/var/log/", "/.bash_history")

# One strace line: "<pid>  <hh:mm:ss.us> syscall(args...) = ret". Parsing is anchored on the syscall
# name so data merely *printed* by read()/write() cannot be mistaken for a syscall.
_LINE_RE = re.compile(r"^\s*\d+\s+[\d:.]+\s+(\w+)\((.*)$")
_FAILED_RE = re.compile(r"\)\s+=\s+-1\s+[A-Z]+")
_V4_RE = re.compile(r'sin_port=htons\((\d+)\), sin_addr=inet_addr\("([^"]+)"\)')
_V6_RE = re.compile(r'sin6_port=htons\((\d+)\), sin6_flowinfo=[^,]+, inet_pton\(AF_INET6, "([^"]+)"')
_EXEC_ARGS_RE = re.compile(r'^"([^"]+)", \[(.*?)\], ')
_OPEN_ARGS_RE = re.compile(r'^(?:AT_FDCWD|\d+), "([^"]+)", ([A-Z_|]+)')
_PATH_ARG_RE = re.compile(r'^(?:AT_FDCWD, )?"([^"]+)"')
_CHMOD_ARGS_RE = re.compile(r'^(?:AT_FDCWD, )?"([^"]+)", (0?[0-7]{3,4})')
_WRITE_FLAGS = ("O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND")
_WRITE_ONLY_SENSITIVE = ("/etc/passwd",)  # every process reads it; only writes are interesting


def parse_sections(serial_text: str) -> Dict[str, str]:
    """Split the guest's serial output into its named sections."""
    return {name: body.strip("\n") for name, body in _SECTION_RE.findall(serial_text.replace("\r\n", "\n"))}


def _is_private_or_loopback(ip: str) -> bool:
    return ip.startswith(("127.", "10.", "192.168.", "169.254.")) or ip in ("::1", "0.0.0.0") or bool(re.match(r"172\.(1[6-9]|2\d|3[01])\.", ip))


def analyze_strace(text: str) -> Dict[str, Any]:
    """Turn a raw strace log into behaviours, network attempts and executed commands."""
    findings: List[Dict[str, Any]] = []
    seen: set = set()
    network: List[Dict[str, Any]] = []
    commands: List[str] = []

    def add(behavior: str, detail: str, mitre: List[str]) -> None:
        key = (behavior, detail)
        if key not in seen and len(findings) < 200:
            seen.add(key)
            findings.append({"behavior": behavior, "detail": detail[:300], "mitre": mitre})

    for line in text.splitlines():
        m = _LINE_RE.match(line)
        if not m:
            continue
        name, rest = m.group(1), m.group(2)
        failed = bool(_FAILED_RE.search(rest))
        note = " (failed)" if failed else ""

        if name == "connect":
            hit = _V4_RE.search(rest) or _V6_RE.search(rest)
            if not hit:
                continue
            port, ip = int(hit.group(1)), hit.group(2)
            entry = {"ip": ip, "port": port}
            if entry not in network and len(network) < 100:
                network.append(entry)
            if port == 53:
                add("dns_lookup_attempt", f"{ip}:53", ["T1071.004"])
            elif not _is_private_or_loopback(ip):
                add("network_connection_attempt", f"{ip}:{port}", ["T1071"])

        elif name == "execve":
            hit = _EXEC_ARGS_RE.match(rest)
            if not hit:
                continue
            binary, args = hit.group(1), hit.group(2)
            cmd = f"{binary} {args}"[:300]
            if cmd not in commands and len(commands) < 100:
                commands.append(cmd)
            if re.search(r"(^|/)(curl|wget|nc|ncat|socat|tftp)$", binary):
                add("download_or_netcat_tool", cmd, ["T1105"])
            if re.search(r"/(bash|sh|dash)$", binary) and '"-c"' in args:
                add("shell_command_execution", cmd, ["T1059.004"])
            if re.search(r"(^|/)(crontab|systemctl|chattr|iptables|ufw|setenforce)$", binary):
                add("system_configuration_change", cmd, ["T1543", "T1562"])

        elif name in ("openat", "open"):
            hit = _OPEN_ARGS_RE.match(rest)
            if not hit:
                continue
            path, flags = hit.group(1), hit.group(2)
            writing = any(f in flags for f in _WRITE_FLAGS)
            if writing and any(p in path for p in _PERSISTENCE_PATHS):
                mitre = ["T1053.003", "T1543.002", "T1546.004"]
                if path.endswith("ld.so.preload"):
                    mitre = ["T1574.006"]
                add("persistence_write", path + note, mitre)
            elif any(p in path for p in _SENSITIVE_PATHS):
                if path in _WRITE_ONLY_SENSITIVE and not writing:
                    continue
                add("sensitive_file_access", f"{path} ({'write' if writing else 'read'}){note}", ["T1003.008", "T1552.004"])

        elif name in ("unlink", "unlinkat"):
            hit = _PATH_ARG_RE.match(rest)
            if hit and any(p in hit.group(1) for p in _LOG_PATHS):
                add("log_or_history_deletion", hit.group(1) + note, ["T1070.002"])

        elif name in ("chmod", "fchmodat"):
            hit = _CHMOD_ARGS_RE.match(rest)
            if hit:
                mode = hit.group(2).lstrip("0")
                if len(mode) == 4 and mode[0] in "46":
                    add("setuid_bit_set", f"{hit.group(1)} {hit.group(2)}{note}", ["T1548.001"])

        elif name == "ptrace":
            if re.match(r"PTRACE_(ATTACH|SEIZE|POKE\w*)", rest):
                add("process_tracing", rest.split(",")[0], ["T1055.008"])

        elif name == "memfd_create":
            add("fileless_memfd_exec", "memfd_create", ["T1620"])

    return {"findings": findings, "network_attempts": network, "commands": commands}


_WINE_NOISE_PROCS = (
    "winemenubuilder.exe", "services.exe", "winedevice.exe", "plugplay.exe", "svchost.exe -k", "rpcss.exe",
    "explorer.exe /desktop", "wineboot.exe", "conhost.exe", "start.exe /exec",
)
_WIN_CREATEPROC_RE = re.compile(r'trace:process:CreateProcessInternalW app (?:\(null\)|L"[^"]*") cmdline L"((?:[^"\\]|\\.)*)"')
_WIN_CONNECT_RE = re.compile(r"trace:winsock:(?:WSA)?[Cc]onnect socket \S+, addr \{ family AF_INET6?, address ([0-9a-fA-F:.]+), port (\d+) \}")
_WIN_DNS_RE = re.compile(r'trace:winsock:(?:gethostbyname "([^"]+)"|getaddrinfo node "([^"]+)")')
_WIN_DROP_EXT = (".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".lnk", ".sys")
_WIN_LOCAL_NAMES = {"localhost", "mh-sandbox"}


def _win_cmdline(raw: str) -> str:
    return raw.replace("\\\\", "\\")


def _win_path(unix_path: str) -> str:
    marker = "/drive_c/"
    i = unix_path.find(marker)
    return "C:\\" + unix_path[i + len(marker):].replace("/", "\\") if i >= 0 else unix_path


def _classify_cmdline(cmd: str, add) -> None:
    """Flag well-known abuse patterns in a Windows command line (shared by the Wine and real-Windows engines)."""
    low = cmd.lower()
    if re.search(r"powershell(\.exe)?\b.*\s-e(nc(odedcommand)?)?\s", low):
        add("encoded_powershell", cmd, ["T1059.001", "T1027"])
    elif re.search(r"(^|[\\\s])(powershell|pwsh)(\.exe)?\b", low):
        add("powershell_execution", cmd, ["T1059.001"])
    if re.search(r"(vssadmin(\.exe)?\s+delete\s+shadows|wmic(\.exe)?\s+shadowcopy\s+delete|wbadmin(\.exe)?\s+delete)", low):
        add("shadow_copy_deletion", cmd, ["T1490"])
    elif re.search(r"schtasks(\.exe)?\s+/create", low):
        add("scheduled_task_creation", cmd, ["T1053.005"])
    elif re.search(r"netsh(\.exe)?\s+(advfirewall|firewall)", low):
        add("firewall_modification", cmd, ["T1562.004"])
    elif re.search(r"\breg(\.exe)?\s+add\b.*\\run", low):
        add("persistence_registry_run", cmd, ["T1547.001"])
    elif re.search(r"(^|[\\\s])(rundll32|regsvr32|mshta|certutil|bitsadmin|wscript|cscript|msbuild|installutil|cmstp)(\.exe)?\b", low):
        add("lolbin_execution", cmd, ["T1218"])


def analyze_windows(sections: Dict[str, str]) -> Dict[str, Any]:
    """Behaviours observed while running a Windows sample under Wine: Win32 debug channels,
    a before/after registry diff and the list of files created in the Wine C: drive."""
    findings: List[Dict[str, Any]] = []
    seen: set = set()
    network: List[Dict[str, Any]] = []
    commands: List[str] = []
    dns: List[str] = []

    def add(behavior: str, detail: str, mitre: List[str]) -> None:
        key = (behavior, detail)
        if key not in seen and len(findings) < 200:
            seen.add(key)
            findings.append({"behavior": behavior, "detail": detail[:300], "mitre": mitre})

    for line in sections.get("windebug", "").splitlines():
        m = _WIN_CREATEPROC_RE.search(line)
        if m:
            cmd = _win_cmdline(m.group(1))
            low = cmd.lower()
            if any(n in low for n in _WINE_NOISE_PROCS) or cmd in commands:
                continue
            if len(commands) < 100:
                commands.append(cmd)
            add("process_creation", cmd, ["T1106"])
            _classify_cmdline(cmd, add)
            continue
        m = _WIN_CONNECT_RE.search(line)
        if m:
            ip, port = m.group(1), int(m.group(2))
            entry = {"ip": ip, "port": port}
            if entry not in network and len(network) < 100:
                network.append(entry)
            if port == 53:
                add("dns_lookup_attempt", f"{ip}:53", ["T1071.004"])
            elif not _is_private_or_loopback(ip):
                add("network_connection_attempt", f"{ip}:{port}", ["T1071"])
            continue
        m = _WIN_DNS_RE.search(line)
        if m:
            name = (m.group(1) or m.group(2) or "").lower().rstrip(".")
            if name and name not in _WIN_LOCAL_NAMES and name not in dns and len(dns) < 100:
                dns.append(name)
                add("dns_lookup_attempt", name, ["T1071.004"])

    for raw in sections.get("winreg", "").splitlines():
        key, _, val = raw.partition("\t")
        key = key.replace("\\\\", "\\")
        low = key.lower()
        if low.startswith(("software\\wine", "volatile environment")) or not val:
            continue
        shown = f"{key} {val}".replace("\\\\", "\\")
        if re.search(r"\\currentversion\\run(once|services)?(ex)?$", low):
            add("persistence_registry_run", shown, ["T1547.001"])
        elif "\\currentcontrolset\\services\\" in low and low.rsplit("\\", 1)[-1] not in ("enum",):
            add("service_registered", shown, ["T1543.003"])
        elif "image file execution options" in low:
            add("ifeo_hijack", shown, ["T1546.012"])
        elif low.endswith("\\winlogon") and re.search(r'"(shell|userinit)"=', val, re.I):
            add("winlogon_hijack", shown, ["T1547.004"])
        elif "windows defender" in low:
            add("defender_tampering", shown, ["T1562.001"])
        elif low.endswith("\\policies\\system") or low.endswith("\\policies\\explorer"):
            add("policy_tampering", shown, ["T1112"])

    new_files: List[str] = []
    for raw in sections.get("winfiles", "").splitlines():
        win = _win_path(raw.strip())
        if not win or win in new_files:
            continue
        low = win.lower()
        if "\\windows\\temp\\" in low and low.endswith(".log"):
            continue
        new_files.append(win)
        if "\\start menu\\programs\\startup\\" in low:
            add("startup_folder_drop", win, ["T1547.001"])
        elif low.endswith(_WIN_DROP_EXT):
            add("dropped_executable", win, ["T1105"])
    return {"findings": findings, "network_attempts": network, "commands": commands, "dns_queries": dns, "new_files": new_files[:200]}


_WINVM_NOISE_PROCS = {
    "conhost.exe", "wmiprvse.exe", "shutdown.exe", "wevtutil.exe", "backgroundtaskhost.exe", "taskhostw.exe",
    "dllhost.exe", "sppsvc.exe", "searchprotocolhost.exe", "searchfilterhost.exe", "tiworker.exe", "mpcmdrun.exe",
}
_WINVM_NOISE_FILES = ("__psscriptpolicytest_", "\\microsoft\\windows\\powershell\\", "\\appdata\\local\\temp\\mh", "\\sbx\\sample")


def analyze_winvm(sections: Dict[str, str]) -> Dict[str, Any]:
    """Behaviours observed in the real Windows VM: process creation (Security 4688 with command lines),
    persistence artefacts (Run keys, services, scheduled tasks, WMI, startup folder) and dropped files."""
    findings: List[Dict[str, Any]] = []
    seen: set = set()
    commands: List[str] = []

    def add(behavior: str, detail: str, mitre: List[str]) -> None:
        key = (behavior, detail)
        if key not in seen and len(findings) < 300:
            seen.add(key)
            findings.append({"behavior": behavior, "detail": detail[:300], "mitre": mitre})

    for line in sections.get("winproc", "").splitlines():
        image, _, cmd = line.partition("|")
        name = image.rsplit("\\", 1)[-1].lower()
        cmd = (cmd or image).strip()
        if name in _WINVM_NOISE_PROCS or "c:\\mh\\agent.ps1" in cmd.lower() or "mhsetup.ps1" in cmd.lower():
            continue
        if cmd in commands or len(commands) >= 100:
            continue
        commands.append(cmd)
        add("process_creation", cmd, ["T1106"])
        _classify_cmdline(cmd, add)

    for line in sections.get("winreg", "").splitlines():
        key, _, val = line.partition("|")
        low = key.lower()
        shown = f"{key}|{val}"
        if re.search(r"\\currentversion\\run(once|services)?(ex)?$", low):
            add("persistence_registry_run", shown, ["T1547.001"])
        elif key == "IFEO":
            add("ifeo_hijack", val, ["T1546.012"])
        elif low.endswith("\\winlogon"):
            add("winlogon_hijack", shown, ["T1547.004"])

    for line in sections.get("winsvc", "").splitlines():
        if line.strip():
            add("service_registered", line, ["T1543.003"])
    for line in sections.get("wintask", "").splitlines():
        if line.strip():
            add("scheduled_task_creation", line, ["T1053.005"])
    for line in sections.get("winwmi", "").splitlines():
        if line.strip():
            add("wmi_persistence", line, ["T1546.003"])
    for line in sections.get("winstartup", "").splitlines():
        if line.strip():
            add("startup_folder_drop", line, ["T1547.001"])

    new_files: List[str] = []
    for line in sections.get("winfiles", "").splitlines():
        path = line.partition("|")[0].strip()
        low = path.lower()
        if not path or any(n in low for n in _WINVM_NOISE_FILES) or path in new_files:
            continue
        new_files.append(path)
        if low.endswith(_WIN_DROP_EXT):
            add("dropped_executable", path, ["T1105"])
    return {"findings": findings, "network_attempts": [], "commands": commands, "dns_queries": [], "new_files": new_files[:200]}


def _diff_processes(before: str, after: str) -> List[str]:
    base = set(before.splitlines())
    kernel_thread = re.compile(r"^\s*\d+\s+\d+\s+\S+\s+\[")
    return [
        ln.strip()
        for ln in after.splitlines()
        if ln not in base and "ps -eo" not in ln and not kernel_thread.match(ln)
    ][:100]


def parse_serial_log(serial_text: str, timed_out: bool = False) -> Dict[str, Any]:
    """Build the ``dynamic`` summary from a serial console capture."""
    sections = parse_sections(serial_text)
    result: Dict[str, Any] = {"ran": "meta" in sections, "timed_out": timed_out, "completed": "===MH_DONE===" in serial_text}
    if not result["ran"]:
        result["reason"] = "guest agent produced no results (image not prepared, boot failure or timeout)"
        result["serial_tail"] = serial_text[-1000:]
        return result

    meta = dict(re.findall(r"(\w+)=(\S+)", sections.get("meta", "")))
    rc = meta.get("rc")
    result["exit_code"] = int(rc) if rc and rc.lstrip("-").isdigit() else None
    result["sample_timed_out"] = result["exit_code"] == 124
    result["elapsed_s"] = int(meta["elapsed"]) if meta.get("elapsed", "").isdigit() else None

    if meta.get("mode") == "winvm":
        result["strace_available"] = False
        result.update(analyze_winvm(sections))
        result["new_processes"] = []
        result["stdout_tail"] = ""
        return result

    if meta.get("mode") == "wine":
        result["strace_available"] = False
        result.update(analyze_windows(sections))
        result["new_processes"] = []  # Wine's own helper processes would only be noise
        result["stdout_tail"] = sections.get("stdout", "")[-2000:]
        return result

    strace_text = sections.get("strace", "")
    result["strace_available"] = "strace not installed" not in strace_text
    result.update(analyze_strace(strace_text))
    result["new_processes"] = _diff_processes(sections.get("ps_before", ""), sections.get("ps_after", ""))
    result["new_files"] = [ln for ln in sections.get("newfiles", "").splitlines() if ln][:200]
    result["stdout_tail"] = sections.get("stdout", "")[-2000:]
    return result


# --------------------------------------------------------------------------
# Public entry point
# --------------------------------------------------------------------------


def run_winvm(sample: Path, kind: str, cfg: SandboxConfig, workdir: Path) -> Dict[str, Any]:
    """Detonate a Windows sample in the real-Windows lab. The lab script runs as the unprivileged lab user;
    it verifies the sealed images, builds disposable layers, and prints the serial results on stdout."""
    if shutil.which("xorriso") is None:
        raise SandboxError("xorriso not found in PATH")
    # World-readable staging dir (the lab user cannot read the caller's home); holds only the sample ISO.
    stage = Path(tempfile.mkdtemp(prefix="mh_winvm_", dir="/tmp"))
    try:
        os.chmod(stage, 0o755)
        content = stage / "content"
        content.mkdir()
        shutil.copyfile(sample, content / "sample.bin")
        (content / "run.cfg").write_text(f"timeout={int(cfg.timeout)}\nkind={kind}\n", encoding="utf-8")
        iso = stage / "sample.iso"
        res = subprocess.run(
            ["xorriso", "-as", "mkisofs", "-quiet", "-V", "SAMPLE", "-J", "-r", "-o", str(iso), str(content)],
            capture_output=True, text=True, timeout=120,
        )
        if res.returncode != 0:
            raise SandboxError(f"xorriso failed: {res.stderr.strip()[-300:]}")
        os.chmod(iso, 0o644)
        proc = subprocess.run(
            ["sudo", "-n", "-u", cfg.winlab_user, f"{cfg.winlab_dir}/winlab.sh", "run", str(iso), str(int(cfg.timeout))],
            capture_output=True, text=True, timeout=cfg.timeout + 1500, errors="replace",
        )
        text = proc.stdout[:MAX_SERIAL_BYTES]
        workdir.mkdir(parents=True, exist_ok=True)
        (workdir / "serial.log").write_text(text, encoding="utf-8")
        result = parse_serial_log(text, timed_out=False)
        if "VERIFY FAIL" in proc.stderr:
            result["ran"] = False
            result["reason"] = "image integrity check failed: " + proc.stderr.strip()[-300:]
        result.update({"serial_log": str(workdir / "serial.log"), "network": "none", "guest_os": "windows", "engine": "winvm"})
        return result
    except subprocess.TimeoutExpired:
        return {"ran": False, "timed_out": True, "reason": "Windows lab run exceeded its time limit", "engine": "winvm", "guest_os": "windows"}
    finally:
        shutil.rmtree(stage, ignore_errors=True)


def run_sandbox(sample: str | Path, cfg: SandboxConfig, workdir: str | Path) -> Dict[str, Any]:
    """Detonate ``sample`` in a throw-away VM and return the behavioural summary."""
    cfg.validate()
    sample = Path(sample)
    if not sample.is_file():
        raise SandboxError(f"sample not found: {sample}")
    workdir = Path(workdir)
    workdir.mkdir(parents=True, exist_ok=True)

    if cfg.winvm and cfg.guest_os != "linux":
        det_os, det_kind = detect_sample_os(sample)
        if det_os == "windows":
            return run_winvm(sample, det_kind, cfg, workdir)
        if not cfg.image:
            raise SandboxError("sample is not a Windows PE and no Linux guest image was given (--sandbox IMAGE)")

    tmp = Path(tempfile.mkdtemp(prefix="mh_sbx_", dir=workdir))
    try:
        seed = tmp / "seed.iso"
        sample_iso = tmp / "sample.iso"
        sample_os, kind = detect_sample_os(sample) if cfg.guest_os == "auto" else (cfg.guest_os, "exe")
        if cfg.guest_os == "windows" and detect_sample_os(sample)[0] == "windows":
            kind = detect_sample_os(sample)[1]
        mode = "wine" if sample_os == "windows" else "linux"
        _make_iso(
            seed,
            "cidata",
            {
                "user-data": _user_data_run(cfg.timeout, mode, kind),
                "meta-data": f"instance-id: mh-run-{uuid.uuid4().hex}\nlocal-hostname: mh-sandbox\n",
            },
        )
        _make_iso(sample_iso, "SAMPLE", {"sample.bin": sample})
        serial_log = workdir / "serial.log"
        serial_log.unlink(missing_ok=True)

        cmd = build_qemu_command(cfg, seed, sample_iso, serial_log)
        timed_out = _run_qemu(cmd, serial_log, cfg.timeout + BOOT_GRACE, tmp)

        text = ""
        if serial_log.exists():
            with serial_log.open("rb") as fh:
                text = fh.read(MAX_SERIAL_BYTES).decode("utf-8", errors="replace")
        result = parse_serial_log(text, timed_out=timed_out)
        result["serial_log"] = str(serial_log)
        result["image"] = str(cfg.image)
        result["network"] = "none"
        result["guest_os"] = sample_os
        result["engine"] = "wine" if mode == "wine" else "native"
        return result
    finally:
        shutil.rmtree(tmp, ignore_errors=True)  # removes the sample ISO and the snapshot overlay
