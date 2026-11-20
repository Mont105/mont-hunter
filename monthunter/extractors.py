"""Extraction helpers for common packers and container formats."""

from __future__ import annotations

import shutil
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

import pefile
import math

from .utils import sh, which


def _calculate_entropy(data: bytes) -> float:
    """Return Shannon entropy (0.0–8.0) for a bytes buffer."""

    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    total = len(data)
    entropy = 0.0
    for c in counts:
        if c:
            p = c / total
            entropy -= p * math.log2(p)
    return entropy


def _extract_ascii_strings(data: bytes, min_len: int = 4) -> List[str]:
    buf: List[str] = []
    cur: List[str] = []
    for b in data:
        if 32 <= b <= 126:
            cur.append(chr(b))
        else:
            if len(cur) >= min_len:
                buf.append("".join(cur))
            cur = []
    if len(cur) >= min_len:
        buf.append("".join(cur))
    return buf


def _extract_utf16le_strings(data: bytes, min_len: int = 4) -> List[str]:
    out: List[str] = []
    cur: List[str] = []
    i = 0
    while i + 1 < len(data):
        lo, hi = data[i], data[i + 1]
        if hi == 0 and 32 <= lo <= 126:
            cur.append(chr(lo))
            i += 2
        else:
            if len(cur) >= min_len:
                out.append("".join(cur))
            cur = []
            i += 1
    if len(cur) >= min_len:
        out.append("".join(cur))
    return out


# Base API name -> reason. Names are matched after stripping the A/W/Ex suffixes (ShellExecuteExW -> ShellExecute).
RISKY_APIS = {
    "VirtualAlloc": "Memory injection",
    "VirtualAllocEx": "Process injection",
    "VirtualProtect": "Memory permission change",
    "WriteProcessMemory": "Process injection",
    "ReadProcessMemory": "Process memory access",
    "CreateRemoteThread": "Process injection",
    "NtUnmapViewOfSection": "Process hollowing",
    "QueueUserAPC": "APC injection",
    "SetThreadContext": "Thread hijacking",
    "ShellExecute": "Command execution",
    "WinExec": "Command execution",
    "InternetOpen": "Network beaconing",
    "InternetOpenUrl": "Network beaconing",
    "InternetReadFile": "Network download",
    "URLDownloadToFile": "Payload download",
    "GetAsyncKeyState": "Keylogging",
    "SetWindowsHook": "Hooking / keylogging",
    "RegSetValue": "Registry modification",
    "IsDebuggerPresent": "Anti-debugging",
    "CheckRemoteDebuggerPresent": "Anti-debugging",
    "CryptEncrypt": "Encryption (ransomware/C2)",
    "AdjustTokenPrivileges": "Privilege escalation",
}
_API_SUFFIXES = ("ExA", "ExW", "A", "W", "Ex")

_PACKER_SECTIONS = {"upx0", "upx1", "upx2", ".aspack", ".adata", ".themida", ".vmp0", ".vmp1", ".petite", ".nsp0", ".nsp1", ".mpress1", ".mpress2"}
_SCN_MEM_EXECUTE = 0x20000000
_SCN_MEM_WRITE = 0x80000000


def _risky_api_reason(name: str) -> str | None:
    if name in RISKY_APIS:
        return RISKY_APIS[name]
    for suf in _API_SUFFIXES:
        if name.endswith(suf) and name[: -len(suf)] in RISKY_APIS:
            return RISKY_APIS[name[: -len(suf)]]
    return None


def analyze_pe_structure(file_path: str | Path, *, min_len: int = 4, max_bytes: int = 8_000_000) -> Dict[str, Any]:
    """Parse a PE file for metadata and extract ASCII/UTF-16LE strings."""

    path = Path(file_path)
    result: Dict[str, Any] = {
        "ok": False,
        "is_pe": False,
        "is_dotnet": False,
        "sections": [],
        "compile_time": None,
        "pdb_path": None,
        "packed_score": None,
        "risky_apis": [],
        "anomalies": [],
        "imphash": None,
        "overlay_size": 0,
        "strings": [],
    }

    try:
        with path.open("rb") as fh:
            head = fh.read(2)
        if head != b"MZ":
            result["reason"] = "not_pe"
            return result
    except FileNotFoundError:
        result["reason"] = "not_found"
        return result
    except Exception as exc:  # pragma: no cover - defensive
        result["reason"] = str(exc)
        return result

    try:
        pe = pefile.PE(str(path), fast_load=True)
        pe.parse_data_directories(
            directories=[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DEBUG"],
            ]
        )
    except Exception as exc:  # pragma: no cover - defensive
        result["reason"] = f"parse_error:{exc}"
        return result

    try:
        result["is_pe"] = True
        result["compile_time"] = datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp, tz=timezone.utc).isoformat()

        section_infos: List[Dict[str, Any]] = []
        max_entropy = 0.0
        for s in getattr(pe, "sections", []) or []:
            sec_name = s.Name.decode("utf-8", errors="ignore").strip("\x00")
            data = s.get_data() or b""
            ent = _calculate_entropy(data)
            max_entropy = max(max_entropy, ent)
            section_infos.append({"name": sec_name, "entropy": ent, "suspicious_packed": ent > 7.2})
            chars = int(getattr(s, "Characteristics", 0))
            if chars & _SCN_MEM_EXECUTE and chars & _SCN_MEM_WRITE:
                result["anomalies"].append(f"rwx_section:{sec_name}")
            if sec_name.lower() in _PACKER_SECTIONS:
                result["anomalies"].append(f"packer_section:{sec_name}")
        result["sections"] = section_infos
        result["packed_score"] = max_entropy

        imports = []
        risky_hits: List[Dict[str, str]] = []
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
            dll_name = entry.dll.decode("utf-8", errors="ignore") if hasattr(entry, "dll") else ""
            imports.append(dll_name.lower())
            for imp in getattr(entry, "imports", []) or []:
                name = imp.name.decode("utf-8", errors="ignore") if getattr(imp, "name", None) else ""
                reason = _risky_api_reason(name)
                if reason:
                    risky_hits.append({"api": name, "risk": reason})
        result["is_dotnet"] = any("mscoree.dll" == dll for dll in imports)
        if not imports:
            result["anomalies"].append("no_imports")
        ts = pe.FILE_HEADER.TimeDateStamp
        if ts == 0 or ts > time.time() + 86400:
            result["anomalies"].append("suspicious_timestamp")
        try:
            result["imphash"] = pe.get_imphash() or None
        except Exception:
            pass
        try:
            overlay_off = pe.get_overlay_data_start_offset()
            if overlay_off:
                result["overlay_size"] = max(0, path.stat().st_size - overlay_off)
                if result["overlay_size"] >= 1024 * 1024:
                    result["anomalies"].append("large_overlay")
        except Exception:
            pass
        if risky_hits:
            seen = set()
            uniq_hits = []
            for item in risky_hits:
                key = item["api"]
                if key in seen:
                    continue
                seen.add(key)
                uniq_hits.append(item)
            result["risky_apis"] = uniq_hits

        try:
            pdb_path = None
            for dbg in getattr(pe, "DIRECTORY_ENTRY_DEBUG", []) or []:
                data = pe.get_data(dbg.struct.AddressOfRawData, dbg.struct.SizeOfData)
                if not data or data[:4] != b"RSDS":
                    continue
                try:
                    pdb_path = data[24:].split(b"\x00", 1)[0].decode("utf-8", errors="ignore")
                    if pdb_path:
                        break
                except Exception:
                    continue
            if pdb_path:
                result["pdb_path"] = pdb_path
        except Exception:
            pass
    finally:
        try:
            pe.close()
        except Exception:
            pass

    try:
        with path.open("rb") as fh:
            raw = fh.read(max_bytes)
    except Exception as exc:  # pragma: no cover - defensive
        result["reason"] = f"read_error:{exc}"
        return result

    ascii_strings = _extract_ascii_strings(raw, min_len=min_len)
    utf16_strings = _extract_utf16le_strings(raw, min_len=min_len)
    dedup = sorted(set(ascii_strings + utf16_strings))

    result.update({"ok": True, "strings": dedup})
    return result


MAX_EXTRACT_FILES = 10_000
MAX_EXTRACT_BYTES = 1024 * 1024 * 1024  # 1 GiB


def _remove(p: Path) -> None:
    """Delete a file, symlink or directory without following symlinks."""
    try:
        if p.is_symlink() or not p.is_dir():
            p.unlink(missing_ok=True)
        else:
            shutil.rmtree(p, ignore_errors=True)
    except Exception:
        # Last-resort cleanup; ignore failures
        pass


def _sanitize_tree(
    base: Path,
    max_files: int = MAX_EXTRACT_FILES,
    max_bytes: int = MAX_EXTRACT_BYTES,
) -> Dict[str, Any]:
    """Remove symlinks and paths escaping the extraction root, and enforce size/count limits.

    Files beyond ``max_files`` or beyond a cumulative ``max_bytes`` are deleted.
    Returns ``{"files": kept, "bytes": kept_bytes, "removed": n, "truncated": bool}``.
    """
    base = Path(base)
    root = base.resolve()

    # Pass 1: drop symlinks and anything resolving outside the root (deepest first).
    for p in sorted(base.rglob("*"), key=lambda x: len(str(x)), reverse=True):
        try:
            if p.is_symlink() or not p.resolve().is_relative_to(root):
                _remove(p)
        except Exception:
            _remove(p)

    # Pass 2: enforce limits in a deterministic order.
    kept_files = 0
    kept_bytes = 0
    removed = 0
    for p in sorted(base.rglob("*")):
        try:
            if not p.is_file():
                continue
            size = p.stat().st_size
        except OSError:
            continue
        if kept_files + 1 > max_files or kept_bytes + size > max_bytes:
            _remove(p)
            removed += 1
            continue
        kept_files += 1
        kept_bytes += size

    return {"files": kept_files, "bytes": kept_bytes, "removed": removed, "truncated": removed > 0}


def ex_pyinstaller(path: str, out_dir: Path, timeout: int = 360) -> Dict[str, Any]:
    """Run pyinstxtractor over a suspected PyInstaller executable and optionally decompile .pyc files."""
    exe = which("pyinstxtractor") or which("pyinstxtractor.py") or which("pyinstxtractor-ng")
    result: Dict[str, Any] = {"ok": False, "tool": exe, "dir": None}
    if not exe:
        result["reason"] = "pyinstxtractor missing"
        return result

    out_dir = Path(out_dir)
    res = sh([exe, path], timeout=timeout, cwd=out_dir)
    result.update(
        {
            "ok": res["ok"],
            "rc": res["rc"],
            "stdout": (res["out"] or "")[-1000:],
            "stderr": (res["err"] or "")[-1000:],
        }
    )

    cand_name = Path(path).with_suffix("").name + "_extracted"
    for base in (Path(path).parent, out_dir):
        candidate = base / cand_name
        if candidate.exists():
            result["dir"] = str(candidate)
            result["sanitize"] = _sanitize_tree(candidate)
            break

    # Best-effort decompilation is intentionally omitted here; handled by higher-level tooling if needed.
    return result


def ex_upx(path: str, out_dir: Path, timeout: int = 360) -> Dict[str, Any]:
    """Attempt to unpack a UPX-compressed binary into out_dir/upx_unpacked_<name>."""
    if not which("upx"):
        return {"ok": False, "reason": "upx missing"}

    out_dir = Path(out_dir)
    tmp = out_dir / ("upx_unpacked_" + Path(path).name)
    shutil.copy2(path, tmp)
    res = sh(["upx", "-d", str(tmp)], timeout=timeout)
    return {
        "ok": res["ok"],
        "rc": res["rc"],
        "unpacked": str(tmp) if res["ok"] else None,
        "stderr": (res["err"] or "")[-300:],
    }


def ex_7z(path: str, out_dir: Path, timeout: int = 360) -> Dict[str, Any]:
    """Generic extraction using 7z into out_dir/sevenzip."""
    if not which("7z"):
        return {"ok": False, "reason": "7z missing"}

    out_dir = Path(out_dir)
    target = out_dir / "sevenzip"
    target.mkdir(parents=True, exist_ok=True)
    res = sh(["7z", "x", "-y", f"-o{str(target)}", path], timeout=timeout)
    sanitize = _sanitize_tree(target)
    return {
        "ok": res["ok"],
        "rc": res["rc"],
        "dir": str(target),
        "sanitize": sanitize,
        "stdout": (res["out"] or "")[-800:],
        "stderr": (res["err"] or "")[-800:],
    }


def ex_inno(path: str, out_dir: Path, timeout: int = 360) -> Dict[str, Any]:
    """Extract Inno Setup installers, falling back to 7z when needed."""
    if which("innoextract"):
        target = Path(out_dir) / "inno"
        target.mkdir(parents=True, exist_ok=True)
        res = sh(["innoextract", "-d", str(target), path], timeout=timeout)
        sanitize = _sanitize_tree(target)
        return {
            "ok": res["ok"],
            "rc": res["rc"],
            "dir": str(target),
            "sanitize": sanitize,
            "stdout": (res["out"] or "")[-800:],
            "stderr": (res["err"] or "")[-800:],
        }
    return ex_7z(path, out_dir, timeout=timeout)


def ex_cab(path: str, out_dir: Path, timeout: int = 360) -> Dict[str, Any]:
    """Extract Microsoft CAB archives, falling back to 7z when needed."""
    if which("cabextract"):
        target = Path(out_dir) / "cab"
        target.mkdir(parents=True, exist_ok=True)
        res = sh(["cabextract", "-d", str(target), path], timeout=timeout)
        sanitize = _sanitize_tree(target)
        return {
            "ok": res["ok"],
            "rc": res["rc"],
            "dir": str(target),
            "sanitize": sanitize,
            "stdout": (res["out"] or "")[-800:],
            "stderr": (res["err"] or "")[-800:],
        }
    return ex_7z(path, out_dir, timeout=timeout)


def ex_asar_search(out_dir: Path, timeout: int = 360) -> Dict[str, Any]:
    """Search for and extract Electron app.asar files under out_dir."""
    asar = which("asar")
    if not asar:
        return {"ok": False, "reason": "asar missing"}

    out_dir = Path(out_dir)
    for ap in out_dir.rglob("app.asar"):
        res = sh(["asar", "extract", str(ap), str(Path(ap).with_suffix(""))], timeout=timeout)
        if res["ok"]:
            extracted = Path(ap).with_suffix("")
            return {"ok": True, "dir": str(extracted), "sanitize": _sanitize_tree(extracted)}
    return {"ok": False, "reason": "app.asar not found after extraction"}
