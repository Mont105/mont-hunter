"""Generic utilities and helpers used across MontHunter modules."""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

# Email and IOC-related constants
_FREE_EMAIL_DOMAINS = {
    "gmail.com",
    "yahoo.com",
    "outlook.com",
    "hotmail.com",
    "live.com",
    "aol.com",
    "icloud.com",
    "proton.me",
    "protonmail.com",
    "yandex.com",
    "yandex.ru",
    "gmx.com",
    "gmx.net",
    "zoho.com",
    "fastmail.com",
    "tutanota.com",
    "mail.com",
}

_SUSP_POWERSHELL_PATTERNS = (
    "powershell -e",
    "powershell.exe -e",
    "frombase64string(",
    "iex(",
    "invoke-webrequest",
    "downloadstring",
    "add-mppreference",
    "-nop",
    "-w hidden",
)

_SUSP_LOLBINS = (
    "rundll32",
    "regsvr32",
    "mshta",
    "wmic",
    "certutil",
    "bitsadmin",
    "cmstp",
    "msbuild",
    "msiexec",
    "wscript",
    "cscript",
    "installutil",
    "forfiles",
    "scriptrunner",
)

_URL_RE = re.compile(
    r"""
    (?:
        (?:(?:https?|ftp)://)           # scheme
        (?:[\w\-]+(?::[\w\-.~%!$&'()*+,;=:]+)?@)?  # auth (optional)
        (?:[A-Za-z0-9\-\._~%]+)       # host (simplified)
        (?::\d{2,5})?                  # port (optional)
        (?:/[A-Za-z0-9\-\._~%!$&'()*+,;=:@/]*)?   # path
        (?:\?[A-Za-z0-9\-\._~%!$&'()*+,;=:@/?]*)? # query
        (?:\#[A-Za-z0-9\-\._~%!$&'()*+,;=:@/?]*)? # fragment
    )
    """,
    re.X,
)

_EMAIL_RE = re.compile(
    r"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,63}\b"
)


def which(name: str) -> str | None:
    """Return the full path of an executable if it exists in PATH."""
    return shutil.which(name)


def sh(
    cmd: Iterable[str],
    timeout: int | None = 240,
    cwd: Path | None = None,
    env: Dict[str, str] | None = None,
) -> Dict[str, Any]:
    """Run a subprocess and capture stdout/stderr in a friendly dict."""
    try:
        proc = subprocess.run(
            list(cmd),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            cwd=str(cwd) if cwd is not None else None,
            env=env,
        )
        return {
            "ok": proc.returncode == 0,
            "rc": proc.returncode,
            "out": proc.stdout,
            "err": proc.stderr,
        }
    except Exception as exc:  # pragma: no cover - defensive
        return {"ok": False, "rc": -1, "out": "", "err": str(exc)}


def read_bytes(path: Path, max_size: int | None = None) -> Tuple[bytes | None, Dict[str, Any] | None]:
    """Read bytes from path in chunks, optionally enforcing a max size.

    Returns a tuple ``(data, meta)`` where:
    - data is the raw bytes (or None if skipped)
    - meta contains optional ``{"skipped": True, "reason": "..."} `` info
    """
    chunk_size = 1024 * 1024
    try:
        size = path.stat().st_size
    except FileNotFoundError:
        return None, {"skipped": True, "reason": "file_not_found"}
    except OSError as exc:
        return None, {"skipped": True, "reason": f"unreadable:{exc}"}

    if max_size is not None and size > max_size:
        return None, {"skipped": True, "reason": f"size>{max_size}"}

    buf = bytearray()
    try:
        with path.open("rb") as fh:
            while True:
                chunk = fh.read(chunk_size)
                if not chunk:
                    break
                buf.extend(chunk)
                if max_size is not None and len(buf) > max_size:
                    return None, {"skipped": True, "reason": f"size>{max_size}"}
    except OSError as exc:
        return None, {"skipped": True, "reason": f"unreadable:{exc}"}
    return bytes(buf), None


def mh_read_bytes(path: Path, max_bytes: int = 8_000_000) -> bytes:
    """Compact reader used for string extraction."""
    try:
        with path.open("rb") as fh:
            return fh.read(max_bytes)
    except Exception:
        return b""


def mh_strings_ascii(path: Path, min_len: int = 4) -> str:
    """Extract ASCII strings using the system 'strings' tool or a pure-Python fallback."""
    txt = ""
    if which("strings"):
        try:
            res = sh(["strings", "-a", "-n", str(min_len), "--", str(path)], timeout=90)
            if res.get("ok"):
                txt = res.get("out", "")
        except Exception:
            txt = ""
    if not txt:
        raw = mh_read_bytes(path)
        cur: list[str] = []
        chunks: list[str] = []
        for b in raw:
            if 32 <= b <= 126:
                cur.append(chr(b))
            else:
                if len(cur) >= min_len:
                    chunks.append("".join(cur))
                cur = []
        if len(cur) >= min_len:
            chunks.append("".join(cur))
        txt = "\n".join(chunks)
    return txt


def mh_strings_utf16le(path: Path, min_len: int = 4) -> str:
    """Extract UTF-16LE strings (Windows Unicode) with tool or fallback."""
    txt = ""
    if which("strings"):
        try:
            res = sh(["strings", "-a", "-el", "-n", str(min_len), "--", str(path)], timeout=90)
            if res.get("ok"):
                txt = res.get("out", "")
        except Exception:
            txt = ""
    if not txt:
        raw = mh_read_bytes(path)
        chars: list[str] = []
        out: list[str] = []
        i = 0
        while i + 1 < len(raw):
            lo, hi = raw[i], raw[i + 1]
            if hi == 0 and 32 <= lo <= 126:
                chars.append(chr(lo))
                i += 2
            else:
                if len(chars) >= min_len:
                    out.append("".join(chars))
                chars = []
                i += 1
        if len(chars) >= min_len:
            out.append("".join(chars))
        txt = "\n".join(out)
    return txt


def mh_extract_urls(text: str) -> List[str]:
    """Return a de-duplicated, sorted list of URL-like strings."""
    try:
        return sorted({m.group(0) for m in _URL_RE.finditer(text)})[:1000]
    except Exception:
        return []


def mh_extract_emails(text: str) -> List[str]:
    """Return a de-duplicated, sorted list of email addresses."""
    try:
        return sorted({m.group(0).lower() for m in _EMAIL_RE.finditer(text)})[:1000]
    except Exception:
        return []


def mh_email_class(email: str) -> str:
    """Classify an email as coming from a free provider or not."""
    dom = email.split("@")[-1].lower()
    return "free" if dom in _FREE_EMAIL_DOMAINS else "corp_or_other"


def mh_extract_domains_from_urls(urls: List[str]) -> List[str]:
    """Extract hostnames from a URL list and return a unique list."""
    hosts: List[str] = []
    for u in urls:
        try:
            host = u.split("://", 1)[1].split("/", 1)[0]
            if "@" in host:
                host = host.split("@", 1)[1]
            host = host.split(":", 1)[0]
            if host:
                hosts.append(host.lower())
        except Exception:
            continue
    return sorted(set(hosts))[:1000]


def mh_hint_flags(texts: List[str]) -> Dict[str, bool]:
    """Compute simple boolean flags based on suspicious patterns in text."""
    t = "\n".join(texts).lower()
    return {
        "hint_powershell_b64": any(s in t for s in (x.lower() for x in _SUSP_POWERSHELL_PATTERNS)),
        "hint_lolbins": any((" " + x + " ") in (" " + t + " ") for x in _SUSP_LOLBINS),
        "hint_http_activity": ("http://" in t) or ("https://" in t),
        "hint_email_refs": _EMAIL_RE.search(t) is not None,
    }


def fuzzy_hash(path: Path, timeout: int = 60) -> str | None:
    """Return the ssdeep fuzzy hash of a file, or None if ssdeep is unavailable."""
    exe = which("ssdeep")
    if not exe:
        return None
    res = sh([exe, "-b", "--", str(Path(path).resolve())], timeout=timeout)
    if not res.get("ok"):
        return None
    lines = (res.get("out") or "").splitlines()
    if len(lines) < 2 or "," not in lines[1]:
        return None
    return lines[1].rsplit(",", 1)[0] or None
