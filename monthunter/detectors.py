"""Detection and IOC-related helpers (packers, languages, YARA, etc.)."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import tempfile
from pathlib import Path
from typing import Any, Dict, Iterable, List, Set

from .utils import (
    mh_extract_domains_from_urls,
    mh_extract_urls,
    sh,
    which,
)

# --- Basic detectors ---


def d_pyinstaller(data: bytes) -> bool:
    markers = [
        b"MEI\014\013\012\013\016",
        b"PYZ\x00",
        b"pyi-runtime-tmpdir",
        b"pyi-windows-manifest-filename",
    ]
    return any(m in data for m in markers)


def d_upx(data: bytes) -> bool:
    return b"UPX!" in data


def d_nsis(data: bytes) -> bool:
    return b"Nullsoft.NSIS" in data or b"Nullsoft Install System" in data


def d_inno(data: bytes) -> bool:
    return b"Inno Setup" in data or b"Inno Setup Setup Data" in data


def d_msi_cab(data: bytes) -> bool:
    return data[:4] == b"MSCF" or b".cab" in data[:4096]


def d_jar(data: bytes) -> bool:
    return (data.find(b"PK\x03\x04") != -1) and (b"META-INF/MANIFEST.MF" in data)


def d_autoit(data: bytes) -> bool:
    return b"AutoIt" in data or b"AU3!EA06" in data


def d_net(data: bytes) -> bool:
    return b"BSJB" in data or b"mscoree.dll" in data or b"CorExeMain" in data


def d_go(data: bytes) -> bool:
    low = data.lower()
    return b"go build id" in low or b"go.build.id" in low or b"go build id:" in low


def d_rust(data: bytes) -> bool:
    return b"rust_eh_personality" in data or b"panic_impl" in data


def d_node_pkg(data: bytes) -> bool:
    low = data.lower()
    return b"pkg/" in low or b"snapshot_blob.bin" in low


def d_electron(data: bytes) -> bool:
    return b"Electron" in data or b"app.asar" in data or b"electron.asar" in data


def d_appimage(data: bytes) -> bool:
    return data[:4] == b"\x7FELF" and b"AppImage" in data


def d_sfx_rar(data: bytes) -> bool:
    return b"Rar!\x1A\x07\x00" in data or b"UnRAR SFX" in data


DETECTORS = (
    ("pyinstaller", d_pyinstaller),
    ("electron", d_electron),
    ("upx", d_upx),
    ("nsis", d_nsis),
    ("inno", d_inno),
    ("msi_cab", d_msi_cab),
    ("autoit", d_autoit),
    (".net", d_net),
    ("go", d_go),
    ("rust", d_rust),
    ("node_pkg", d_node_pkg),
    ("appimage", d_appimage),
    ("sfx_rar", d_sfx_rar),
    ("jar", d_jar),
)


def run_detectors(data: bytes) -> List[str]:
    """Return the names of all detectors that match ``data``."""
    return [name for name, fn in DETECTORS if fn(data)]


_B64_RE = re.compile(rb"[A-Za-z0-9+/=]{20,}")
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN_RE = re.compile(r"\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,63}\b")


# Trailing "labels" that are file extensions, not TLDs (kernel32.dll, gate.php, ...).
_FILE_EXTENSIONS = frozenset(
    "dll exe sys drv ocx scr msi cab bat cmd vbs lnk tmp dat bin log txt ini cfg config conf "
    "json xml yml yaml db lib obj pdb res tlb manifest resources pyc pyd jar class "
    "jpg jpeg png gif bmp ico svg css js html htm php asp aspx jsp".split()
)


def _looks_like_filename(domain: str) -> bool:
    return domain.rsplit(".", 1)[-1].lower() in _FILE_EXTENSIONS


def _valid_ip(ip: str) -> bool:
    try:
        parts = [int(x) for x in ip.split(".")]
    except ValueError:
        return False
    return len(parts) == 4 and all(0 <= x <= 255 for x in parts)


def extract_iocs_from_text(text: str) -> Dict[str, List[str]]:
    """Extract basic IOCs (IPs, URLs, domains) from plain text."""

    urls = mh_extract_urls(text)
    domains_from_urls = mh_extract_domains_from_urls(urls)

    ips: Set[str] = set()
    for m in _IP_RE.finditer(text):
        ip = m.group(0)
        if _valid_ip(ip):
            ips.add(ip)

    domains: Set[str] = set(domains_from_urls)
    for dom in _DOMAIN_RE.findall(text):
        if not _looks_like_filename(dom):
            domains.add(dom.lower())
    domains = {d for d in domains if not _is_benign_domain(d)}

    return {
        "ips": sorted(ips)[:1000],
        "urls": urls,
        "domains": sorted(domains)[:1000],
    }


# Infrastructure that shows up as "domains" in nearly every binary (XML namespaces, cert chains).
_BENIGN_DOMAIN_SUFFIXES = (
    "w3.org",
    "schemas.microsoft.com",
    "schemas.openxmlformats.org",
    "purl.org",
    "digicert.com",
    "verisign.com",
    "symcb.com",
    "symcd.com",
    "sectigo.com",
    "globalsign.com",
    "usertrust.com",
    "letsencrypt.org",
)


def _is_benign_domain(domain: str) -> bool:
    d = domain.lower()
    return any(d == suf or d.endswith("." + suf) for suf in _BENIGN_DOMAIN_SUFFIXES)


_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_BTC_RE = re.compile(r"\b[13][1-9A-HJ-NP-Za-km-z]{25,34}\b")
_XMR_RE = re.compile(r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b")
_DISCORD_WEBHOOK_RE = re.compile(r"https?://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[\w-]+")
_TELEGRAM_BOT_RE = re.compile(r"https?://api\.telegram\.org/bot\d+:[\w-]{30,}")


def _base58check_ok(addr: str) -> bool:
    """Validate a Base58Check string (Bitcoin legacy address checksum)."""
    num = 0
    for ch in addr:
        idx = _B58_ALPHABET.find(ch)
        if idx < 0:
            return False
        num = num * 58 + idx
    raw = num.to_bytes((num.bit_length() + 7) // 8, "big")
    raw = b"\x00" * (len(addr) - len(addr.lstrip("1"))) + raw
    if len(raw) < 5:
        return False
    payload, checksum = raw[:-4], raw[-4:]
    return hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] == checksum


def extract_extra_iocs(text: str) -> Dict[str, List[str]]:
    """Extract crypto wallets (checksum-validated BTC, Monero) and exfiltration channels."""
    wallets: Set[str] = {m.group(0) for m in _BTC_RE.finditer(text) if _base58check_ok(m.group(0))}
    wallets.update(m.group(0) for m in _XMR_RE.finditer(text))
    exfil: Set[str] = {m.group(0) for m in _DISCORD_WEBHOOK_RE.finditer(text)}
    exfil.update(m.group(0) for m in _TELEGRAM_BOT_RE.finditer(text))
    return {"wallets": sorted(wallets)[:1000], "exfil": sorted(exfil)[:1000]}


_PS_ENC_RE = re.compile(r"(?i)(?:^|\s)-e(?:nc(?:odedcommand)?)?\s+([A-Za-z0-9+/]{16,}={0,2})")


def decode_powershell_commands(text: str) -> List[str]:
    """Decode ``powershell -enc <base64 UTF-16LE>`` payloads found in text."""
    out: List[str] = []
    for m in _PS_ENC_RE.finditer(text):
        blob = m.group(1)
        try:
            decoded = base64.b64decode(blob + "=" * ((-len(blob)) % 4)).decode("utf-16le")
        except (binascii.Error, ValueError, UnicodeDecodeError):
            continue
        if decoded and sum(c.isprintable() or c in "\r\n\t" for c in decoded) / len(decoded) > 0.9:
            out.append(decoded)
    return out


def _is_pe_at(data: bytes, off: int) -> bool:
    if data[off : off + 2] != b"MZ" or off + 0x40 > len(data):
        return False
    e_lfanew = int.from_bytes(data[off + 0x3C : off + 0x40], "little")
    if not 0x40 <= e_lfanew <= 0x1000:
        return False
    return data[off + e_lfanew : off + e_lfanew + 4] == b"PE\x00\x00"


def find_embedded_pe(data: bytes, include_start: bool = False, limit: int = 20) -> List[int]:
    """Return offsets of PE images embedded in ``data`` (the file's own header is skipped by default)."""
    offsets: List[int] = []
    pos = 0 if include_start else 1
    while len(offsets) < limit:
        pos = data.find(b"MZ", pos)
        if pos < 0:
            break
        if _is_pe_at(data, pos):
            offsets.append(pos)
        pos += 2
    return offsets


def find_base64_pe(data: bytes, limit: int = 20) -> int:
    """Count Base64 blobs that decode to a PE image."""
    count = 0
    for m in re.finditer(rb"TV[pqroQ][A-Za-z0-9+/=]{200,}", data):
        blob = m.group(0)
        try:
            dec = base64.b64decode(blob + b"=" * ((-len(blob)) % 4))
        except (binascii.Error, ValueError):
            continue
        if _is_pe_at(dec, 0):
            count += 1
            if count >= limit:
                break
    return count


def detect_embedded_payloads(data: bytes) -> Dict[str, Any]:
    return {"embedded_pe": find_embedded_pe(data), "base64_pe": find_base64_pe(data)}


def recursive_decode_and_scan(content_bytes: bytes, max_depth: int = 2) -> Dict[str, List[str]]:
    """Recursively decode Base64 blobs and extract IOCs from decoded text."""

    findings: Dict[str, Set[str]] = {"ips": set(), "urls": set(), "domains": set()}
    seen_chunks: Set[bytes] = set()

    def _decode_and_scan(raw: bytes, depth: int) -> None:
        if depth > max_depth:
            return
        for match in _B64_RE.finditer(raw):
            blob = match.group(0)
            padding = (-len(blob)) % 4
            try:
                decoded = base64.b64decode(blob + (b"=" * padding), validate=False)
            except (binascii.Error, ValueError):
                continue
            if not decoded or decoded in seen_chunks:
                continue
            seen_chunks.add(decoded)
            try:
                decoded_text = decoded.decode("utf-8")
            except UnicodeDecodeError:
                continue

            iocs = extract_iocs_from_text(decoded_text)
            for key, values in iocs.items():
                findings[key].update(values)

            if depth < max_depth:
                _decode_and_scan(decoded, depth + 1)

    _decode_and_scan(content_bytes, 0)
    return {key: sorted(vals)[:1000] for key, vals in findings.items()}


def scan_with_json_signatures(sig_path: Path | str, texts: List[str]) -> List[Dict[str, Any]]:
    """Scan combined text blobs against JSON signature rules."""

    try:
        path = Path(sig_path)
        if not path.exists():
            return []
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []

    rules = data.get("rules") if isinstance(data, dict) else data
    if not isinstance(rules, list):
        return []

    blob = "\n".join(texts).lower()
    findings: List[Dict[str, Any]] = []

    for rule in rules:
        if not isinstance(rule, dict):
            continue
        strings_field = rule.get("strings") or rule.get("patterns") or []
        try:
            min_matches = int(rule.get("min_matches", 1))
        except Exception:
            min_matches = 1
        unique_patterns = {str(s).lower() for s in strings_field if isinstance(s, str)}
        if not unique_patterns:
            continue

        matches_found = sum(1 for pat in unique_patterns if pat and pat in blob)
        if matches_found >= min_matches:
            rule_name = rule.get("name") or rule.get("rule") or rule.get("id") or "unknown_rule"
            severity = rule.get("severity", "UNKNOWN")
            description = rule.get("description", "")
            score = rule.get("score", matches_found)
            mitre = [str(t) for t in rule.get("mitre") or [] if isinstance(t, str)]
            findings.append(
                {
                    "mitre": mitre,
                    "rule_name": str(rule_name),
                    "severity": str(severity),
                    "description": str(description),
                    "score": int(score) if isinstance(score, (int, float)) else matches_found,
                }
            )

    return findings


# --- YARA integration ---


def _yara_exec() -> str | None:
    for name in ("yara", "yara64", "yara.exe"):
        exe = which(name)
        if exe:
            return exe
    return None


_YARA_RULE_SUFFIXES = {".yar", ".yara"}


def _collect_rule_files(rules: Path) -> List[Path]:
    return sorted(f for f in rules.rglob("*") if f.is_file() and f.suffix.lower() in _YARA_RULE_SUFFIXES)


def _yara_quote(path: Path) -> str:
    return str(path.resolve()).replace("\\", "\\\\").replace('"', '\\"')


def _parse_yara_output(out: str) -> List[Dict[str, str]]:
    """Parse ``rule_name path`` lines printed by the yara CLI."""
    found: List[Dict[str, str]] = []
    for line in out.splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2:
            found.append({"rule": parts[0], "path": parts[1]})
    return found


def yara_scan(
    rules: str,
    targets: Iterable[Path],
    timeout: int | None = None,
) -> Dict[str, Any]:
    """Scan targets with YARA.

    ``rules`` is either a single rules file or a directory of ``.yar``/``.yara`` files.
    A directory is turned into one index file (using ``include``) so the rules are
    parsed once per yara invocation, and yara is run once per target (directories are
    scanned recursively by yara itself) instead of once per file.
    """
    exe = _yara_exec()
    if not exe or not rules:
        return {"ok": False, "reason": "yara missing or rules not set"}

    rules_path = Path(rules)
    if not rules_path.exists():
        return {"ok": False, "reason": f"rules path not found: {rules}"}

    with tempfile.TemporaryDirectory(prefix="monthunter_yara_") as tmp:
        if rules_path.is_dir():
            rule_files = _collect_rule_files(rules_path)
            if not rule_files:
                return {"ok": False, "reason": f"no .yar/.yara files in {rules}"}
            index_file = Path(tmp) / "index.yar"
            index_file.write_text("".join(f'include "{_yara_quote(f)}"\n' for f in rule_files), encoding="utf-8")
            rules_file = index_file
        else:
            rules_file = rules_path

        findings: List[Dict[str, str]] = []
        errors: List[str] = []
        for target in targets:
            if not target.exists():
                continue
            cmd = [exe]
            if target.is_dir():
                cmd.append("-r")
            cmd += [str(rules_file), str(target)]
            res = sh(cmd, timeout=timeout or 300)
            if res.get("ok"):
                findings.extend(_parse_yara_output(res.get("out") or ""))
            else:
                errors.append((res.get("err") or "").strip()[-300:])

    result: Dict[str, Any] = {"ok": not errors, "count": len(findings), "findings": findings[:1000]}
    if errors:
        result["errors"] = errors
    return result
