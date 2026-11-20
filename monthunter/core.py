"""Core analysis pipeline: MhSession and analyze_one()."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List

from .detectors import (
    decode_powershell_commands,
    detect_embedded_payloads,
    extract_extra_iocs,
    extract_iocs_from_text,
    recursive_decode_and_scan,
    run_detectors,
    scan_with_json_signatures,
    yara_scan,
)
from .plugins import run_summary_plugins
from .sandbox import SandboxError, run_sandbox
from .scoring import compute_risk
from .utils import (
    fuzzy_hash,
    mh_extract_emails,
    mh_hint_flags,
    mh_read_bytes,
    read_bytes,
    mh_strings_ascii,
    mh_strings_utf16le,
)
from .extractors import (
    ex_7z,
    ex_asar_search,
    ex_cab,
    ex_inno,
    ex_pyinstaller,
    ex_upx,
    analyze_pe_structure,
)


class MhSession:
    """Simple helper to manage input and output paths for a single run."""

    def __init__(self, input_path: str | Path, output_dir: str | Path):
        self.input_path = Path(input_path)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def detect(self, max_size: int = 200 * 1024 * 1024) -> Dict[str, Any]:
        """Return a simple detection summary for the input path."""
        data, meta = read_bytes(self.input_path, max_size=max_size)
        if data is None:
            return {"path": str(self.input_path), "errors": [meta or {}]}

        return {"path": str(self.input_path), "detected": run_detectors(data)}

    def extract(self, timeout: int = 360) -> Dict[str, Any]:
        """Run extractors, chaining UPX output to other tools if successful."""
        path_str = str(self.input_path.resolve())
        reports: Dict[str, Any] = {}

        upx_res = ex_upx(path_str, self.output_dir, timeout=timeout)
        reports["upx"] = upx_res

        target_path = path_str
        if upx_res.get("ok") and upx_res.get("unpacked"):
            target_path = upx_res["unpacked"]
            reports["upx"]["note"] = f"Chaining: switching context to {target_path}"

        reports["pyinstaller"] = ex_pyinstaller(target_path, self.output_dir, timeout=timeout)
        reports["sevenzip"] = ex_7z(target_path, self.output_dir, timeout=timeout)
        reports["inno"] = ex_inno(target_path, self.output_dir, timeout=timeout)
        reports["cab"] = ex_cab(target_path, self.output_dir, timeout=timeout)
        reports["asar"] = ex_asar_search(self.output_dir, timeout=timeout)

        return {"path": path_str, "effective_path": target_path, "extractors": reports}

    def analyze(
        self,
        *,
        yara_rules: str | None = None,
        max_size: int = 200 * 1024 * 1024,
        timeout_per_tool: int = 360,
        do_extract: bool = False,
    ) -> Dict[str, Any]:
        """Full analysis entry point that delegates to analyze_one()."""
        return analyze_one(
            str(self.input_path),
            self.output_dir,
            yara_rules=yara_rules,
            max_size=max_size,
            timeout_per_tool=timeout_per_tool,
            do_extract=do_extract,
        )


def analyze_one(
    path: str,
    out_dir: str | Path,
    *,
    yara_rules: str | None = None,
    max_size: int = 200 * 1024 * 1024,
    timeout_per_tool: int = 360,
    do_extract: bool = False,
    sandbox: Any = None,
    threatintel: Any = None,
) -> Dict[str, Any]:
    """Analyze a single file and write its summary.json into out_dir/files/<sha256>/."""
    p = Path(path)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    data, meta = read_bytes(p, max_size=max_size)
    if data is None:
        summary: Dict[str, Any] = {
            "path": str(p),
            "sha256": None,
            "detected": [],
            "hints": {},
            "iocs": {},
            "meta": meta or {},
        }
        sha256 = "missing"
    else:
        sha256 = hashlib.sha256(data).hexdigest()
        md5 = hashlib.md5(data, usedforsecurity=False).hexdigest()
        sha1 = hashlib.sha1(data, usedforsecurity=False).hexdigest()
        detected: List[str] = run_detectors(data)
        summary = {
            "sha256": sha256,
            "md5": md5,
            "sha1": sha1,
            "ssdeep": fuzzy_hash(p),
            "size": len(data),
            "path": str(p),
            "detected": detected,
            "hints": {},
            "iocs": {},
            "meta": meta or {},
        }

    # Optional extraction phase
    if do_extract:
        extract_dir = out_dir / "files" / sha256 / "extracted"
        session = MhSession(p, extract_dir)
        summary["extraction"] = session.extract(timeout=timeout_per_tool)

    # Strings and IOCs
    ascii_text = mh_strings_ascii(p, min_len=4)
    utf16_text = mh_strings_utf16le(p, min_len=4)

    pe_analysis = analyze_pe_structure(p)
    if pe_analysis:
        summary["pe_analysis"] = {k: v for k, v in pe_analysis.items() if k != "strings"}
    pe_strings_text = "\n".join(pe_analysis.get("strings", [])) if pe_analysis else ""

    text_blobs = [ascii_text, utf16_text]
    if pe_strings_text:
        text_blobs.append(pe_strings_text)

    decoded_ps: List[str] = []
    for blob in (ascii_text, utf16_text):
        decoded_ps.extend(decode_powershell_commands(blob))
    if decoded_ps:
        text_blobs.extend(decoded_ps)
        summary["decoded_powershell"] = [c[:2000] for c in decoded_ps[:20]]

    ioc_sets = {"urls": set(), "domains": set(), "ips": set()}
    email_set = set()
    for blob in text_blobs:
        blob_iocs = extract_iocs_from_text(blob)
        for key in ioc_sets:
            ioc_sets[key].update(blob_iocs.get(key, []))
        email_set.update(mh_extract_emails(blob))

    iocs = summary.setdefault("iocs", {})
    iocs["urls"] = sorted(ioc_sets["urls"])[:1000]
    iocs["domains"] = sorted(ioc_sets["domains"])[:1000]
    iocs["ips"] = sorted(ioc_sets["ips"])[:1000]
    iocs["emails"] = sorted(email_set)[:1000]
    wallets: set = set()
    exfil: set = set()
    for blob in text_blobs:
        extra = extract_extra_iocs(blob)
        wallets.update(extra["wallets"])
        exfil.update(extra["exfil"])
    iocs["wallets"] = sorted(wallets)[:1000]
    iocs["exfil"] = sorted(exfil)[:1000]

    if data is not None:
        embedded = detect_embedded_payloads(data)
        if embedded["embedded_pe"] or embedded["base64_pe"]:
            summary["embedded"] = embedded

    raw_for_b64 = data if data is not None else mh_read_bytes(p)
    b64_iocs = recursive_decode_and_scan(raw_for_b64 or b"") if raw_for_b64 else {"ips": [], "urls": [], "domains": []}
    if any(b64_iocs.values()):
        detail_list = summary.setdefault("ioc_details", [])
        seen_detail = {
            (entry.get("type"), entry.get("value"), entry.get("source"))
            for entry in detail_list
            if isinstance(entry, dict)
        }

        for key in ("ips", "domains", "urls"):
            merged = set(iocs.get(key, [])) | set(b64_iocs.get(key, []))
            if merged:
                iocs[key] = sorted(merged)[:1000]
            for value in b64_iocs.get(key, []):
                entry = (key[:-1] if key.endswith("s") else key, value, "obfuscated_base64")
                if entry not in seen_detail:
                    detail_list.append({"type": entry[0], "value": value, "source": "obfuscated_base64"})
                    seen_detail.add(entry)

    # Signature-based detection
    sig_path = Path(__file__).parent / "signatures.json"
    signatures = scan_with_json_signatures(sig_path, text_blobs)
    if signatures:
        summary["signatures"] = signatures
        if any(s.get("severity", "").upper() in {"CRITICAL", "HIGH"} for s in signatures):
            summary.setdefault("hints", {})["threat_detected"] = True

    summary.setdefault("hints", {}).update(mh_hint_flags([ascii_text, utf16_text]))
    if decoded_ps:
        summary["hints"]["powershell_encoded_command"] = True

    # Summary plugins
    run_summary_plugins(summary, ascii_text, utf16_text)

    # Optional YARA
    if yara_rules:
        targets = [p]
        extracted = out_dir / "files" / sha256 / "extracted"
        if extracted.exists():
            targets.append(extracted)
        yr = yara_scan(yara_rules, targets, timeout=timeout_per_tool)
        summary["yara"] = yr

    # Optional dynamic analysis in a disposable QEMU VM (explicitly requested only)
    if sandbox is not None:
        try:
            summary["dynamic"] = run_sandbox(p, sandbox, out_dir / "files" / sha256 / "sandbox")
        except SandboxError as exc:
            summary["dynamic"] = {"ran": False, "reason": str(exc)}

    # Offline cross-check against the cached ThreatFox feed (runs after the sandbox so runtime
    # connection attempts are included). Nothing is sent over the network.
    if threatintel is not None:
        summary["threatintel"] = threatintel.match_summary(summary)

    summary["risk"] = compute_risk(summary)

    # Persist to disk
    files_dir = out_dir / "files" / sha256
    files_dir.mkdir(parents=True, exist_ok=True)
    (files_dir / "summary.json").write_text(
        json.dumps({"schema_version": "1.0.0", "summary": summary}, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return summary
