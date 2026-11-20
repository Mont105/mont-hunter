"""Reporting helpers: IOC CSV and HTML extended report."""

from __future__ import annotations

import csv
import html as _html
import json
from pathlib import Path
from typing import Any, Dict, List

from . import __version__
from .utils import mh_email_class


_CSV_DANGEROUS_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _csv_safe(value: Any) -> str:
    """Neutralise spreadsheet formula injection: prefix risky cells with a single quote."""
    text = "" if value is None else str(value)
    if text.startswith(_CSV_DANGEROUS_PREFIXES):
        return "'" + text
    return text


def _esc(value: Any) -> str:
    """HTML-escape any value (quotes included) for safe interpolation into the report."""
    return _html.escape(str(value), quote=True)


class _SafeCsvWriter:
    """csv.writer wrapper that neutralises formula-injection in every cell."""

    def __init__(self, writer) -> None:
        self._writer = writer

    def writerow(self, row) -> None:
        self._writer.writerow([_csv_safe(c) for c in row])


def write_ioc_csv(index: Dict[str, Any], out_dir: Path) -> None:
    """Write a flat IOC CSV file based on all per-file summaries."""
    out_dir = Path(out_dir)
    fpath = out_dir / "iocs.csv"
    with fpath.open("w", newline="", encoding="utf-8") as fh:
        writer = _SafeCsvWriter(csv.writer(fh))
        writer.writerow(["sha256", "path", "type", "value", "extra"])

        for fobj in index.get("files", []):
            sha = fobj.get("sha256") or "missing"
            fpath_str = fobj.get("path", "")
            s_path = out_dir / "files" / sha / "summary.json"
            if not s_path.exists():
                continue
            try:
                raw = json.loads(s_path.read_text(encoding="utf-8", errors="ignore"))
                summary = raw.get("summary", raw)
                iocs = summary.get("iocs") or {}

                for field, typ in (
                    ("ips", "ip"),
                    ("ips_ascii", "ip_ascii"),
                    ("domains", "domain"),
                    ("urls", "url"),
                    ("emails", "email"),
                    ("wallets", "wallet"),
                    ("exfil", "exfil_channel"),
                ):
                    for value in iocs.get(field) or []:
                        extra = ""
                        if typ == "email":
                            extra = mh_email_class(value)
                        writer.writerow([sha, fpath_str, typ, value, extra])

                for m in (summary.get("threatintel") or {}).get("matches") or []:
                    writer.writerow([sha, fpath_str, "threatfox_" + str(m.get("kind")), m.get("value"), f"{m.get('malware', '')}|{m.get('where', '')}"])

                extra_iocs = summary.get("iocs_extra") or {}
                for field, typ in (
                    ("risky_urls", "risky_url"),
                    ("emails_free", "email_free"),
                    ("emails_corp", "email_corp"),
                ):
                    for value in extra_iocs.get(field) or []:
                        writer.writerow([sha, fpath_str, typ, value, ""])
            except Exception as exc:
                writer.writerow([sha, fpath_str, "error", "read_summary_failed", str(exc)])


def write_html_report(index: Dict[str, Any], out_dir: Path) -> None:
    """Generate a lightweight HTML report summarizing IOC findings."""
    out_dir = Path(out_dir)
    html: List[str] = []
    html.append("<html><head><meta charset='utf-8'>")
    html.append(
        "<style>"
        "body{font-family:system-ui,Segoe UI,Arial;margin:20px}"
        ".tag{background:#eef;padding:2px 6px;border-radius:6px}"
        ".box{border:1px solid #ddd;border-radius:12px;padding:12px;margin:12px 0}"
        ".pill{display:inline-block;background:#f2f2f2;padding:3px 8px;margin:2px;border-radius:999px}"
        "</style>"
    )
    html.append("</head><body>")
    html.append(f"<h2>MontHunter — Extended Report v{__version__}</h2><div>")

    files = index.get("files", [])
    html.append(f"<div class='box'><b>Summary</b><div>Files Analyzed: {len(files)}</div></div>")

    dom_counter: Dict[str, int] = {}
    url_counter = 0
    email_counter = 0

    for fobj in files:
        sha = fobj.get("sha256") or "missing"
        s_path = out_dir / "files" / sha / "summary.json"
        if not s_path.exists():
            continue
        try:
            raw = json.loads(s_path.read_text(encoding="utf-8", errors="ignore"))
            summary = raw.get("summary", raw)
            iocs = summary.get("iocs") or {}
            for d in iocs.get("domains") or []:
                dom_counter[d] = dom_counter.get(d, 0) + 1
            url_counter += len(iocs.get("urls") or [])
            email_counter += len(iocs.get("emails") or [])
        except Exception:
            continue

    top_domains = sorted(dom_counter.items(), key=lambda x: x[1], reverse=True)[:15]
    if top_domains:
        html.append("<div class='box'><div><b>Top Domains</b></div>")
        for dom, count in top_domains:
            html.append(f"<div>🌐 <span class='pill'>{_esc(dom)}</span> — {count}</div>")
        html.append("</div>")

    html.append("<div class='box'><b>IOC Metrics</b>")
    html.append(f"<div>Total URLs: {url_counter}</div>")
    html.append(f"<div>Total Emails: {email_counter}</div></div>")

    html.append("<div class='box'><b>Files</b>")
    for fobj in files:
        sha = fobj.get("sha256") or "missing"
        path_str = fobj.get("path", "")
        s_path = out_dir / "files" / sha / "summary.json"
        if not s_path.exists():
            continue
        try:
            raw = json.loads(s_path.read_text(encoding="utf-8", errors="ignore"))
            summary = raw.get("summary", raw)
            html.append(
                "<div style='margin-top:8px'>"
                f"<span class='tag'>sha256</span> {_esc(sha)}<br>"
                f"<span class='tag'>path</span> {_esc(path_str)}</div>"
            )
            risk = summary.get("risk")
            if risk:
                html.append(f"<div><b>Risk</b>: {_esc(risk.get('score'))}/100 ({_esc(risk.get('level'))})</div>")
                for reason in risk.get("reasons") or []:
                    html.append(f"<div>• {_esc(reason)}</div>")
            for sig in summary.get("signatures") or []:
                mitre = ", ".join(sig.get("mitre") or [])
                html.append(
                    f"<div>⚠ {_esc(sig.get('rule_name'))} ({_esc(sig.get('severity'))})"
                    + (f" <span class='pill'>{_esc(mitre)}</span>" if mitre else "")
                    + "</div>"
                )
            intel = summary.get("threatintel") or {}
            for m in intel.get("matches") or []:
                html.append(
                    f"<div>🚩 ThreatFox {_esc(m.get('kind'))}: {_esc(m.get('value'))} → {_esc(m.get('malware', '?'))} "
                    f"({_esc(m.get('threat_type', '?'))}, confidence {_esc(m.get('confidence', '?'))}) "
                    f"<span class='pill'>{_esc(m.get('where'))}</span></div>"
                )
            dyn = summary.get("dynamic")
            if dyn:
                html.append("<div><b>Dynamic analysis (QEMU sandbox, no network)</b></div>")
                if not dyn.get("ran"):
                    html.append(f"<div>• did not run: {_esc(dyn.get('reason', ''))}</div>")
                for f in dyn.get("findings") or []:
                    html.append(
                        f"<div>• {_esc(f.get('behavior'))}: {_esc(f.get('detail'))} "
                        f"<span class='pill'>{_esc(', '.join(f.get('mitre') or []))}</span></div>"
                    )
                for net in dyn.get("network_attempts") or []:
                    html.append(f"<div>• connect attempt: {_esc(net.get('ip'))}:{_esc(net.get('port'))}</div>")
            iocs = summary.get("iocs") or {}
            urls = iocs.get("urls") or []
            emails = iocs.get("emails") or []
            doms = iocs.get("domains") or []

            if urls:
                html.append("<div><b>URLs</b></div>")
                for url in urls[:20]:
                    html.append(f"<div>• {_esc(url)}</div>")

            if emails:
                html.append("<div><b>Emails</b></div>")
                for email in emails[:20]:
                    html.append(f"<div>• {_esc(email)} <span class='pill'>{_esc(mh_email_class(email))}</span></div>")

            if doms:
                html.append("<div><b>Domains</b></div>")
                for dom in doms[:20]:
                    html.append(f"<div>• {_esc(dom)}</div>")

            if summary.get("hints"):
                html.append("<div><b>Hints</b></div>")
                for key, value in sorted(summary["hints"].items()):
                    html.append(f"<div>• {_esc(key)}: {_esc(value)}</div>")
        except Exception as exc:
            html.append(f"<div>Error reading summary: {_esc(exc)}</div>")
    html.append("</div></body></html>")
    (out_dir / "report.html").write_text("\n".join(html), encoding="utf-8")
