"""Command-line interface for MontHunter (monthunter.cli.main)."""

from __future__ import annotations

import argparse
import concurrent.futures
import importlib.util
import json
import time
from pathlib import Path
from typing import Any, Dict, List, Sequence

from . import __version__
from .core import analyze_one
from .sandbox import SandboxConfig, SandboxError, prepare_image
from .threatintel import DEFAULT_CACHE, ThreatFoxIndex, ThreatIntelError, load_auth_key, update_feed
from .reporting import write_html_report, write_ioc_csv
from .utils import sh, which

_RICH_AVAILABLE = importlib.util.find_spec("rich") is not None

if _RICH_AVAILABLE:
    from rich import print as rprint
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
else:  # pragma: no cover - fallback
    rprint = print
    Console = None  # type: ignore
    Panel = None  # type: ignore
    Table = None  # type: ignore


C = "\033[36m"
R = "\033[31m"
W = "\033[0m"

BANNER = rf"""{C}
 __  __  ____  _   _ _______ _    _ _   _ _   _ ______ _______ _____  
|  \/  |/ __ \| \ | |__   __| |  | | \ | | \ | |  ____|__   __|  __ \ 
| \  / | |  | |  \| |  | |  | |  | |  \| |  \| | |__     | |  | |  | |
| |\/| | |  | | . ` |  | |  | |  | | . ` | . ` |  __|    | |  | |  | |
| |  | | |__| | |\  |  | |  | |__| | |\  | |\  | |____   | |  | |__| |
|_|  |_|\____/|_| \_|  |_|   \____/|_| \_|_| \_|______|  |_|  |_____/ 
{W}"""


def _get_console() -> Console | None:
    if _RICH_AVAILABLE:
        return Console()
    return None


def _log(console: Console | None, message: str) -> None:
    if console:
        console.print(message)
    else:
        print(message)


def _diagnostics(console: Console | None) -> None:
    """Print a simple JSON document with versions and paths of external tools."""
    tools = ["strings", "7z", "innoextract", "cabextract", "upx", "asar", "pyinstxtractor", "pyinstxtractor-ng", "yara", "ssdeep", "qemu-system-x86_64", "xorriso"]
    vers: Dict[str, Any] = {}
    for tool in tools:
        exe = which(tool) or which(tool + ".py")
        if exe:
            if tool in ("pyinstxtractor", "pyinstxtractor-ng", "asar"):
                v = {"out": "(no --version)"}
            else:
                v = sh([exe, "--version"], timeout=10)
            vers[tool] = {
                "path": exe,
                "version": (v.get("out") or v.get("err") or "").splitlines()[:1],
            }
        else:
            vers[tool] = None
    if console:
        console.print_json(data={"version": __version__, "tools": vers})
    else:
        print(json.dumps({"version": __version__, "tools": vers}, ensure_ascii=False, indent=2))


def _print_critical_alerts(console: Console | None, index: Dict[str, Any]) -> None:
    """Emit high-priority console alerts for critical IOC findings."""

    alerts: List[str] = []
    has_b64 = False
    for fobj in index.get("files", []):
        path_label = fobj.get("path", "")
        iocs = fobj.get("iocs") or {}
        details = fobj.get("ioc_details") or []
        base64_tagged = {
            (entry.get("type"), entry.get("value"))
            for entry in details
            if isinstance(entry, dict) and entry.get("source") == "obfuscated_base64"
        }
        has_b64 = has_b64 or bool(base64_tagged)

        for ip in iocs.get("ips") or []:
            marker = " (Hidden in Base64)" if ("ip", ip) in base64_tagged else ""
            alerts.append(f"[!] CRITICAL DETECTED: IP = {ip}{marker} [{path_label}]")
        for dom in iocs.get("domains") or []:
            marker = " (Hidden in Base64)" if ("domain", dom) in base64_tagged else ""
            alerts.append(f"[!] CRITICAL DETECTED: Domain = {dom}{marker} [{path_label}]")
        for url in iocs.get("urls") or []:
            if ("url", url) in base64_tagged:
                alerts.append(f"[!] CRITICAL DETECTED: URL = {url} (Hidden in Base64) [{path_label}]")

    if has_b64:
        _log(console, "[bold red][!] ALERTA: Payload detectado en memoria[/]")

    for line in alerts:
        if console:
            console.print(f"[bold red]{line}[/]")
        else:
            print(f"{R}{line}{W}")


def _print_signature_alerts(console: Console | None, index: Dict[str, Any]) -> None:
    """Show alerts for signature-based detections."""

    for fobj in index.get("files", []):
        sigs = fobj.get("signatures") or []
        if not sigs:
            continue
        path_label = fobj.get("path", "")
        lines: List[str] = []
        top_sev = "LOW"
        for sig in sigs:
            sev = str(sig.get("severity", "")).upper() or "UNKNOWN"
            if sev in {"CRITICAL", "HIGH"}:
                top_sev = "CRITICAL"
            line = f"[!] AMENAZA DETECTADA: {sig.get('rule_name', 'unknown')} ({sev.title()})"
            lines.append(line)
            desc = sig.get("description", "")
            if desc:
                lines.append(f"    Description: {desc}")
        if lines:
            header = f"{path_label}" if path_label else "Firmas detectadas"
            color = "red" if top_sev == "CRITICAL" else "yellow"
            body = "\n".join(lines)
            if console and Panel:
                console.print(Panel(body, title=header, style=color, expand=False))
            else:
                print(body)


def _print_dynamic_and_risk(console: Console | None, index: Dict[str, Any]) -> None:
    for fobj in index.get("files", []):
        label = fobj.get("path", "")
        risk = fobj.get("risk")
        if risk:
            _log(console, f"[bold]Riesgo[/] {label}: {risk.get('score')}/100 ({risk.get('level')})")
        for m in (fobj.get("threatintel") or {}).get("matches") or []:
            _log(
                console,
                f"[bold red][!] THREATFOX: {m['kind']} {m['value']} -> {m.get('malware', '?')} "
                f"({m.get('threat_type', '?')}, confidence {m.get('confidence', '?')}) [{m['where']}][/]",
            )
        dyn = fobj.get("dynamic")
        if not dyn:
            continue
        if not dyn.get("ran"):
            _log(console, f"[yellow][!] Sandbox no produjo resultados: {dyn.get('reason', '')}[/]")
            continue
        for f in dyn.get("findings") or []:
            _log(console, f"[bold red][!] RUNTIME: {f['behavior']} — {f['detail']}[/]")


def _log_step(console: Console | None, message: str) -> None:
    _log(console, f"[bold cyan][*] {message}[/]")


def _run_with_status(console: Console | None, status_msg: str, func, *args, **kwargs):
    if console:
        with console.status(status_msg):
            return func(*args, **kwargs)
    return func(*args, **kwargs)


def _build_ioc_table(index: Dict[str, Any]) -> Table | None:
    if not _RICH_AVAILABLE or not Table:
        return None
    table = Table(title="Indicadores de Compromiso (IOCs)")
    table.add_column("Tipo", style="cyan", no_wrap=True)
    table.add_column("Valor", style="magenta")
    counts = 0
    for f in index.get("files", []):
        iocs = f.get("iocs") or {}
        for key, typ in (("ips", "IP"), ("domains", "Dominio"), ("urls", "URL"), ("emails", "Email")):
            for value in iocs.get(key) or []:
                table.add_row(typ, value)
                counts += 1
                if counts >= 50:
                    return table
    return table


def _summary_panel(console: Console | None, duration: float, index: Dict[str, Any], out_dir: Path) -> None:
    total_files = len(index.get("files", []))
    extracted = sum(1 for f in index.get("files", []) if f.get("extraction"))
    total_iocs = 0
    for f in index.get("files", []):
        iocs = f.get("iocs") or {}
        total_iocs += sum(len(iocs.get(k) or []) for k in ("ips", "domains", "urls", "emails"))

    content = (
        f"[bold]Tiempo de análisis:[/] {duration:.2f}s\n"
        f"[bold]Archivos analizados:[/] {total_files}\n"
        f"[bold]Archivos extraídos:[/] {extracted}\n"
        f"[bold]IOCs detectados:[/] {total_iocs}\n"
        f"[bold]Reporte:[/] {out_dir}"
    )

    if console and Panel:
        console.print(Panel(content, title="Resumen", expand=False))
    else:
        print("==== Resumen ====")
        print(content)


def main(argv: Sequence[str] | None = None) -> None:
    console = _get_console()

    parser = argparse.ArgumentParser(
        description=f"MontHunter v{__version__} — multi-packer static triage",
    )
    parser.add_argument("inputs", nargs="*", help="Input files to analyze")
    parser.add_argument("--out", default="mont_out", help="Output directory")
    parser.add_argument("--extract", action="store_true", help="Attempt extractor passes (7z, inno, cab, UPX, asar)")
    parser.add_argument("--json", action="store_true", help="Print final index.json to stdout")
    parser.add_argument("--quiet", action="store_true", help="Do not print banner or OK line")
    parser.add_argument("--jobs", type=int, default=1, help="Concurrent analysis jobs")
    parser.add_argument("--max-size", type=int, default=200 * 1024 * 1024, help="Max size per file in bytes")
    parser.add_argument("--timeout-per-tool", type=int, default=360, help="Timeout per external tool (seconds)")
    parser.add_argument("--yara-rules", type=str, default=None, help="Optional YARA rules file, or a directory of .yar/.yara files")
    parser.add_argument("--mem-limit", type=int, default=0, help="(Reserved) memory limit in MB")
    parser.add_argument("--diag", action="store_true", help="Show environment diagnostics and exit")
    parser.add_argument(
        "--sandbox",
        metavar="IMAGE",
        default=None,
        help="Detonate each sample in a disposable QEMU VM (prepared Linux qcow2 image). "
        "No network, snapshot disk, results via serial console only.",
    )
    parser.add_argument("--threatfox", action="store_true", help="Match IOCs, hashes and sandbox connections against the cached ThreatFox feed (offline)")
    parser.add_argument("--threatfox-update", action="store_true", help="Download the recent ThreatFox feed to the local cache and exit (needs an Auth-Key)")
    parser.add_argument("--threatfox-days", type=int, default=7, help="Days of IOCs to download (1-7)")
    parser.add_argument("--threatfox-key-file", default=None, help="File holding the abuse.ch Auth-Key (default: the THREATFOX_AUTH_KEY environment variable)")
    parser.add_argument("--threatfox-feed", default=str(DEFAULT_CACHE), help="ThreatFox cache file")
    parser.add_argument("--with-wine", action="store_true", help="With --sandbox-prepare: also install Wine so Windows .exe samples can run")
    parser.add_argument("--sandbox-winvm", action="store_true", help="Run Windows PE samples in the real-Windows lab (outer VM -> inner Windows VM, see scripts/winlab.sh) instead of Wine")
    parser.add_argument("--sandbox-os", choices=["auto", "linux", "windows"], default="auto", help="Guest OS for the sample (auto detects PE files and runs them under Wine)")
    parser.add_argument("--sandbox-timeout", type=int, default=120, help="Seconds the sample may run in the VM")
    parser.add_argument("--sandbox-memory", type=int, default=1024, help="Guest RAM in MB")
    parser.add_argument(
        "--sandbox-prepare",
        metavar="IMAGE",
        default=None,
        help="One-time: install strace into a copy of the guest image (the only networked VM step), then exit",
    )

    args = parser.parse_args(argv)

    if args.diag:
        _diagnostics(console)
        return

    if args.threatfox_update:
        try:
            res = update_feed(load_auth_key(args.threatfox_key_file), days=args.threatfox_days, cache_path=args.threatfox_feed)
        except ThreatIntelError as exc:
            parser.error(str(exc))
        print(json.dumps(res, indent=2))
        raise SystemExit(0)

    if args.sandbox_prepare:
        _log(console, f"[*] Preparing guest image {args.sandbox_prepare} (networked, no sample attached)...")
        try:
            res = prepare_image(args.sandbox_prepare, with_wine=args.with_wine)
        except SandboxError as exc:
            parser.error(str(exc))
        print(json.dumps(res, indent=2))
        raise SystemExit(0 if res.get("ok") else 1)

    if not args.inputs:
        parser.error("at least one input file is required")

    intel_index = None
    if args.threatfox:
        try:
            intel_index = ThreatFoxIndex.load(args.threatfox_feed)
        except ThreatIntelError as exc:
            parser.error(str(exc))

    sandbox_cfg = None
    if args.sandbox or args.sandbox_winvm:
        sandbox_cfg = SandboxConfig(image=args.sandbox or "", timeout=args.sandbox_timeout, memory_mb=args.sandbox_memory, guest_os=args.sandbox_os, winvm=args.sandbox_winvm)
        try:
            sandbox_cfg.validate()
        except SandboxError as exc:
            parser.error(str(exc))

    if not args.quiet:
        if console:
            console.print(BANNER)
        else:
            print(BANNER)

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    run_cfg: Dict[str, Any] = {
        "max_size": args.max_size,
        "timeout_per_tool": args.timeout_per_tool,
        "mem_limit_mb": args.mem_limit,
        "yara_rules": args.yara_rules,
        "extract": args.extract,
        "sandbox": bool(args.sandbox or args.sandbox_winvm),
    }

    summaries: List[Dict[str, Any]] = []

    def _run_one(path_str: str) -> Dict[str, Any]:
        if not args.quiet:
            _log_step(console, f"Iniciando análisis de: {path_str}")
            if args.extract:
                _log_step(console, "Iniciando motor de extracción...")
        return _run_with_status(
            console,
            "[bold green]Analizando archivo y extrayendo artefactos...[/]",
            analyze_one,
            path_str,
            out_dir,
            yara_rules=args.yara_rules,
            max_size=args.max_size,
            timeout_per_tool=args.timeout_per_tool,
            do_extract=args.extract,
            sandbox=sandbox_cfg,
            threatintel=intel_index,
        )

    start = time.perf_counter()

    if args.jobs > 1 and len(args.inputs) > 1:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
            futures = [pool.submit(_run_one, p) for p in args.inputs]
            for fut in concurrent.futures.as_completed(futures):
                res = fut.result()
                summaries.append(res)
    else:
        for p in args.inputs:
            res = _run_one(p)
            summaries.append(res)

    duration = time.perf_counter() - start

    index: Dict[str, Any] = {
        "version": __version__,
        "out": str(out_dir),
        "run_cfg": run_cfg,
        "files": summaries,
    }

    index_path = out_dir / "index.json"
    index_path.write_text(json.dumps(index, indent=2, ensure_ascii=False), encoding="utf-8")

    write_ioc_csv(index, out_dir)
    write_html_report(index, out_dir)

    if args.json:
        print(index_path.read_text(encoding="utf-8"))

    if not args.quiet:
        _log_step(console, "Escaneando en busca de ofuscación Base64...")
        _print_critical_alerts(console, index)
        _print_signature_alerts(console, index)
        _print_dynamic_and_risk(console, index)

        ioc_table = _build_ioc_table(index)
        if console and ioc_table:
            console.print(ioc_table)
        elif not console and summaries:
            print("IOCs extractados (modo texto): ver reporte JSON/HTML.")

        _summary_panel(console, duration, index, out_dir)
        _log(console, f"[bold green]OK -> {args.out}[/]")


if __name__ == "__main__":
    main()
