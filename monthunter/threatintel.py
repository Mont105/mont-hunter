"""Offline matching against the abuse.ch ThreatFox IOC feed.

The feed is downloaded once with :func:`update_feed` (needs a free abuse.ch Auth-Key) and stored
in a local cache file. Matching is done locally, so no IOC extracted from a sample ever leaves
the machine. The Auth-Key is read from the environment or a file, never from the command line,
and is never written to the cache or the reports.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, Iterable, List

API_URL = "https://threatfox-api.abuse.ch/api/v1/"
KEY_ENV = "THREATFOX_AUTH_KEY"
DEFAULT_CACHE = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "monthunter" / "threatfox.json"
MAX_FEED_BYTES = 64 * 1024 * 1024


class ThreatIntelError(RuntimeError):
    pass


def load_auth_key(key_file: str | None = None) -> str:
    """Return the Auth-Key from ``key_file`` or $THREATFOX_AUTH_KEY."""
    key = ""
    if key_file:
        try:
            key = Path(key_file).read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise ThreatIntelError(f"cannot read key file: {exc}") from exc
    else:
        key = os.environ.get(KEY_ENV, "").strip()
    if not key:
        raise ThreatIntelError(
            f"no Auth-Key: export {KEY_ENV} or pass --threatfox-key-file "
            "(free key at https://auth.abuse.ch/)"
        )
    return key


def update_feed(auth_key: str, *, days: int = 7, cache_path: str | Path = DEFAULT_CACHE, timeout: int = 60) -> Dict[str, Any]:
    """Download recent IOCs (``days`` 1-7, the API maximum) and write them to the cache."""
    if not 1 <= days <= 7:
        raise ThreatIntelError("days must be between 1 and 7")
    body = json.dumps({"query": "get_iocs", "days": days}).encode()
    req = urllib.request.Request(API_URL, data=body, method="POST", headers={"Auth-Key": auth_key, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read(MAX_FEED_BYTES + 1)
    except urllib.error.HTTPError as exc:
        raise ThreatIntelError(f"ThreatFox HTTP {exc.code} (check your Auth-Key)") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise ThreatIntelError(f"ThreatFox request failed: {exc}") from exc
    if len(raw) > MAX_FEED_BYTES:
        raise ThreatIntelError("ThreatFox response too large")
    try:
        payload = json.loads(raw)
    except ValueError as exc:
        raise ThreatIntelError("ThreatFox returned invalid JSON") from exc
    if payload.get("query_status") != "ok" or not isinstance(payload.get("data"), list):
        raise ThreatIntelError(f"ThreatFox query failed: {str(payload.get('query_status'))[:80]}")

    cache = Path(cache_path)
    cache.parent.mkdir(parents=True, exist_ok=True)
    doc = {"source": "ThreatFox", "fetched_at": int(time.time()), "days": days, "data": payload["data"]}
    tmp = cache.with_suffix(".tmp")
    tmp.write_text(json.dumps(doc), encoding="utf-8")
    os.replace(tmp, cache)
    return {"ok": True, "iocs": len(payload["data"]), "cache": str(cache)}


class ThreatFoxIndex:
    """In-memory lookup tables built from a cached feed."""

    def __init__(self, entries: Iterable[Dict[str, Any]], fetched_at: int | None = None):
        self.fetched_at = fetched_at
        self.ip_port: Dict[str, Dict[str, Any]] = {}
        self.ip: Dict[str, Dict[str, Any]] = {}
        self.domain: Dict[str, Dict[str, Any]] = {}
        self.url: Dict[str, Dict[str, Any]] = {}
        self.hash: Dict[str, Dict[str, Any]] = {}
        for e in entries:
            if not isinstance(e, dict):
                continue
            ioc, typ = str(e.get("ioc") or "").strip(), str(e.get("ioc_type") or "")
            if not ioc:
                continue
            info = {
                "ioc": ioc,
                "ioc_type": typ,
                "malware": e.get("malware_printable") or e.get("malware"),
                "threat_type": e.get("threat_type"),
                "confidence": e.get("confidence_level"),
                "first_seen": e.get("first_seen"),
                "id": e.get("id"),
            }
            if typ == "ip:port":
                self.ip_port[ioc.lower()] = info
                self.ip.setdefault(ioc.rsplit(":", 1)[0], info)
            elif typ == "domain":
                self.domain[ioc.lower()] = info
            elif typ == "url":
                self.url[ioc] = info
            elif typ.endswith("_hash"):
                self.hash[ioc.lower()] = info
        self.size = len(self.ip_port) + len(self.domain) + len(self.url) + len(self.hash)

    @classmethod
    def load(cls, cache_path: str | Path = DEFAULT_CACHE) -> "ThreatFoxIndex":
        try:
            doc = json.loads(Path(cache_path).read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise ThreatIntelError(f"no usable ThreatFox cache at {cache_path} (run --threatfox-update): {exc}") from exc
        return cls(doc.get("data") or [], doc.get("fetched_at"))

    def match_summary(self, summary: Dict[str, Any]) -> Dict[str, Any]:
        """Return ``{"source", "feed_size", "feed_age_hours", "matches": [...]}`` for one file summary."""
        matches: List[Dict[str, Any]] = []

        def add(kind: str, value: str, info: Dict[str, Any], where: str) -> None:
            m = {"kind": kind, "value": value, "where": where}
            m.update({k: v for k, v in info.items() if k != "ioc" and v is not None})
            if m not in matches and len(matches) < 200:
                matches.append(m)

        for algo in ("md5", "sha1", "sha256"):
            h = (summary.get(algo) or "").lower()
            if h and h in self.hash:
                add("file_hash", h, self.hash[h], "sample")

        iocs = summary.get("iocs") or {}
        for ip in iocs.get("ips") or []:
            if ip in self.ip:
                add("ip", ip, self.ip[ip], "static")
        for dom in iocs.get("domains") or []:
            if dom.lower() in self.domain:
                add("domain", dom, self.domain[dom.lower()], "static")
        for url in iocs.get("urls") or []:
            if url in self.url:
                add("url", url, self.url[url], "static")

        dynamic = summary.get("dynamic") or {}
        for name in dynamic.get("dns_queries") or []:
            if name.lower() in self.domain:
                add("domain", name, self.domain[name.lower()], "sandbox")
        for net in dynamic.get("network_attempts") or []:
            ip, port = net.get("ip"), net.get("port")
            exact = f"{ip}:{port}".lower()
            if exact in self.ip_port:
                add("ip_port", exact, self.ip_port[exact], "sandbox")
            elif ip in self.ip:
                add("ip", str(ip), self.ip[ip], "sandbox")

        age = None if self.fetched_at is None else round((time.time() - self.fetched_at) / 3600, 1)
        return {"source": "ThreatFox", "feed_size": self.size, "feed_age_hours": age, "matches": matches}
