"""Aggregate risk score and verdict for a per-file summary."""

from __future__ import annotations

from typing import Any, Dict, List

_SEVERITY_POINTS = {"CRITICAL": 40, "HIGH": 25, "MEDIUM": 10, "LOW": 3}


def compute_risk(summary: Dict[str, Any]) -> Dict[str, Any]:
    """Return ``{"score": 0-100, "level": str, "reasons": [str]}``.

    This is a triage heuristic, not a verdict: it only ranks what to look at first.
    """
    score = 0
    reasons: List[str] = []

    sig_points = 0
    for sig in summary.get("signatures") or []:
        sev = str(sig.get("severity", "")).upper()
        pts = _SEVERITY_POINTS.get(sev, 0)
        if pts:
            sig_points += pts
            reasons.append(f"signature {sig.get('rule_name')} ({sev.lower()}) +{pts}")
    score += min(sig_points, 70)

    embedded = summary.get("embedded") or {}
    if embedded.get("embedded_pe") or embedded.get("base64_pe"):
        score += 20
        reasons.append("embedded PE payload +20")

    pe = summary.get("pe_analysis") or {}
    if pe.get("packed_score") and pe["packed_score"] > 7.2:
        score += 10
        reasons.append("high-entropy section (packed/encrypted) +10")
    anomalies = pe.get("anomalies") or []
    if anomalies:
        pts = min(5 * len(anomalies), 15)
        score += pts
        reasons.append(f"{len(anomalies)} PE anomalies +{pts}")
    risky = pe.get("risky_apis") or []
    if risky:
        pts = min(3 * len(risky), 15)
        score += pts
        reasons.append(f"{len(risky)} risky API imports +{pts}")

    hints = summary.get("hints") or {}
    if hints.get("powershell_encoded_command"):
        score += 15
        reasons.append("encoded PowerShell command +15")
    for key, pts, label in (
        ("persistence_possible", 5, "persistence artifacts"),
        ("lolbins_used", 5, "LOLBIN usage"),
        ("risky_urls_present", 5, "risky URL paths"),
    ):
        if hints.get(key):
            score += pts
            reasons.append(f"{label} +{pts}")

    iocs = summary.get("iocs") or {}
    if any(d.get("source") == "obfuscated_base64" for d in summary.get("ioc_details") or []):
        score += 10
        reasons.append("IOCs hidden in Base64 +10")
    if iocs.get("exfil"):
        score += 15
        reasons.append("exfiltration channel (webhook/bot) +15")
    if iocs.get("wallets"):
        score += 5
        reasons.append("cryptocurrency wallet +5")

    dynamic = summary.get("dynamic") or {}
    if dynamic.get("ran"):
        behaviors = {f.get("behavior") for f in dynamic.get("findings") or []} - {"process_creation"}  # informational only
        if behaviors:
            pts = min(8 * len(behaviors), 40)
            score += pts
            reasons.append(f"{len(behaviors)} suspicious runtime behaviours +{pts}")
        if "persistence_write" in behaviors:
            score += 15
            reasons.append("persistence written at runtime +15")
        if dynamic.get("network_attempts"):
            score += 10
            reasons.append("network connection attempts at runtime +10")

    intel = summary.get("threatintel") or {}
    matches = intel.get("matches") or []
    if matches:
        if any(m.get("kind") == "file_hash" for m in matches):
            score += 50
            reasons.append("file hash listed in ThreatFox +50")
        if any(m.get("kind") != "file_hash" for m in matches):
            score += 40
            reasons.append(f"{sum(m.get('kind') != 'file_hash' for m in matches)} IOC(s) listed in ThreatFox +40")

    score = max(0, min(score, 100))
    if score >= 70:
        level = "critical"
    elif score >= 40:
        level = "high"
    elif score >= 15:
        level = "medium"
    elif score > 0:
        level = "low"
    else:
        level = "none"
    return {"score": score, "level": level, "reasons": reasons}
