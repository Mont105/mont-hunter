"""Plugin system and default summary plugins for MontHunter."""

from __future__ import annotations

from typing import Any, Callable, Dict, List

from .utils import _SUSP_LOLBINS, mh_email_class


SummaryPlugin = Callable[[Dict[str, Any], str, str], Any]

_SUMMARY_PLUGINS: List[SummaryPlugin] = []


def register_summary_plugin(fn: SummaryPlugin) -> SummaryPlugin:
    """Register a summary-level plugin that enriches per-file analysis results."""
    _SUMMARY_PLUGINS.append(fn)
    return fn


def run_summary_plugins(summary: Dict[str, Any], ascii_text: str, utf16_text: str) -> None:
    """Run all registered summary plugins on a file summary."""
    for fn in list(_SUMMARY_PLUGINS):
        try:
            ret = fn(summary, ascii_text, utf16_text)
            if isinstance(ret, dict):
                for key, value in ret.items():
                    if isinstance(value, dict):
                        summary.setdefault(key, {}).update(value)
                    elif isinstance(value, list):
                        summary.setdefault(key, []).extend(value)
                    else:
                        summary[key] = value
        except Exception as exc:
            summary.setdefault("errors", []).append(
                f"plugin_error:{fn.__name__}:{exc}"
            )


# ------------------------------------------------------------------
# Default summary plugins
# ------------------------------------------------------------------


@register_summary_plugin
def plugin_url_labels(summary: Dict[str, Any], ascii_text: str, utf16_text: str) -> Dict[str, Any] | None:
    """Flag suspicious URLs based on simple path heuristics."""
    urls = (summary.get("iocs", {}).get("urls") or [])
    risky = [
        u
        for u in urls
        if any(
            token in u
            for token in ("/login", "/admin", "/gate", "/panel", "/update", "/bot")
        )
    ]
    if not risky:
        return None
    summary.setdefault("hints", {}).update({"risky_urls_present": True})
    return {"iocs_extra": {"risky_urls": risky[:100]}}  # keep it compact


@register_summary_plugin
def plugin_email_buckets(summary: Dict[str, Any], ascii_text: str, utf16_text: str) -> Dict[str, Any] | None:
    """Split emails into 'free' and 'corporate/other' buckets."""
    emails = summary.get("iocs", {}).get("emails") or []
    if not emails:
        return None
    free: list[str] = []
    corp: list[str] = []
    for e in emails:
        (free if mh_email_class(e) == "free" else corp).append(e)
    return {
        "iocs_extra": {
            "emails_free": sorted(set(free))[:200],
            "emails_corp": sorted(set(corp))[:200],
        }
    }


@register_summary_plugin
def plugin_persistence_heuristics(summary: Dict[str, Any], ascii_text: str, utf16_text: str) -> None:
    """Mark artifacts that hint at Windows persistence mechanisms."""
    t = (ascii_text + "\n" + utf16_text).lower()
    keys = (
        "\\run\\",
        "\\runonce\\",
        "currentversion\\run",
        "currentversion\\runonce",
        "taskschd.msc",
        "schtasks",
        "hkcu\\software\\microsoft\\windows\\currentversion\\run",
    )
    if any(k in t for k in keys):
        summary.setdefault("hints", {}).update({"persistence_possible": True})


@register_summary_plugin
def plugin_lolbins_intensifier(summary: Dict[str, Any], ascii_text: str, utf16_text: str) -> None:
    """Mark cases where known LOLBINs appear alongside suspicious patterns."""
    t = (ascii_text + "\n" + utf16_text).lower()
    hits = [b for b in _SUSP_LOLBINS if (" " + b + " ") in (" " + t + " ")]
    if hits:
        summary.setdefault("hints", {}).update(
            {"lolbins_used": True, "lolbins_list": hits[:20]}
        )
