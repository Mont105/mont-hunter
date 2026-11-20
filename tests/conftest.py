"""Shared fixtures. All samples are tiny synthetic byte strings; nothing is ever executed."""

from __future__ import annotations

import json
from pathlib import Path

import pytest


@pytest.fixture
def make_sample(tmp_path):
    """Write synthetic bytes to a file inside tmp_path and return its Path."""

    def _make(name: str, data: bytes) -> Path:
        p = tmp_path / name
        p.write_bytes(data)
        return p

    return _make


@pytest.fixture
def load_summary():
    def _load(out_dir: Path, sha256: str) -> dict:
        raw = json.loads((Path(out_dir) / "files" / sha256 / "summary.json").read_text(encoding="utf-8"))
        return raw["summary"]

    return _load
