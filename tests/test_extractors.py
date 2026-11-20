import os

from monthunter.extractors import _sanitize_tree, analyze_pe_structure


def test_sanitize_tree_removes_symlinks_keeps_regular_files(tmp_path):
    base = tmp_path / "extract"
    base.mkdir()
    outside = tmp_path / "secret.txt"
    outside.write_text("x")
    (base / "ok.txt").write_text("fine")
    os.symlink(outside, base / "link.txt")

    _sanitize_tree(base)

    assert (base / "ok.txt").exists()
    assert not (base / "link.txt").exists()
    assert outside.exists()


def test_analyze_pe_structure_non_pe(tmp_path):
    p = tmp_path / "x.bin"
    p.write_bytes(b"not a pe file")
    res = analyze_pe_structure(p)
    assert res["ok"] is False and res["reason"] == "not_pe"


def test_analyze_pe_structure_missing(tmp_path):
    assert analyze_pe_structure(tmp_path / "nope")["reason"] == "not_found"


def test_sanitize_tree_removes_symlinked_directory(tmp_path):
    base = tmp_path / "extract"
    base.mkdir()
    outside = tmp_path / "outside_dir"
    outside.mkdir()
    (outside / "f.txt").write_text("x")
    os.symlink(outside, base / "dirlink")

    _sanitize_tree(base)

    assert not (base / "dirlink").exists() and not (base / "dirlink").is_symlink()
    assert (outside / "f.txt").exists()


def test_sanitize_tree_sibling_prefix_is_not_inside_root(tmp_path):
    # "/x/out" must not be treated as the parent of "/x/out_evil/..."
    base = tmp_path / "out"
    base.mkdir()
    evil = tmp_path / "out_evil"
    evil.mkdir()
    (evil / "f").write_text("x")
    os.symlink(evil / "f", base / "escape")

    _sanitize_tree(base)

    assert not (base / "escape").is_symlink()
    assert (evil / "f").exists()


def test_sanitize_tree_file_count_limit(tmp_path):
    base = tmp_path / "e"
    base.mkdir()
    for i in range(5):
        (base / f"f{i}.txt").write_text("x")
    res = _sanitize_tree(base, max_files=3)
    assert res["files"] == 3 and res["removed"] == 2 and res["truncated"] is True
    assert len([p for p in base.iterdir()]) == 3


def test_sanitize_tree_byte_limit(tmp_path):
    base = tmp_path / "e"
    base.mkdir()
    (base / "a").write_bytes(b"x" * 60)
    (base / "b").write_bytes(b"x" * 60)
    res = _sanitize_tree(base, max_bytes=100)
    assert res["files"] == 1 and res["bytes"] == 60 and res["truncated"] is True


def test_sanitize_tree_within_limits_not_truncated(tmp_path):
    base = tmp_path / "e"
    base.mkdir()
    (base / "a").write_text("hi")
    assert _sanitize_tree(base)["truncated"] is False
