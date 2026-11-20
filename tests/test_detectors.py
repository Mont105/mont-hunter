import pytest

from monthunter import detectors as d


@pytest.mark.parametrize(
    "fn,positive,negative",
    [
        (d.d_pyinstaller, b"xx pyi-runtime-tmpdir xx", b"plain"),
        (d.d_pyinstaller, b"PYZ\x00abc", b"PYZ"),
        (d.d_upx, b"..UPX!..", b"UPX"),
        (d.d_nsis, b"Nullsoft.NSIS", b"Nullsoft"),
        (d.d_inno, b"Inno Setup Setup Data", b"Setup"),
        (d.d_msi_cab, b"MSCF\x00\x00", b"abcd"),
        (d.d_jar, b"PK\x03\x04 META-INF/MANIFEST.MF", b"META-INF/MANIFEST.MF"),
        (d.d_autoit, b"AU3!EA06", b"Au3"),
        (d.d_net, b"BSJB", b"bsjb"),
        (d.d_go, b"Go Build ID: abc", b"golang"),
        (d.d_rust, b"rust_eh_personality", b"rusty"),
        (d.d_node_pkg, b"snapshot_blob.bin", b"nothing"),
        (d.d_electron, b"app.asar", b"app"),
        (d.d_appimage, b"\x7fELF....AppImage", b"MZ....AppImage"),
        (d.d_sfx_rar, b"Rar!\x1a\x07\x00", b"Rar!"),
    ],
)
def test_detector_positive_and_negative(fn, positive, negative):
    assert fn(positive) is True
    assert fn(negative) is False


def test_detectors_on_empty_data():
    for name in dir(d):
        if name.startswith("d_"):
            assert getattr(d, name)(b"") is False
