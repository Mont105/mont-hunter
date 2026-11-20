#!/usr/bin/env bash
# Install MontHunter's external tools on Arch Linux. Review before running; uses sudo.
set -euo pipefail
sudo pacman -S --needed --noconfirm yara 7zip upx cabextract innoextract ssdeep binutils \
  qemu-base xorriso perl-image-exiftool radare2
command -v asar >/dev/null 2>&1 || npm i -g asar || true
# Real PyInstaller extractor in its own venv
if ! command -v pyinstxtractor-ng >/dev/null 2>&1; then
  python3 -m venv "$HOME/.local/share/pyinstxtractor-venv"
  "$HOME/.local/share/pyinstxtractor-venv/bin/pip" install -q pyinstxtractor-ng
  mkdir -p "$HOME/.local/bin"
  ln -sf "$HOME/.local/share/pyinstxtractor-venv/bin/pyinstxtractor-ng" "$HOME/.local/bin/pyinstxtractor-ng"
fi
echo "[OK] tools installed"
