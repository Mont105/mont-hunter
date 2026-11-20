#!/usr/bin/env bash
# One-time setup of the MontHunter QEMU sandbox guest image (Arch cloud image, checksum-verified).
# Usage: scripts/setup_sandbox_arch.sh [dest_dir]   (default: ~/vm/monthunter-lab)
set -euo pipefail
DEST="${1:-$HOME/vm/monthunter-lab}"
BASE=https://geo.mirror.pkgbuild.com/images/latest
mkdir -p "$DEST"; cd "$DEST"
curl -fsSL -o base.qcow2 "$BASE/Arch-Linux-x86_64-cloudimg.qcow2"
curl -fsSL -o base.sha256 "$BASE/Arch-Linux-x86_64-cloudimg.qcow2.SHA256"
echo "$(cut -d' ' -f1 base.sha256)  base.qcow2" | sha256sum -c -
cp base.qcow2 guest.qcow2
qemu-img resize -q guest.qcow2 +6G
# Installs strace and Wine in the guest (the ONLY networked VM step); sample runs have no network at all.
python3 -m monthunter.cli --sandbox-prepare "$DEST/guest.qcow2" --with-wine
echo "[OK] guest image ready: $DEST/guest.qcow2"
echo "Run: mont-hunter sample --sandbox $DEST/guest.qcow2"
