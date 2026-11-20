#!/bin/bash
# MontHunter Windows lab: an outer Linux VM (QEMU/KVM) that runs a disposable inner Windows VM.
# Run it as the unprivileged lab user (member of group kvm only, no sudo, own home on the SSD):
#   sudo -u mhlab /home/mhlab/winlab/winlab.sh <command>
#
# Isolation rules enforced here:
#   * base images are sealed (chmod 444 + stored sha256) and verified before EVERY use
#   * every run is a qcow2 layer on top of the base (qemu-img create -b ...), deleted afterwards
#   * outer VM network: "none" in run mode; in maintenance mode only a restrict=on user net with the
#     ssh port forwarded to 127.0.0.1 (no outbound access). "provision" is the one networked step.
#   * samples enter as a read-only CD, results leave over the serial console. No shared folders.
set -euo pipefail

W="${WINLAB:-/home/mhlab/winlab}"
SSH_PORT=2222
OUTER_MEM=${OUTER_MEM:-6144}
OUTER_CPUS=${OUTER_CPUS:-6}
ISO="$W/iso/win10-ltsc2021-eval.iso"

seal() {  # seal FILE : read-only + recorded checksum
  local f="$1"
  chmod 644 "$f" 2>/dev/null || true
  sha256sum "$f" | cut -d' ' -f1 > "$f.sha256"
  chmod 444 "$f" "$f.sha256"
  echo "sealed $f ($(cat "$f.sha256" | cut -c1-16)...)"
}

verify() {  # verify FILE : must be read-only and match the stored checksum
  local f="$1"
  [ -f "$f" ] && [ -f "$f.sha256" ] || { echo "VERIFY FAIL: missing $f or checksum" >&2; return 1; }
  if [ -w "$f" ]; then echo "VERIFY FAIL: $f is writable" >&2; return 1; fi
  local got; got=$(sha256sum "$f" | cut -d' ' -f1)
  [ "$got" = "$(cat "$f.sha256")" ] || { echo "VERIFY FAIL: checksum mismatch for $f" >&2; return 1; }
  echo "verified $(basename "$f")"
}

layer() {  # layer BASE OUT : instant copy-on-write layer over a sealed base
  qemu-img create -q -f qcow2 -b "$1" -F "$2" "$3" 2>/dev/null || qemu-img create -q -f qcow2 -b "$1" -F qcow2 "$3"
}

# qemu_outer MODE NAME DRIVE_ARGS... ; MODE = provision | maint | run
qemu_outer() {
  local mode="$1" name="$2"; shift 2
  local net
  case "$mode" in
    provision) net=(-nic "user,hostfwd=tcp:127.0.0.1:$SSH_PORT-:22") ;;   # networked: package install only
    maint)     net=(-netdev "user,id=n0,restrict=on,hostfwd=tcp:127.0.0.1:$SSH_PORT-:22" -device virtio-net-pci,netdev=n0) ;;
    run)       net=(-nic none) ;;
    *) echo "bad mode" >&2; return 2 ;;
  esac
  qemu-system-x86_64 -name "winlab-$name" -machine q35,accel=kvm -cpu host -m "$OUTER_MEM" -smp "$OUTER_CPUS" \
    -display none -vga std -nodefaults -no-reboot \
    -monitor "unix:$W/runs/$name.mon,server,nowait" -serial "file:$W/log/$name.serial" \
    -daemonize -pidfile "$W/runs/$name.pid" "${net[@]}" "$@"
}

cmd_provision() {  # one-time: install qemu/tcpdump/python inside the outer image, then seal it as the base
  local key="${1:?usage: provision PUBKEY_FILE}"
  [ -f "$W/base/outer-base.qcow2" ] && { echo "outer-base already sealed"; return 0; }
  mkdir -p "$W/seed/prov"
  cat > "$W/seed/prov/user-data" <<EOF
#cloud-config
ssh_authorized_keys:
  - $(cat "$key")
runcmd:
  - [ sh, -c, "pacman -Sy --noconfirm --needed qemu-base tcpdump python xorriso e2fsprogs > /dev/ttyS0 2>&1; echo PROVISIONED > /dev/ttyS0" ]
EOF
  printf 'instance-id: prov-%s\nlocal-hostname: winlab-outer\n' "$(date +%s)" > "$W/seed/prov/meta-data"
  xorriso -as mkisofs -quiet -V cidata -J -r -o "$W/seed/prov.iso" "$W/seed/prov" 2>/dev/null
  qemu_outer provision prov \
    -drive "file=$W/work/outer-prov.qcow2,if=none,id=sys,format=qcow2" -device virtio-blk-pci,drive=sys,bootindex=1 \
    -drive "file=$W/seed/prov.iso,if=none,id=seed,media=cdrom,readonly=on" -device ide-cd,drive=seed
  echo "provisioning VM started (ssh 127.0.0.1:$SSH_PORT); wait for PROVISIONED in $W/log/prov.serial"
}

cmd_seal_outer() {  # after provisioning + clean shutdown
  seal "$W/work/outer-prov.qcow2"
  mv "$W/work/outer-prov.qcow2" "$W/base/outer-base.qcow2"; mv "$W/work/outer-prov.qcow2.sha256" "$W/base/outer-base.qcow2.sha256"
}

cmd_verify() { verify "$W/base/outer-base.qcow2"; [ -f "$W/base/win10-golden.qcow2" ] && verify "$W/base/win10-golden.qcow2" || true; }

cmd_maint() {  # outer on a layer, restricted network + ssh forward, extra args are extra qemu drives
  local name="${1:-maint}"; shift || true
  verify "$W/base/outer-base.qcow2"
  rm -f "$W/runs/$name.qcow2"; layer "$W/base/outer-base.qcow2" qcow2 "$W/runs/$name.qcow2"
  mkdir -p "$W/seed/$name"; printf '#cloud-config\n{}\n' > "$W/seed/$name/user-data"
  printf 'instance-id: %s-%s\nlocal-hostname: winlab-outer\n' "$name" "$(date +%s)" > "$W/seed/$name/meta-data"
  xorriso -as mkisofs -quiet -V cidata -J -r -o "$W/seed/$name.iso" "$W/seed/$name" 2>/dev/null
  qemu_outer maint "$name" \
    -drive "file=$W/runs/$name.qcow2,if=none,id=sys,format=qcow2" -device virtio-blk-pci,drive=sys,bootindex=1 \
    -drive "file=$W/seed/$name.iso,if=none,id=seed,media=cdrom,readonly=on" -device ide-cd,drive=seed "$@"
}

cmd_seal_golden() {  # after the stage-2 shutdown: work disk becomes the sealed golden image + a sealed backup copy
  [ -f "$W/base/win10-golden.qcow2" ] && { echo "golden already sealed"; return 0; }
  mv "$W/work/win10-work.qcow2" "$W/base/win10-golden.qcow2"
  seal "$W/base/win10-golden.qcow2"
  cp "$W/base/win10-golden.qcow2" "$W/base/win10-golden.bak.qcow2"
  cp "$W/base/win10-golden.qcow2.sha256" "$W/base/win10-golden.bak.qcow2.sha256"
  chmod 444 "$W/base/win10-golden.bak.qcow2" "$W/base/win10-golden.bak.qcow2.sha256"
  echo "golden + backup sealed"
}

cmd_restore_golden() {  # golden failed verification: rebuild it from the verified backup
  verify "$W/base/win10-golden.bak.qcow2" || { echo "backup is also bad: rebuild the image" >&2; return 1; }
  rm -f "$W/base/win10-golden.qcow2" "$W/base/win10-golden.qcow2.sha256"
  cp "$W/base/win10-golden.bak.qcow2" "$W/base/win10-golden.qcow2"
  cp "$W/base/win10-golden.bak.qcow2.sha256" "$W/base/win10-golden.qcow2.sha256"
  chmod 444 "$W/base/win10-golden.qcow2" "$W/base/win10-golden.qcow2.sha256"
  verify "$W/base/win10-golden.qcow2"
}

# run SAMPLE_ISO TIMEOUT_S : detonate in the inner Windows VM, print the serial log (results) on stdout
cmd_run() {
  local iso="${1:?usage: run SAMPLE_ISO TIMEOUT}" t="${2:-60}"
  [[ "$t" =~ ^[0-9]+$ ]] && [ "$t" -ge 5 ] && [ "$t" -le 900 ] || { echo "bad timeout" >&2; return 2; }
  verify "$W/base/outer-base.qcow2" >&2
  verify "$W/base/win10-golden.qcow2" >&2 || { cmd_restore_golden >&2; }
  local name="run-$$-$(date +%s)"
  local layer="$W/runs/$name.qcow2" seed="$W/seed/$name"
  layer "$W/base/outer-base.qcow2" qcow2 "$layer"
  mkdir -p "$seed"
  {
    printf '#cloud-config\nwrite_files:\n  - path: /usr/local/bin/mh-outer.sh\n    permissions: "0755"\n    content: |\n'
    sed -e "s/__TIMEOUT__/$t/" "$W/outer-agent.sh" | sed 's/^/      /'
    printf 'runcmd:\n  - [ /usr/local/bin/mh-outer.sh ]\n'
  } > "$seed/user-data"
  printf 'instance-id: %s\nlocal-hostname: winlab-outer\n' "$name" > "$seed/meta-data"
  xorriso -as mkisofs -quiet -V cidata -J -r -o "$seed.iso" "$seed" 2>/dev/null
  : > "$W/log/$name.serial"
  # Outer VM: NO network device. Golden image and sample are attached read-only.
  qemu_outer run "$name" \
    -drive "file=$layer,if=none,id=sys,format=qcow2" -device virtio-blk-pci,drive=sys,bootindex=1 \
    -drive "file=$seed.iso,if=none,id=seed,media=cdrom,readonly=on" -device ide-cd,drive=seed,bus=ide.0 \
    -drive "file=$iso,if=none,id=smp,media=cdrom,readonly=on,format=raw" -device ide-cd,drive=smp,bus=ide.1 \
    -drive "file=$W/base/win10-golden.qcow2,if=none,id=gold,format=qcow2,readonly=on" -device virtio-blk-pci,drive=gold,serial=wingold
  local pid; pid=$(cat "$W/runs/$name.pid")
  local waited=0 limit=$((t + 900))
  while kill -0 "$pid" 2>/dev/null && [ "$waited" -lt "$limit" ]; do sleep 2; waited=$((waited + 2)); done
  kill "$pid" 2>/dev/null || true
  cat "$W/log/$name.serial"
  rm -f "$layer" "$seed.iso" "$W/runs/$name.pid" "$W/runs/$name.mon" "$W/log/$name.serial"
  rm -r "$seed"
}

cmd_stop() { local n="${1:-maint}"; [ -f "$W/runs/$n.pid" ] && kill "$(cat "$W/runs/$n.pid")" 2>/dev/null || true; rm -f "$W/runs/$n.pid" "$W/runs/$n.mon"; }

"cmd_${1:?commands: provision seal_outer verify maint stop}" "${@:2}"
