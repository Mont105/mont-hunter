# MontHunter

MontHunter is a static triage tool for suspicious binaries and installers. It unpacks what it can, extracts indicators of compromise (IOCs), gives the sample a risk score from 0 to 100 and writes a report you can open in a browser. An optional sandbox runs the sample in an isolated virtual machine and records what it does.

It handles PE files, common installers, Electron ASAR packages and PyInstaller bundles.

## Install

You need Python 3.10 or newer.

```bash
pip install .
pip install .[decompile]   # optional PyInstaller decompilers
pip install .[rich]        # optional nicer console output
```

The external tools are optional. MontHunter uses the ones it finds in your PATH: `7z`, `strings`, `innoextract`, `cabextract`, `asar`, `upx`, a PyInstaller extractor (`pyinstxtractor`) and `yara`. On Arch Linux, `scripts/install_mont_deps_arch.sh` installs them. Read it first, because it uses sudo.

## Use

```bash
mont-hunter sample.exe --out mont_out
```

The output folder contains:

- `report.html`, a readable overview
- `index.json`, the summary of the run
- `iocs.csv`, every IOC in a flat file
- `files/<sha256>/summary.json`, the details for each file

Useful options: `--extract` to try the extractors, `--json` to print the summary, `--jobs N`, `--max-size BYTES`, `--timeout-per-tool SECONDS` and `--yara-rules FILE_OR_DIR`. Run `mont-hunter --help` for the full list.

## What it detects

- Packer and installer fingerprints, PE anomalies (RWX or packer-named sections, no imports, a bad timestamp, a large overlay), the imphash and risky API imports.
- IOCs: URLs, domains, IPs, emails, IOCs hidden in Base64, Bitcoin and Monero wallets validated by checksum, and Discord webhook and Telegram bot exfiltration channels. File names and well-known infrastructure are filtered out of the domain list.
- Embedded PE images, raw or in Base64, and decoded `powershell -enc` commands.
- 29 signature rules in JSON, each tagged with MITRE ATT&CK technique IDs.
- MD5, SHA-1, SHA-256 and an ssdeep fuzzy hash.
- A risk score from 0 to 100 with the reasons behind it, in `summary.risk`.

## Dynamic analysis in a QEMU sandbox

`--sandbox IMAGE` runs each sample in a disposable QEMU/KVM virtual machine and reports what it does: network connection attempts, persistence writes, shell or downloader execution, log deletion, setuid, memfd and ptrace use.

The isolation lives in `monthunter/sandbox.py` and the tests check it:

- The VM has no network device (`-nic none`), no shared folders, no USB and no display.
- The guest disk is opened with `snapshot=on`, so the base image is never modified.
- The sample reaches the guest as a read-only CD-ROM, and results come back over the serial console only.
- A hard wall-clock timeout applies. The VM powers off at the end and the temporary ISOs and overlays are deleted.

ELF files and scripts run natively in a Linux guest and are observed with `strace`. Windows PE files (`.exe`, and `.dll` through `rundll32`) run under Wine in the same guest, so you don't need a Windows licence. `--sandbox-os` takes `auto`, `linux` or `windows`; the default, `auto`, reads the PE header. For Windows samples MontHunter reports process creation and LOLBIN use (PowerShell `-enc`, `schtasks`, `vssadmin delete shadows`, `mshta`), DNS lookups and connection attempts, and a before and after diff of the registry (Run keys, services, IFEO, Winlogon, Defender policies) and of the files created on `C:`.

Wine is not Windows. Malware that checks for real Windows internals, needs a GUI or a driver, targets one Windows build or detects Wine will behave differently or won't run, so read "no findings" as "no findings under Wine". Also keep the host as your trust boundary: run this on a machine where a VM escape is an acceptable loss, and keep QEMU updated.

Setup on Arch Linux:

```bash
scripts/install_mont_deps_arch.sh
scripts/setup_sandbox_arch.sh    # downloads and verifies an Arch cloud image, installs strace and Wine in it
mont-hunter suspicious.elf --sandbox ~/vm/monthunter-lab/guest.qcow2 --sandbox-timeout 60
mont-hunter suspicious.exe --sandbox ~/vm/monthunter-lab/guest.qcow2 --sandbox-timeout 60
```

`--sandbox-prepare IMAGE [--with-wine]` is the only step that gives the VM network access, to install `strace` and Wine. Never attach a sample then.

## ThreatFox matching

MontHunter can check file hashes, extracted IOCs and the connections a sample tries inside the sandbox against the [ThreatFox](https://threatfox.abuse.ch/) feed from abuse.ch. The matching is offline. The feed is cached on your machine, so nothing from your samples goes to abuse.ch.

```bash
export THREATFOX_AUTH_KEY=...    # free key from https://auth.abuse.ch/, or use --threatfox-key-file FILE
mont-hunter --threatfox-update   # downloads the last 7 days to ~/.cache/monthunter/threatfox.json
mont-hunter sample.elf --sandbox ~/vm/monthunter-lab/guest.qcow2 --threatfox
```

The key is read from the environment or from a file, never from the command line, and it is never written to the cache or the reports. The API only returns the last 7 days of IOCs, so refresh the cache regularly. A match adds `threatintel.matches` to the summary, a section in `report.html` and `threatfox_*` rows in `iocs.csv`, and it raises the risk score. ThreatFox lists IOCs, not samples. To get samples, use MalwareBazaar.

## Real Windows lab (optional)

`--sandbox-winvm` runs Windows samples that Wine can't handle on a real Windows 10 Enterprise LTSC evaluation image, downloaded from Microsoft and nested inside a Linux VM. Everything sits on one SSD under an unprivileged user (`mhlab`, in the `kvm` group only, with no sudo and a home folder with mode 700). `scripts/winlab.sh` builds and drives the lab.

- The outer Linux VM has no network device while it runs. In maintenance mode it only gets a `restrict=on` user network with an SSH forward on 127.0.0.1 and no outbound access. The inner Windows VM always runs with `-nic none`.
- The base images (`outer-base`, `win10-golden` and a backup copy) are sealed with `chmod 444` and `chattr +i`, and their sha256 is checked before every use. A corrupted golden image is restored from the verified backup.
- Each run is a qcow2 layer over the base (`qemu-img create -b`) that is deleted at the end. Nothing is written to a base image.
- The sample enters as a read-only CD and results leave over the serial port. There are no shared folders and no clipboard.
- Results include process creation with command lines (Security event 4688), Run keys, IFEO, Winlogon, new services, scheduled tasks, WMI consumers, and the files dropped in the startup folder, all mapped to MITRE ATT&CK.

The inner VM has no network card, so network attempts aren't observed there. Use the Wine engine for connection and DNS traces. The evaluation licence lasts 90 days, so rebuild the golden image when it expires.

## Tests

```bash
pip install pytest
pytest -q
```

The sandbox tests need a real guest image and are skipped unless you set `MH_SANDBOX_IMAGE`:

```bash
MH_SANDBOX_IMAGE=~/vm/monthunter-lab/guest.qcow2 pytest -q tests/test_sandbox.py tests/test_sandbox_windows.py
```

The Windows test needs mingw-w64. The fixtures are harmless.

## License

MIT. See [LICENSE](LICENSE).
