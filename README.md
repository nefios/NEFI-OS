# NEFI OS

**Network Event Forensics Intelligence** — a Linux distribution based on **Debian 13 "trixie"**
for **defensive security (Blue Team)**: hardening, monitoring, DFIR, incident response and
threat hunting, all from one interface, the **NEFI Security Center**.

> *Enterprise-grade defense without enterprise complexity.*
> NEFI OS contains **no offensive tools**.

> ⚠️ **Status: pre-release (0.2).** Tested in virtual machines. Not yet recommended for production.

## Features

- **NEFI Security Center** (PyQt6), organized in six sections:
  - **System** – Security Score, System Status, Secure Boot / TPM monitor, Snapshot Manager (Btrfs + Snapper)
  - **Prevention** – Hardening Profiles (Home / Professional / Paranoid), Hardening Check, Zero Trust, USB Guardian, Privacy Control, Sandbox (Firejail)
  - **Detection** – EDR, Threat Intelligence + IOC Manager (VirusTotal), Vulnerability Scanner (Lynis), Honeypot
  - **DFIR** – one-click Forensics collection, Integrity Control (AIDE), Log Viewer
  - **Monitoring** – Security Status, Network Monitor, Process Monitor
  - **Response** – Incident Response mode, **Guardian**: a local AI assistant (Ollama + Mistral) that works offline
- **Secure by default**: nftables firewall (inbound default-deny), AppArmor, auditd rules, kernel hardening (sysctl),
  automatic security updates, SSH root login disabled, no root password (first user gets `sudo`)
- **Blue Team tools** preinstalled: Suricata, YARA, ClamAV, rkhunter, chkrootkit, Lynis, AIDE, nmap, tcpdump
  (+ optional DFIR set: Sleuth Kit, Autopsy, dc3dd, foremost, binwalk, Wireshark…)
- **KDE Plasma 6** desktop with the NEFI theme
- **Graphical installer** (Debian Installer) with NEFI branding and a software selection screen

## Download

Get the ISO from the [**Releases**](../../releases) page.
GitHub limits files to 2 GB, so the ISO is split in parts: download all the `.part` files
and join them.

**Linux / macOS**
```bash
cat nefi-os-0.2-amd64.iso.part* > nefi-os-0.2-amd64.iso
```
**Windows** (Command Prompt, in the download folder)
```bat
copy /b nefi-os-0.2-amd64.iso.part00 + nefi-os-0.2-amd64.iso.part01 nefi-os-0.2-amd64.iso
```

### Verify the download

```bash
gpg --import NEFI-OS-RELEASE-KEY.asc
gpg --verify SHA256SUMS.asc SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing
```
Both commands must report a good signature / `OK`. If not, **do not use the ISO**.

Write it to a USB stick with [balenaEtcher](https://etcher.balena.io/), Rufus (DD mode) or
`sudo dd if=nefi-os-0.2-amd64.iso of=/dev/sdX bs=4M status=progress`.

## System requirements

| | Minimum | Recommended |
|---|---|---|
| CPU | 64-bit (amd64) | 4+ cores |
| RAM | 4 GB | 8 GB+ (16 GB to use Guardian AI) |
| Disk | 30 GB | 60 GB+ (SSD) |
| Firmware | BIOS or UEFI | UEFI with Secure Boot |

During installation we recommend **"Guided – use entire disk and set up encrypted LVM"**.

## Build from source

Build host: Debian 13 (a VM with 8 GB RAM and ~100 GB free disk is fine).

```bash
sudo apt install live-build simple-cdd debian-cd reprepro xorriso python3-pil dpkg-dev
# simple-cdd >= 0.6.10 is required for trixie (0.6.9 tries to fetch i386 installer images)
git clone https://github.com/nefios/NEFI-OS.git ~/nefi-os
# Ollama is not stored in Git: download the official Linux amd64 release and place
#   bin/ollama  -> config/includes.chroot/usr/local/bin/ollama
#   lib/ollama/ -> config/includes.chroot/usr/local/lib/ollama/
~/nefi-os/installer/build.sh        # -> installer/images/nefi-os-<version>-amd64.iso
```

## Repository layout

| Path | Content |
|---|---|
| `config/includes.chroot/` | NEFI files (Security Center, modules, scripts, KDE theme, hardening) |
| `config/hooks/normal/` | system setup scripts (also run by the packages at install time) |
| `packages/` | `.deb` package generators: `nefi-security-center`, `nefi-desktop`, `nefi-ollama`, `nefi-branding`, `nefi-tasks` |
| `installer/` | Debian Installer build (simple-cdd profile, preseed, NEFI graphics) |
| `branding/` | installer artwork and generators |
| `tools/` | maintenance scripts |

## Security

Found a vulnerability? See [SECURITY.md](SECURITY.md) — please report it privately.

## License

NEFI OS code is released under the **GNU GPL v3.0** (see [LICENSE](LICENSE)).
Debian packages, Ollama and all other third-party components keep their own licenses;
their sources are available from the Debian archive and their upstream projects.

## Disclaimer

NEFI OS is provided "as is", without warranty. It helps you defend systems you own or are
authorized to protect; no software makes a system perfectly secure.
