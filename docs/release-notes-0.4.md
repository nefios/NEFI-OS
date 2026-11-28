# NEFI OS 0.4 — Blue Team Edition

NEFI OS 0.4 turns the Security Center into a complete **detect → investigate → respond** workstation: a detection
engine running as a system service, forensics with chain of custody, network monitoring, incident handling and
prevention checks with one-click fixes. The installer adds GNOME and Xfce, a Btrfs root with snapshots and kernel
hardening boot parameters.

Base: Debian 13 "trixie" (latest trixie, trixie-updates and trixie-security packages), Linux 6.12.118,
KDE Plasma 6 (default), GNOME or Xfce, NEFI Security Center (PyQt6).

## Highlights

- **Detection engine `nefi-detectd`** — a root service that replaces the in-window EDR. It reads kernel telemetry
  from auditd, Falco and Suricata events, applies 48 built-in Sigma rules mapped to MITRE ATT&CK, and raises alerts
  with process tree and investigation view.
- **DFIR with chain of custody** — evidence IDs, signed SHA-256 manifests, append-only custody log, full RAM
  acquisition (AVML + Volatility 3), structured timeline, write-blocked disk acquisition.
- **Response** — incidents with timeline and reports, guided playbooks, host isolation, process and file
  containment, recovery checklist.
- **Prevention** — vulnerability management with CISA KEV priority, attack surface view, kernel and SSH assessment
  with fixes that can be undone.
- **Btrfs root with Snapper** — snapshots at install, at every boot and on a timeline; the Snapshots page works
  out of the box.
- **Three desktops** — KDE Plasma (default), GNOME and Xfce in the installer's Software selection.

## Installer

| Area | 0.3 | 0.4 |
| --- | --- | --- |
| Root filesystem | ext4 in encrypted LVM | **Btrfs** in encrypted LVM, zstd compression |
| Snapshots | Not available | **Snapper** configured at install, first snapshot + one per boot |
| Security Score, Backup & Recovery | 8/100 | **92/100** |
| Desktops | KDE Plasma | KDE Plasma (default), **GNOME**, **Xfce** |
| Kernel | 6.12.x | **6.12.118** |
| Boot to graphical installer | Black box over the background for about 6 s | No black box; a few seconds of plain black while the kernel starts |
| Services failed after first boot | `suricata`, `clamav-freshclam(-once)` | **None** |

- Kernel hardening boot parameters (KSPP): `init_on_alloc=1`, `slab_nomerge`, `page_alloc.shuffle=1`,
  `randomize_kstack_offset=on`, `vsyscall=none`.
- AIDE excludes `/.snapshots`, so the first-boot baseline takes minutes.
- Suricata listens on the real network interface; ClamAV is active after the first boot.

## Security Center

**Detection**
- Detections: MITRE ATT&CK tactic and technique, process tree, acknowledge and false-positive exceptions.
- Integrity & Persistence: protected baseline for critical files, autorun entries, SUID programs, accounts and
  listening ports; changes wait for approval, recorded in a hash-chained audit log.
- Detection Rules: built-in and custom Sigma rules, correlation rules, ATT&CK coverage, optional SigmaHQ rules.
- Threat Hunting: execution history with process tree, live osquery queries.
- Canary files, YARA scan of programs started from temporary directories, syslog forwarding (RFC 5424 over
  TCP/TLS), optional Wazuh agent.

**DFIR**
- Evidence & Chain of custody, Memory Forensics, Timeline (Timesketch-compatible), Disk Forensics.
- Forensic evidence is readable by root only.

**Monitoring**
- Network IDS, DNS Monitoring, Traffic & Flows from Suricata events, kept for 30 days.
- Packet Capture with time and size limits, built-in summary, preservation as signed evidence.

**Response**
- Incidents, Playbooks, Host Isolation (with automatic restore unless confirmed, and `nefi-ir-recover`),
  Containment, Recovery.

**Prevention**
- Vulnerability Management (Debian Security Tracker, CISA KEV), Attack Surface, Kernel Hardening and SSH Security
  assessment, "Apply fix" with Undo.

**System**
- Security Score over time, points gained per fix, advice on what to fix first, HTML report export.

## Fixes

- Professional profile really blocks USB storage; Paranoid profile no longer disables keyboards and hubs.
- Incident Response no longer shows "active" after deactivation, and stays active if the isolation table cannot
  be removed.
- Threat Intelligence: the VirusTotal API key no longer appears in the process list, and the VirusTotal response
  can no longer execute code.
- Honeypot logs are written to `~/.local/share/nefi/`; Log Viewer shows the right Kernel, Authentication and
  Firewall entries; Process Monitor no longer flags `systemd-timesyncd`; snapshot numbers are validated.
- ISO built from a clean clone no longer fails at "Select and install software".
- Detection: no false critical "Root shell" alert when the Security Center runs a task with pkexec; no false
  alerts at login (`systemd-executor`, `pam-tmpdir-helper`) or from the system assessment, which no longer reads
  `/etc/shadow`.
- Snapshots page: no password prompt every 5 seconds; "Setup Snapper" hidden when Snapper is configured.
- The first user is in the `systemd-journal` group, so the Log Viewer reads the journal without a password.
- Plaso is found under Debian's command names; the Security Center uses SVG icons instead of colour emoji.

The full list is in [CHANGELOG.md](../CHANGELOG.md).

## Known limitations

- A few seconds of black screen remain while the kernel starts the graphical installer.
- Suricata listens on the interface found at install time; after switching interface (for example from cable to
  Wi-Fi) `/etc/suricata/suricata.yaml` must be updated.
- Xfce runs on X11, without Wayland's isolation between applications.
- On first boot the AIDE baseline runs for a few minutes at low priority.
- The Btrfs root and Snapper are set up by the installer: systems installed with 0.3 (ext4) do not get snapshots.
- Configuration Audit reports "System disk encrypted (LUKS)" as failed on the Btrfs root although the disk is
  encrypted. Fix planned for 0.4.1.
- While Suricata runs, "Promiscuous mode" is reported on its interface, and UDP sockets that Firefox opens for
  HTTP/3 are reported as new listening ports; together they can raise the critical "Several attack stages on this
  machine". Mark them with "False positive…". Fix planned for 0.4.1.
- No task is pre-checked in the Software selection: choose a desktop, core and default yourself.
- The Snapshots page asks for the administrator password at every Refresh.
- VirtualBox: use VMSVGA with 128 MB of video memory; with EFI the disk passphrase is asked in text mode.
- Honeypot times are shown in UTC; the action buttons in the Snapshots list are truncated.

Tested in QEMU/KVM and in VirtualBox, with BIOS and with EFI + Secure Boot + TPM 2.0.

## Download and verify

The ISO is split into parts because of GitHub's 2 GB limit. Join and verify:

```bash
cat nefi-os-0.4-amd64.iso.part* > nefi-os-0.4-amd64.iso
gpg --import NEFI-OS-RELEASE-KEY.asc
gpg --verify SHA256SUMS.asc SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing
```

The release key fingerprint must be `0CC0 887C BCC8 ED05 E308  FBBA ECF8 8C1D 9133 66D3`.
See [keys/README.md](../keys/README.md).
