# Changelog

All notable changes to NEFI OS are documented here.

## [0.4] — 2026-11

### Added
- GNOME and Xfce desktops in the installer's Software selection, alongside KDE Plasma
  (KDE stays the default; GNOME and Xfce use the Debian look).
- Kernel hardening boot parameters (KSPP): `init_on_alloc=1`, `slab_nomerge`,
  `page_alloc.shuffle=1`, `randomize_kstack_offset=on`, `vsyscall=none`
  (`/etc/default/grub.d/nefi-hardening.cfg`, package `nefi-branding`).
- Btrfs root filesystem (inside the encrypted LVM) with zstd compression, and Snapper configured
  at install time: a first snapshot after installation, one at every boot and timeline snapshots
  with automatic cleanup. The Security Center Snapshots page works out of the box
  (Backup & Recovery score from 8 to 92 in tests).
- Detection engine `nefi-detectd` (root service) replacing the in-window EDR: kernel telemetry from auditd
  (process execution, sensitive files, module loading), Falco and Suricata events, periodic scans.
- Detection > Detections: alerts with MITRE ATT&CK tactic and technique, process tree, investigation view,
  acknowledge and false-positive exceptions.
- Detection > Integrity & Persistence: protected baseline (immutable file) for critical files, autorun
  entries, SUID programs, accounts, administrators and listening ports. Changes wait for explicit approval;
  approvals are recorded in an append-only, hash-chained audit log.
- Detection > Detection Rules: 48 built-in rules in Sigma format (process behaviour, privilege escalation,
  credential access, persistence, rootkit indicators, network and DNS anomalies), correlation rules,
  import of custom Sigma rules, ATT&CK coverage view.
- Desktop notifications and a Security Score check for the detection engine.
- Response from an alert: terminate the process, block the address in both directions (nftables table
  `nefi_block`), or open Incident Response - always confirmed by the administrator and recorded.
- YARA scan of programs started from temporary directories and of new autorun or SUID files.
- Canary files (decoy credentials watched by auditd): any access raises a critical alert.
- Detection > Threat Hunting: search of the program execution history with process tree, and live osquery queries.
- Incident report: one self-contained HTML document per alert (MITRE ATT&CK, process tree, evidence).
- Copy of alerts and audit trail to an external syslog server (RFC 5424 over TCP/TLS), resuming after outages.
- SigmaHQ rules for Linux: download, filtering to what the engine supports, optional weekly update.
- osquery (official repository) as an extra telemetry source; Wazuh agent to join an existing Wazuh manager.
- Detection > Detection Settings page for all of the above.
- DFIR > Evidence & Chain of custody: unique evidence IDs, manifests with the SHA-256 of every file signed with a
  dedicated GPG key, operator and case, clock (NTP) state, append-only hash-chained custody log, verification,
  verified export to another disk, configurable evidence store, kernel audit of every access to the store.
- DFIR > Memory Forensics: full RAM acquisition with AVML (pinned, checksum-verified), acquisition checks,
  Volatility 3 with kernel symbol generation. The old 64 MB /dev/mem dump is gone.
- DFIR > Timeline: structured timeline (file MACB times, logins, services, packages, shell and browser history,
  executed programs, NEFI alerts, disk images) in Timesketch-compatible JSONL and CSV; optional Plaso.
- DFIR > Disk Forensics: write-blocked acquisition (block verified before reading) to E01 or raw with hash
  verification, software write blocker for new disks, Sleuth Kit / Foremost on images (bulk_extractor
  only if installed: it is not in Debian 13).
- System > Security Score: score over time with the list of checks that changed state, points gained by fixing
  each check ("+N pts", issues sorted by gain), advice on what to fix first, full report export (HTML).
- Prevention > Vulnerability Management: risk-based priority - CISA Known Exploited Vulnerabilities catalogue
  and packages of services reachable from the network come first.
- Prevention > Kernel Hardening / SSH Security: list of the fixes applied by NEFI with "Undo" (previous value restored).
- Monitoring > Network IDS, DNS Monitoring, Traffic & Flows: Suricata events (alerts, DNS, flows, TLS) summarized
  every two minutes into hourly counters kept for 30 days: alerts by signature, most requested and unusual DNS
  names, remote hosts, services, traffic per hour. Suricata interface check and fix, IDS rule update.
- Monitoring > Packet Capture: time- and size-limited captures (dumpcap or tcpdump) with validated filters, reason
  and account; built-in summary (conversations, DNS, TLS SNI, HTTP hosts), Wireshark as normal user, preservation
  as signed evidence.
- Response > Incidents: incident records with severity, category, status, append-only hash-chained timeline,
  notes, linked evidence, HTML and PDF report. Incidents can be opened from detection and IDS alerts.
- Response > Playbooks: guided procedures (malware, compromised account, network activity, data exposure,
  generic) with manual steps and whitelisted automatic actions; custom playbooks in /etc/nefi/ir/playbooks.
- Response > Host Isolation: full or selective isolation, automatic network restore unless confirmed, state kept
  true across reboots, emergency command `nefi-ir-recover`.
- Response > Containment: process freeze / resume / terminate (PID reuse safe), file quarantine with restore,
  IP / domain / SHA-256 indicator blocking and hash sweep.
- Response > Recovery: checklist with automatic verifications required before an incident is closed.
- Prevention › Vulnerability Management: CVEs of installed packages from the Debian Security Tracker (debsecan),
  with urgency, remote exploitability and available fixes; one-click security updates.
- Prevention › Attack Surface: listening ports with real firewall exposure, services, login accounts, SUID
  programs, scheduled jobs, interfaces.
- Prevention › Kernel Hardening Assessment: kernel command line and taint checks, one-click fixes.
- Prevention › SSH Security Assessment: 13 checks on the effective `sshd -T` configuration, fixes validated with
  `sshd -t` and undone if invalid; password login can only be disabled once an administrator has an SSH key.
- "Apply fix" on fixable checks (whitelisted fixes in `/opt/nefi/prevention/fix.py`).

### Changed
- Debian 13 base updated to the latest trixie, trixie-updates and trixie-security packages;
  Linux kernel 6.12.118.
- Installer disc label and version strings set to 0.4.
- Debian-owned files are detected from the Debian archive Contents index, downloaded from the
  build mirror and cached in `installer/tmp/contents/`. The build stops if the index cannot be
  checked (`NEFI_SKIP_DEBIAN_CHECK=1` is for offline test builds only).
- All NEFI packages use the maintainer `NEFI OS Developers <osnefi@gmail.com>`.
- Security Center modules from 0.3 that are no longer loaded (in-window EDR, forensics, Secure Boot monitor,
  security status) moved to `legacy/modules/`.

### Fixed
- ISO built from a clean clone (without a live-build chroot) failed at "Select and install software":
  Debian-owned files shipped by NEFI packages (`/etc/skel/.face`, `/etc/skel/.face.icon`) are now
  moved aside with `dpkg-divert`.
- Black box shown when starting the graphical installer: the GRUB terminal now uses the NEFI
  background full screen, and "Graphical install" boots with `loglevel=3`, so no kernel
  messages are shown before the installer starts.
- AIDE scanned Snapper snapshots: `/.snapshots` is now excluded, so the first-boot baseline takes
  minutes instead of scanning every snapshot.
- Suricata did not start: Debian's configuration listens on `eth0`; the installer now sets the
  real network interface.
- ClamAV: `clamav-freshclam-once` (service and timer) conflicted with the `clamav-freshclam`
  daemon on the log file and is now disabled; `clamd` no longer stays off when the signatures are
  downloaded after it starts on first boot (it waits up to 10 minutes for them).
- The AIDE configuration file was silently left out of the generated packages.
- Paranoid profile: the USB rule matched the device class (almost always 00) and could disable keyboards and
  hubs; it now refuses every USB interface except keyboards/mice (HID) and hubs.
- Hardening Check no longer runs commands through a shell; the SSH root-login check reads the effective
  configuration order (sshd_config.d first).
- Forensic evidence is readable by root only, whatever the caller's umask: collection folders 0700, files and
  archives 0600; administrators can still see the list of archives and their SHA-256. Evidence collected by older
  versions is locked down at the next collection.
- Professional profile really blocks USB storage (USB sticks, external disks, card readers): the
  usb-storage/uas drivers cannot load and USB mass-storage interfaces are not authorized. The Home profile
  removes the block. *Hardening Check* reports the effective state.
- Incident Response no longer shows "active" after deactivation: the state file holds one value per key and
  is written atomically; the page reads it as key/value and refreshes every 5 seconds. Deactivation fails
  (and IR stays active) if the isolation firewall table cannot be removed. Snapshots and session logs are
  readable by root only.
- Threat Intelligence: the VirusTotal API key no longer appears in the process list, and the VirusTotal
  response can no longer execute code; IOCs are validated and matched as plain text.
- Honeypot: SSH and HTTP honeypot logs are written to `~/.local/share/nefi/` and the page reads them from there.
- Log Viewer: the Kernel, Authentication and Firewall sources show the right journal entries; administrators
  are added to the `systemd-journal` group so the journal can be read.
- Process Monitor: no more false positives such as `systemd-timesyncd`; suspicious names are matched exactly.
- Snapshots: snapshot numbers are validated before delete and rollback.

### Verified
- Installation tested in QEMU/KVM: KDE Plasma (default), GNOME, Xfce, and UEFI with Secure Boot
  and TPM 2.0 (Secure Boot enabled, kernel lockdown in integrity mode).
- Memory at idle with the same task selection: KDE 2.5 GB, GNOME 2.2 GB, Xfce 2.0 GB in total;
  the desktop itself uses about 1.1, 0.8 and 0.3 GB. ClamAV (`clamd`) uses about 1 GB on all of them.

### Known limitations
- A few seconds of black screen remain while the kernel starts the graphical installer.
- Suricata listens on the network interface found at install time; after switching interface
  (for example from cable to Wi-Fi) `/etc/suricata/suricata.yaml` must be updated.
- Xfce runs on X11, without Wayland's isolation between applications.
- On first boot the AIDE baseline runs for a few minutes at low priority.

## [0.3] — 2026-11

Full release notes: [docs/release-notes-0.3.md](docs/release-notes-0.3.md).

### Added
- Evidence-based Security Score: 61 verified checks in 9 areas, weights, evidence, method, coverage and
  "not verifiable" status (`/opt/nefi/system/collect.py`, `nefi-assess.timer`). Methodology: [docs/security-score.md](docs/security-score.md).
- System pages: Hardware Security, Boot Integrity, Kernel Security, System Integrity, Security Services,
  Package Security, Configuration Audit, Backup & Recovery, Update Health.
- Falco runtime detection (one-click install) and the *Runtime Alerts* page.
- CrowdSec automatic blocking (one-click install, nftables bouncer) and the *Threat Blocking* page
  (unblock, always allow, manual block).
- Desktop notifications for serious security events (`nefi-notifier`).
- Anti-root hardening (sudo, su, SUID reduction, kernel sysctls, module blacklist, compilers for admins only,
  no core dumps) and `verify-antiroot.sh`.
- Lynis recommendations (index 70 → 85), fail2ban, pam_pwquality, acct, sysstat, debsums, needrestart, debsecan,
  legal banner, GRUB password tool.
- AIDE baseline at first boot. Full-disk encryption (LUKS + LVM) proposed by default in the installer.
- Two-column menus in the Security Center for sections with many pages.

### Changed
- Firewall closed inbound by default; SSH opened only when installed; per-service rules in `/etc/nefi/firewall.d/`.
- Incident Response and Zero Trust use their own nftables tables and restore the base firewall correctly.
- KDE Connect and Avahi no longer exposed on the network.
- Paranoid profile also disables unprivileged user namespaces.
- Ollama and the AIDE helper run in systemd sandboxes.

### Fixed
- `shell=True` removed from the Security Score module.
- AppArmor "unconfined" profiles no longer forced into enforce mode (Firefox did not start).
- First user without password/sudo after installation; AIDE database permissions; header version.
- Missing icons (Sandbox, Zero Trust); alert selection lost on refresh; UTC times shown as local.

## [0.2] — 2026-10

- First public release: Debian 13 installer with NEFI branding, NEFI Security Center with Prevention, Detection,
  DFIR, Monitoring and Response modules, NEFI Guardian AI assistant (Ollama).
