# NEFI OS 0.3 — Blue Team Edition

NEFI OS 0.3 focuses on **verified security**: the system is harder to take over, it detects and blocks attacks in
real time, and the Security Score now measures what is really in place instead of which services are running.

Base: Debian 13 "trixie", KDE Plasma 6, NEFI Security Center (PyQt6).

## Highlights

- **Evidence-based Security Score** — 61 verified checks across 9 areas, each with evidence, method and documented
  weight. Checks that cannot be verified are excluded and shown with the reason, together with a *coverage*
  percentage. See [security-score.md](security-score.md).
- **Nine new System pages** — Hardware Security, Boot Integrity, Kernel Security, System Integrity, Security
  Services (with start/restart/stop), Package Security, Configuration Audit, Backup & Recovery, Update Health.
- **Runtime threat detection with Falco** (CNCF) — one-click install from the official repository (modern eBPF
  driver, works with Secure Boot), alerts in *Detection → Runtime Alerts*.
- **Automatic blocking with CrowdSec** — one-click install, the nftables bouncer blocks hostile addresses; in
  *Response → Threat Blocking* you can unblock, always allow (false positive) or block an address yourself.
- **Desktop notifications** for serious Falco alerts and new automatic CrowdSec blocks.
- **Anti privilege-escalation hardening** — Lynis hardening index raised from 70 to 85.
- **Full-disk encryption by default** in the installer (LUKS + LVM).

## Hardening

- Firewall: everything closed inbound by default; SSH port opened only if the SSH server is installed; exceptions in
  `/etc/nefi/firewall.d/*.nft`. Incident Response and Zero Trust now use their own nftables tables and never flush
  the base firewall.
- KDE Connect (1716) and mDNS/Avahi (5353) no longer exposed to the network.
- sudo: password re-prompt after 5 minutes, 3 attempts, `use_pty`, every command logged to `/var/log/sudo.log`;
  `su` limited to the `sudo` group.
- SUID bit removed from 8 programs not needed on a Blue Team workstation (`chfn`, `chsh`, `gpasswd`, `newgrp`,
  `ssh-keysign`, `pppd`, `Xorg.wrap`, `ntfs-3g`), kept across updates with `dpkg-statoverride`.
- Kernel: kexec disabled, perf/BPF/userfaultfd/io_uring restricted, BPF JIT hardening, no tty line-discipline
  autoload, SysRq off, no core dumps, extra network sysctls.
- Risky kernel modules blocked: dccp, sctp, rds, tipc, FireWire (DMA attacks), legacy iptables modules.
- Compilers usable only by administrators (an intruder without sudo cannot build an exploit locally).
- Password policy (pam_pwquality for password changes, expiry, `UMASK 027`), legal login banner, fail2ban with
  nftables, process accounting, sysstat, weekly debsums, needrestart, debsecan.
- AIDE baseline created automatically at first boot.
- Optional GRUB menu password: `sudo /opt/nefi/hardening/grub-password.sh` (normal boot needs no password).
- systemd sandboxing for Ollama and the AIDE helper (`systemd-analyze security`: OK / SAFE).
- *Paranoid* profile now also disables unprivileged user namespaces (note: Chromium/Electron and Flatpak stop working).
- New verification script: `sudo /opt/nefi/hardening/verify-antiroot.sh`.

## Fixes

- `security_score` no longer runs shell commands through the shell.
- AppArmor: Zero Trust and the hardening profiles never force "unconfined" profiles into enforce mode (this broke
  Firefox) and Zero Trust deactivation restores the previous modes.
- Installer: the first user's password and `sudo` membership are set correctly; the AIDE database keeps the right
  permissions; the Security Center header shows the real version.
- Missing icons in Sandbox and Zero Trust; Runtime Alerts keeps the selected alert during auto-refresh;
  alert times shown in local time.

## Known limitations

- Debian's kernel has no AppArmor user-namespace mediation: unprivileged user namespaces stay allowed unless you
  apply the *Paranoid* profile.
- Falco and CrowdSec are installed on demand from their official repositories (Internet required).
- On virtual machines some hardware checks are reported as *not verifiable* (microcode, IOMMU, sometimes TPM).
- The Disposable VM for untrusted files/USB drives is planned for a later release.

## Download and verify

The ISO is split into parts because of GitHub's 2 GB limit. Join and verify:

```bash
cat nefi-os-0.3-amd64.iso.part* > nefi-os-0.3-amd64.iso
gpg --import NEFI-OS-RELEASE-KEY.asc
gpg --verify SHA256SUMS.asc SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing
```
