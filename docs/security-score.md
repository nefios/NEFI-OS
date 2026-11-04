# NEFI Security Score — methodology

The Security Score in **NEFI Security Center → System → Security Score** is calculated from checks whose result is *verified on the running system*, not from the mere fact that a service is running. For example, the firewall counts only if an input chain with `policy drop` is actually loaded, AppArmor only if profiles are in enforce mode, auditd only if audit rules are loaded, CrowdSec only if the engine, the firewall bouncer, the local API and the firewall table all work.

## How it works

- `/opt/nefi/system/collect.py` runs as root at boot (+3 min) and every 30 minutes (`nefi-assess.timer`), or on demand with **Run checks now**.
- Results are written to `/var/lib/nefi/system/report.json` (`root:sudo`, mode `0640`): administrators can read them without entering a password.
- Every check records its **status**, the **evidence** (what was read or measured), the **method** (command or file used) and its **weight**.
- Slow checks (package checksums, SUID scan, vulnerable packages, firmware) are cached and refreshed every 6–24 hours; the page shows when a cached result was produced.

## Statuses

| Status | Meaning | Effect on the score |
|---|---|---|
| Passed | The protection is verified to be in place | full weight |
| Warning | Partially in place or needs attention | half weight |
| Failed | The protection is missing or not working | zero |
| Not verifiable | The check could not be performed here (e.g. a virtual machine has no IOMMU, a tool is not installed) — the reason is shown | **excluded** from the score, lowers the coverage |

## Formula

```
Score    = (Σ weights of passed checks + ½ Σ weights of warnings) / Σ weights of verifiable checks × 100
Coverage = Σ weights of verifiable checks / Σ weights of all checks × 100
```

Weights go from **1** (minor hardening) to **10** (core protection). Score ≥ 80 is *Good*, 50–79 *Needs improvement*, below 50 *Critical*. Always read the score together with the coverage.

## The 61 checks

### Hardware Security (5 checks, total weight 16)

| ID | Check | Weight | Why it matters |
|---|---|---|---|
| `hw.tpm` | TPM 2.0 present | 3 | A TPM stores keys in hardware and enables measured boot and TPM-bound disk unlock. |
| `hw.cpu_vulns` | CPU vulnerabilities mitigated | 6 | Unmitigated CPU flaws (Spectre, Meltdown, MDS...) let processes read other processes' memory. |
| `hw.microcode` | CPU microcode package installed | 3 | Microcode updates fix CPU security bugs; they are loaded at every boot. |
| `hw.iommu` | IOMMU (DMA protection) active | 2 | The IOMMU stops malicious devices (Thunderbolt, PCIe) from reading memory via DMA. |
| `hw.firmware` | Firmware updates checked (fwupd) | 2 | Firmware (UEFI, SSD, Thunderbolt) bugs are fixed only by firmware updates. |

### Boot Integrity (6 checks, total weight 23)

| ID | Check | Weight | Why it matters |
|---|---|---|---|
| `boot.uefi` | Booted in UEFI mode | 2 | Secure Boot and modern boot protections need UEFI; legacy BIOS boot cannot be verified. |
| `boot.secureboot` | Secure Boot enabled | 8 | Secure Boot verifies the signatures of the bootloader and kernel before running them. |
| `boot.lockdown` | Kernel lockdown active | 5 | Lockdown stops even root from modifying the running kernel (unsigned modules, /dev/mem, kexec). |
| `boot.module_sig` | Only signed kernel modules can load | 4 | Unsigned modules are the classic way to install a kernel rootkit. |
| `boot.grub_password` | GRUB menu protected by a password | 3 | Without it, anyone at the keyboard can edit the boot entry and get a root shell. |
| `boot.grub_perms` | grub.cfg not readable by users | 1 | grub.cfg can contain the password hash and boot details. |

### Kernel Security (21 checks, total weight 42)

| ID | Check | Weight | Why it matters |
|---|---|---|---|
| `sysctl.kernel.kptr_restrict` | Kernel pointers hidden | 2 | Kernel addresses help exploits bypass KASLR. |
| `sysctl.kernel.dmesg_restrict` | dmesg restricted to root | 1 | Kernel logs leak addresses and hardware details. |
| `sysctl.kernel.yama.ptrace_scope` | ptrace restricted | 3 | Stops a process from reading another process' memory (password theft). |
| `sysctl.kernel.unprivileged_bpf_disabled` | BPF restricted to root | 2 | Unprivileged BPF has been a frequent source of kernel exploits. |
| `sysctl.kernel.kexec_load_disabled` | kexec disabled | 2 | Prevents replacing the running kernel. |
| `sysctl.kernel.perf_event_paranoid` | perf restricted | 1 | perf exposes kernel internals to users. |
| `sysctl.kernel.randomize_va_space` | Full ASLR | 3 | Address randomisation makes memory exploits much harder. |
| `sysctl.kernel.io_uring_disabled` | io_uring restricted | 1 | io_uring had many privilege-escalation bugs. |
| `sysctl.vm.unprivileged_userfaultfd` | userfaultfd restricted | 1 | Used by exploits to win race conditions. |
| `sysctl.fs.protected_symlinks` | Symlink protection | 2 | Blocks /tmp symlink attacks against root. |
| `sysctl.fs.protected_hardlinks` | Hardlink protection | 2 | Blocks hardlink attacks against privileged programs. |
| `sysctl.fs.protected_fifos` | FIFO protection | 1 | Blocks FIFO spoofing in sticky directories. |
| `sysctl.fs.protected_regular` | Regular file protection | 1 | Blocks file spoofing in sticky directories. |
| `sysctl.fs.suid_dumpable` | No core dumps of SUID programs | 1 | Core dumps of privileged programs can leak secrets. |
| `sysctl.net.ipv4.tcp_syncookies` | TCP SYN cookies | 1 | Protects against SYN flood denial of service. |
| `sysctl.net.ipv4.conf.all.rp_filter` | Reverse path filtering | 1 | Drops spoofed packets. |
| `sysctl.net.ipv4.conf.all.accept_redirects` | ICMP redirects ignored | 1 | Redirects can be used to reroute traffic (MITM). |
| `sysctl.net.ipv4.conf.all.accept_source_route` | Source routing disabled | 1 | Source-routed packets bypass network controls. |
| `kernel.apparmor` | AppArmor enforcing profiles | 8 | Mandatory access control limits what a compromised program can do. |
| `kernel.audit` | Kernel audit rules loaded | 5 | Audit rules record changes to identity files, privileged commands and module loading. |
| `kernel.modules_blacklist` | Risky kernel modules blocked | 2 | Rare network protocols and FireWire have a long history of kernel bugs and DMA attacks. |

### System Integrity (6 checks, total weight 24)

| ID | Check | Weight | Why it matters |
|---|---|---|---|
| `int.aide_db` | AIDE baseline exists and is recent | 4 | AIDE compares files with a known-good baseline to detect tampering. |
| `int.aide_check` | AIDE check run recently | 2 | A baseline is useful only if the system is compared with it regularly. |
| `int.dpkg_verify` | System files match their packages | 6 | Detects modified or replaced system binaries and libraries (checksums of every installed package). |
| `int.suid` | No unexpected SUID programs | 4 | A new SUID-root program is a typical backdoor left by an attacker. |
| `int.critical_perms` | Critical files have safe permissions | 4 | Writable or readable identity files allow account takeover. |
| `int.world_writable` | No world-writable files in /etc and /usr | 4 | Any user could modify a world-writable system file. |

### Security Services (6 checks, total weight 25)

| ID | Check | Weight | Why it matters |
|---|---|---|---|
| `svc.firewall` | Firewall blocks incoming traffic | 10 | Checks the LOADED rules, not just the service: an input chain with policy drop must exist. |
| `svc.fail2ban` | fail2ban responding with active jails | 3 | Bans addresses after repeated failed logins. |
| `svc.falco` | Falco runtime detection running | 4 | Detects suspicious activity on the system in real time. |
| `svc.crowdsec` | CrowdSec engine and firewall bouncer working | 4 | Blocks hostile addresses automatically; the bouncer must be connected to the engine. |
| `svc.clamav` | Antivirus signatures up to date | 2 | ClamAV detects known malware only with fresh signatures. |
| `svc.suricata` | Suricata IDS running | 2 | Network intrusion detection on the traffic of this machine. |

### Package Security (4 checks, total weight 17)

| ID | Check | Weight | Why it matters |
|---|---|---|---|
| `pkg.vulnerable` | No installed packages with fixed vulnerabilities | 7 | debsecan compares installed versions with the Debian security tracker. |
| `pkg.restart` | No services running outdated libraries | 3 | After an update, services keep using the old vulnerable code until restarted. |
| `pkg.repos` | Package sources are signed | 5 | Unsigned or 'trusted=yes' sources let anyone on the network inject packages. |
| `pkg.dpkg_state` | Package database consistent | 2 | Half-installed packages can leave security fixes not applied. |

### Configuration Audit (6 checks, total weight 31)

| ID | Check | Weight | Why it matters |
|---|---|---|---|
| `cfg.encryption` | System disk encrypted (LUKS) | 8 | Without encryption, anyone with the disk can read every file. |
| `cfg.ssh` | SSH server hardened (or not installed) | 5 | An exposed SSH server must refuse root and limit login attempts. |
| `cfg.sudo` | sudo hardened (no NOPASSWD, logging, use_pty) | 5 | Passwordless sudo turns any compromised user account into root. |
| `cfg.accounts` | Accounts safe (single UID 0, no empty passwords, root locked) | 7 | Extra UID 0 accounts and empty passwords are classic backdoors. |
| `cfg.password_policy` | Password policy (quality, expiry, umask) | 3 | Weak or never-changing passwords and permissive umask expose accounts and files. |
| `cfg.listening` | No unexpected network services listening | 3 | Every listening service is a door; the firewall must cover what is open. |

### Backup & Recovery (2 checks, total weight 6)

| ID | Check | Weight | Why it matters |
|---|---|---|---|
| `bk.snapshots` | Recent system snapshot or backup | 5 | Snapshots let you roll back after a compromise, a bad update or ransomware. |
| `bk.restore_test` | Restore tested in the last 90 days | 1 | An untested backup may not restore. Mark a restore test from System > Backup & Recovery. |

### Update Health (5 checks, total weight 20)

| ID | Check | Weight | Why it matters |
|---|---|---|---|
| `up.lists` | Package lists refreshed recently | 2 | Without fresh package lists, available security updates are not even known. |
| `up.security_pending` | No pending security updates | 8 | Installed packages with a published security fix are the most common way in. |
| `up.automatic` | Automatic security updates working | 5 | unattended-upgrades must be enabled AND have run recently. |
| `up.reboot` | No reboot pending | 2 | Kernel and core library updates take effect only after a reboot. |
| `up.release` | Debian release supported | 3 | An end-of-life release receives no security updates. |

Total weight of all checks: **204**.
