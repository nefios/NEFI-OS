# Changelog

All notable changes to NEFI OS are documented here.

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
- New release signing key `0CC0 887C BCC8 ED05 E308  FBBA ECF8 8C1D 9133 66D3`; the 0.2 key is kept in `NEFI-OS-RELEASE-KEY-0.2.asc`.
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
