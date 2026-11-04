#!/bin/bash
# NEFI OS - etichette e issue iniziali nel repository privato
# Uso: REPO=organizzazione/NEFI-OS-dev ./setup-tracker.sh
set -uo pipefail
REPO="${REPO:?imposta REPO, es. REPO=nefi-os/NEFI-OS-dev}"

lab() { gh label create "$1" --repo "$REPO" --color "$2" --description "$3" --force > /dev/null && echo "  etichetta: $1"; }
echo "=== Etichette ==="
lab "type: security"   B60205 "Vulnerability or weakness"
lab "type: bug"        D73A4A "Something does not work"
lab "type: task"       0E8A16 "Feature, improvement or chore"
lab "severity: critical" 5C0000 "Exploitable, high impact - fix immediately"
lab "severity: high"   B60205 "Fix before next release"
lab "severity: medium" FBCA04 "Fix soon"
lab "severity: low"    C2E0C6 "Minor"
lab "severity: info"   EDEDED "Hardening suggestion, no direct risk"
lab "status: triage"   D4C5F9 "New, to be evaluated"
lab "status: blocked"  000000 "Waiting on something else"
lab "area: security-center" 1D76DB "PyQt6 GUI and modules"
lab "area: root-helpers"    5319E7 "/opt/nefi scripts, pkexec, polkit"
lab "area: installer"       0052CC "simple-cdd, preseed, ISO"
lab "area: packaging"       006B75 ".deb packages, repository, updates"
lab "area: hardening"       0E8A16 "firewall, sysctl, AppArmor, auditd"
lab "area: desktop"         C5DEF5 "KDE, theme, branding"
lab "area: guardian"        F9D0C4 "AI assistant, Ollama"
lab "area: infra"           BFDADC "build machine, CI, team workflow"

iss() { # iss "titolo" "etichette,separate,da,virgola" "testo"
  gh issue create --repo "$REPO" --title "$1" --label "$2" --body "$3" > /dev/null && echo "  issue: $1"; }
echo "=== Issue iniziali (problemi noti e lavori da fare) ==="
iss "[SEC] KDE Connect (1716/tcp+udp) and mDNS (5353/udp) reachable from LAN" "type: security,severity: medium,area: hardening" \
"nmap from the host shows 1716 and 5353 open although nftables input policy is drop. Find which rule allows them (hook 0010-hardening), decide: block by default or remove kdeconnect from the default install.

Definition of done:
- [ ] nmap -sS -sU from another machine shows no open ports (except 22 if SSH task selected)
- [ ] KDE Connect can be enabled from the Security Center if the user wants it"
iss "[SEC] security_score.py still runs shell=True commands" "type: security,severity: low,area: security-center" \
"bandit B602 at usr/lib/nefi/modules/security_score.py:27 (_run). Commands are fixed strings today; convert them to argument lists (pipes done in Python) so future changes cannot introduce injection."
iss "[SEC] Harden systemd units: nefi-aide-perms (UNSAFE), ollama (MEDIUM)" "type: security,severity: low,area: hardening" \
"systemd-analyze security reports nefi-aide-perms as UNSAFE and ollama as MEDIUM. Add sandboxing directives (ProtectSystem, PrivateTmp, CapabilityBoundingSet...) without breaking AIDE permissions or the Ollama model directory."
iss "[SEC] Verify Incident Response / Zero Trust restore the base firewall" "type: security,severity: medium,area: root-helpers" \
"IR and Zero Trust modify nftables directly. Check that after deactivation the default-deny ruleset is restored (systemctl restart nftables) and that the system is never left with an open firewall."
iss "[BUG] Missing icons (empty squares) in Sandbox and Zero Trust" "type: bug,area: security-center" \
"Icons are rendered as empty boxes (missing glyph). Replace emoji/unicode icons with the SVG icon set from nefi_theme.py."
iss "[BUG] Security Center header shows v0.1 instead of 0.2" "type: bug,area: security-center" \
"Read the version from /etc/nefi-version (or a single constant) instead of a hard-coded string."
iss "[TASK] AIDE baseline: guide the user to create it after install" "type: task,area: hardening" \
"Lynis FINT-4316: no AIDE database after installation. Show a first-run notice in Integrity Control (or a one-shot service) to initialize the baseline."
iss "[TASK] Raise Lynis hardening index from 70 to 75+" "type: task,area: hardening" \
"Review lynis suggestions on a fresh install and apply the safe ones in the packages (not by hand)."
iss "[TASK] Packaging cleanup (lintian): copyright, changelog, /opt, units in /usr/lib" "type: task,area: packaging" \
"lintian errors: no-copyright-file, no-changelog, dir-or-file-in-opt, systemd/udev files in /etc. Fix in packages/nefi-pkgs-gen.sh and build-debs.sh."
iss "[TASK] NEFI APT repository for updates" "type: task,area: packaging" \
"Publish NEFI .deb packages in a signed APT repository (reprepro) so installed systems get NEFI updates with apt upgrade."
iss "[TASK] Light ISO under 2 GB (Ollama downloaded on demand)" "type: task,area: installer" \
"Current ISO is 2.8 GB and must be split for GitHub Releases. Option: nefi-ai task downloads the official Ollama release during/after install."
iss "[TASK] GRUB entry title: 'NEFI OS' instead of 'Debian GNU/Linux'" "type: task,area: installer" \
"Needs GRUB_DISTRIBUTOR without breaking the signed shim path (/EFI/debian) used by Secure Boot. Test with Secure Boot on."
iss "[TASK] Test on real hardware (laptop + desktop, UEFI + Secure Boot)" "type: task,area: installer" \
"Wi-Fi firmware, GPU, suspend, Secure Boot, encrypted LVM install. Report each problem as a separate bug."
iss "[TASK] Shared build machine + automatic ISO builds" "type: task,area: infra" \
"Always-on machine that builds main every N minutes, publishes ISO + changelog to the team."
iss "[TASK] NEFI Academy (integrated tutorials)" "type: task,area: security-center" \
"Tutorials on Suricata, YARA, DFIR, threat hunting, hardening inside the Security Center."
echo "FATTO"
