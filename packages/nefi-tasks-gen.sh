#!/bin/bash
# NEFI OS - genera le voci della "Scelta del software" (tasksel)
# e aggiunge i pacchetti dei task a nefi.downloads (cosi' sono sulla ISO).
# ATTENZIONE: nelle descrizioni NON usare virgole (tasksel le usa come separatore).
set -uo pipefail
cd "$(dirname "$0")"
DESC="nefi-tasks/usr/share/tasksel/descs/debian-tasks.desc"
DL="../installer/profiles/nefi.downloads"
mkdir -p "$(dirname "$DESC")"
: > "$DESC"
grep -q "^# Pacchetti dei task NEFI" "$DL" || printf '\n# Pacchetti dei task NEFI (generato da nefi-tasks-gen.sh)\n' >> "$DL"

# Disponibile se e' un pacchetto NEFI (cartella in packages/) oppure esiste in Debian 13.
# Niente pipe: con pipefail grep -q dava falsi negativi.
avail() {
  [ -f "$1/DEBIAN/control" ] && return 0
  local out; out="$(apt-cache policy "$1" 2>/dev/null)"
  [[ "$out" == *"Candidate: "[0-9]* ]]
}

# task <nome> <genitore|-> <ordine> <descrizione> <pacchetti...>
task() {
  local name="$1" parent="$2" rel="$3" desc="$4"; shift 4
  {
    echo "Task: $name"
    if [ "$parent" != "-" ]; then echo "Parent: $parent"; fi
    echo "Relevance: $rel"
    echo "Section: user"
    echo "Description: $desc"
    echo " $desc"
    echo "Packages: list"
    for p in "$@"; do
      if avail "$p"; then
        echo " $p"
        grep -qx "$p" "$DL" || echo "$p" >> "$DL"
      else
        echo "   [$name] non esiste in trixie, saltato: $p" >&2
      fi
    done
    echo
  } >> "$DESC"
}

DESKTOP_KDE="nefi-desktop kde-plasma-desktop sddm konsole dolphin kate firefox-esr plasma-nm
  powerdevil plasma-widgets-addons plymouth plymouth-themes fonts-noto-color-emoji"
CORE="nefi-security-center python3-pyqt6 python3-pyqt6.qtsvg python3-psutil python3-requests
  python3-twisted apparmor apparmor-utils apparmor-profiles auditd audispd-plugins nftables
  aide aide-common mokutil polkitd pkexec udisks2 firejail keepassxc snapper btrfs-progs
  netcat-openbsd"
DEFAULT="suricata yara clamav clamav-daemon chkrootkit rkhunter lynis nmap tcpdump net-tools"
LARGE_EXTRA="dc3dd foremost binwalk sleuthkit autopsy testdisk gddrescue ewf-tools wireshark tshark"
AI="nefi-ollama"
task nefi-all          -            5 "Select all -- every NEFI collection (desktop + tools + DFIR + AI + SSH)" $DESKTOP_KDE $CORE $DEFAULT $LARGE_EXTRA $AI openssh-server

task nefi-desktop      -            10 "Desktop environment [selecting this item has no effect]" base-files
task nefi-desktop-kde  nefi-desktop 11 "KDE Plasma (NEFI OS desktop)" $DESKTOP_KDE
task nefi-tools        -            20 "Collection of tools [selecting this item has no effect]" base-files
task nefi-core         nefi-tools   21 "core -- NEFI Security Center and system hardening" $CORE
task nefi-default      nefi-tools   22 "default -- Blue Team tools: IDS and antivirus and audit scanners" $DEFAULT
task nefi-large        nefi-tools   23 "large -- default tools plus DFIR and forensics" $DEFAULT $LARGE_EXTRA
task nefi-ai           nefi-tools   24 "ai -- Guardian AI assistant (Ollama engine - about 2 GB)" $AI
task nefi-ssh          -            30 "SSH server" openssh-server
cat >> "$DESC" << 'EOF'
Task: nefi-standard
Relevance: 40
Section: user
Description: standard system utilities
 standard system utilities
Packages: standard
EOF
echo "[NEFI] task generati in $DESC"
