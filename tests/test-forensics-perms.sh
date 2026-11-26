#!/bin/bash
# Test: le prove raccolte NON sono leggibili dagli altri utenti, anche se chi lancia ha umask 022.
# Da eseguire come root su una VM di test NEFI (la raccolta dura qualche minuto):
#     sudo bash tests/test-forensics-perms.sh [percorso di collect.sh]
set -u
COLLECT="${1:-/opt/nefi/forensics/collect.sh}"
BASE=/var/lib/nefi/forensics
[ "$(id -u)" -eq 0 ] || { echo "Run as root"; exit 2; }
fail=0
check() {  # check <percorso> <permessi attesi> <proprietario:gruppo atteso>
    local got; got="$(stat -c '%a %U:%G' "$1")"
    if [ "$got" = "$2 $3" ]; then echo "PASS $1 ($got)"; else echo "FAIL $1: got $got, expected $2 $3"; fail=1; fi
}

before="$(ls "$BASE" 2>/dev/null | grep -c '^evidence-.*\.tar\.gz$')"
( umask 022; bash "$COLLECT" > /tmp/nefi-forensics-test.log 2>&1 ) || { echo "FAIL: collect.sh exited with error, see /tmp/nefi-forensics-test.log"; exit 1; }
after="$(ls "$BASE" | grep -c '^evidence-.*\.tar\.gz$')"
[ "$after" -gt "$before" ] || { echo "FAIL: no new archive created"; exit 1; }

ARCHIVE="$(ls -t "$BASE"/evidence-*.tar.gz | head -1)"
TS="$(basename "$ARCHIVE" .tar.gz)"; TS="${TS#evidence-}"
GROUP=sudo; getent group sudo > /dev/null || GROUP=root

check "$BASE" 750 "root:$GROUP"
check "$BASE/$TS" 700 root:root
check "$BASE/$TS/MANIFEST.txt" 600 root:root
check "$ARCHIVE" 600 root:root
check "$ARCHIVE.sha256" 640 "root:$GROUP"

open_files="$(find "$BASE/$TS" "$ARCHIVE" -perm /077 | head -5)"
if [ -n "$open_files" ]; then echo "FAIL: readable by group/others:"; echo "$open_files"; fail=1
else echo "PASS no evidence file or folder is readable by group or others"; fi
not_root="$(find "$BASE/$TS" ! -user root | head -5)"
if [ -n "$not_root" ]; then echo "FAIL: not owned by root:"; echo "$not_root"; fail=1
else echo "PASS everything owned by root"; fi

# un utente normale non puo' leggere il contenuto
U="$(getent passwd 1000 | cut -d: -f1)"
if [ -n "$U" ]; then
    if su -s /bin/sh "$U" -c "cat '$BASE/$TS/MANIFEST.txt'" > /dev/null 2>&1; then
        echo "FAIL: user $U can read the evidence"; fail=1
    else
        echo "PASS user $U cannot read the evidence"
    fi
fi

[ "$fail" -eq 0 ] && echo "ALL TESTS PASSED" || echo "SOME TESTS FAILED"
exit "$fail"
