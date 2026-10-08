#!/bin/bash
# NEFI Integrity Control — File integrity check
set -e

if [ ! -f /var/lib/aide/aide.db ]; then
    echo "NO_BASELINE"
    exit 1
fi

mkdir -p /var/log/nefi
REPORT="/var/log/nefi/aide-check-$(date +%Y%m%d-%H%M%S).log"

aide --check > "$REPORT" 2>&1 || true

grep -E "^(added|removed|changed):" "$REPORT" || echo "NO_CHANGES"

ls -t /var/log/nefi/aide-check-*.log 2>/dev/null | tail -n +11 | xargs -r rm
