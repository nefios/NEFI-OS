#!/bin/bash
# NEFI Snapshot Manager
ACTION="$1"
DESCRIPTION="${2:-NEFI Snapshot}"

case "$ACTION" in
    check_btrfs)
        # Verifica se il filesystem è Btrfs
        FS=$(df -T / | awk 'NR==2{print $2}')
        echo "FILESYSTEM=$FS"
        if [ "$FS" = "btrfs" ]; then
            echo "BTRFS_SUPPORTED=true"
        else
            echo "BTRFS_SUPPORTED=false"
        fi
        ;;

    setup)
        # Configura Snapper per root
        if ! snapper -c root list &>/dev/null; then
            snapper -c root create-config / 2>&1
            echo "[NEFI-SNAP] Snapper configured for root filesystem"
        else
            echo "[NEFI-SNAP] Snapper already configured"
        fi
        ;;

    create)
        # Crea snapshot manuale
        snapper -c root create --description "$DESCRIPTION" --cleanup-algorithm number 2>&1
        echo "[NEFI-SNAP] Snapshot created: $DESCRIPTION"
        ;;

    list)
        # Lista snapshot
        snapper -c root list 2>&1
        ;;

    delete)
        # Elimina snapshot per numero
        NUM="$2"
        snapper -c root delete "$NUM" 2>&1
        echo "[NEFI-SNAP] Snapshot $NUM deleted"
        ;;

    rollback)
        # Rollback a snapshot
        NUM="$2"
        snapper -c root undochange "${NUM}..0" 2>&1
        echo "[NEFI-SNAP] Rolled back to snapshot $NUM"
        ;;

    pre_update)
        # Snapshot pre-aggiornamento
        NUM=$(snapper -c root create --print-number \
            --description "Pre-update $(date +%Y-%m-%d)" \
            --cleanup-algorithm number 2>/dev/null)
        echo "PRE_SNAPSHOT=$NUM"
        echo "[NEFI-SNAP] Pre-update snapshot created: #$NUM"
        ;;

    post_update)
        # Snapshot post-aggiornamento
        PRE="$2"
        snapper -c root create \
            --description "Post-update $(date +%Y-%m-%d)" \
            --cleanup-algorithm number 2>&1
        echo "[NEFI-SNAP] Post-update snapshot created"
        ;;

    status)
        # Stato generale
        SNAP_COUNT=$(snapper -c root list 2>/dev/null | grep -c "^[0-9]" || echo 0)
        echo "SNAPSHOT_COUNT=$SNAP_COUNT"
        LATEST=$(snapper -c root list 2>/dev/null | grep "^[0-9]" | tail -1)
        echo "LATEST=$LATEST"
        ;;
esac
