#!/bin/bash
# NEFI Incident Response - file di stato /var/lib/nefi/ir/ir-state.conf
# Incluso (source) da activate.sh e deactivate.sh, che girano come root.
#
# Formato: una riga CHIAVE=valore per ogni chiave, MAI ripetuta.
# Ogni modifica riscrive il file in modo atomico (file temporaneo nella stessa cartella + mv),
# cosi' il Security Center non legge mai un file a meta' o con valori vecchi.
# Permessi: root:sudo 0640 (gli amministratori lo leggono senza password).

STATE_DIR="/var/lib/nefi/ir"
STATE_FILE="$STATE_DIR/ir-state.conf"
STATE_GROUP="sudo"
getent group "$STATE_GROUP" > /dev/null 2>&1 || STATE_GROUP="root"

ir_state_init() {
    install -d -m 0750 -o root -g "$STATE_GROUP" "$STATE_DIR"
    chown root:"$STATE_GROUP" "$STATE_DIR"
    chmod 0750 "$STATE_DIR"
    # snapshot e log delle sessioni precedenti: solo root
    find "$STATE_DIR" -maxdepth 1 -type f ! -name "$(basename "$STATE_FILE")" -exec chmod 0600 {} + 2>/dev/null || true
}

# ir_state_set CHIAVE valore [CHIAVE valore ...]
# Aggiorna le chiavi indicate, tiene le altre (una sola volta ciascuna, vince l'ultimo valore).
ir_state_set() {
    local tmp k keys=""
    if [ $(( $# % 2 )) -ne 0 ]; then echo "ir_state_set: key/value pairs expected" >&2; return 1; fi
    local args=("$@")
    for (( i = 0; i < $#; i += 2 )); do
        k="${args[i]}"
        [[ "$k" =~ ^[A-Z_][A-Z0-9_]*$ ]] || { echo "ir_state_set: invalid key $k" >&2; return 1; }
        [[ "${args[i+1]}" =~ ^[A-Za-z0-9_.:+-]*$ ]] || { echo "ir_state_set: invalid value for $k" >&2; return 1; }
        keys="$keys $k"
    done
    tmp="$(mktemp "$STATE_DIR/.ir-state.XXXXXX")" || return 1
    {
        if [ -f "$STATE_FILE" ]; then
            awk -v keys="$keys" '
                BEGIN { n = split(keys, a, " "); for (i = 1; i <= n; i++) skip[a[i]] = 1 }
                /^[A-Z_][A-Z0-9_]*=/ {
                    k = substr($0, 1, index($0, "=") - 1)
                    if (k in skip) next
                    if (!(k in val)) order[++m] = k
                    val[k] = $0
                }
                END { for (i = 1; i <= m; i++) print val[order[i]] }' "$STATE_FILE"
        fi
        for (( i = 0; i < ${#args[@]}; i += 2 )); do
            printf '%s=%s\n' "${args[i]}" "${args[i+1]}"
        done
    } > "$tmp" || { rm -f "$tmp"; return 1; }
    chmod 0640 "$tmp"
    chgrp "$STATE_GROUP" "$tmp" 2>/dev/null || true
    mv -f "$tmp" "$STATE_FILE"
}

# ir_state_reset CHIAVE valore ...   nuovo file con solo queste chiavi (inizio di una sessione)
ir_state_reset() {
    rm -f "$STATE_FILE"
    ir_state_set "$@"
}

# ir_state_get CHIAVE   valore attuale (vuoto se manca)
ir_state_get() {
    [ -f "$STATE_FILE" ] && sed -n "s/^$1=//p" "$STATE_FILE" | tail -n 1
}

# ir_isolation_apply [IP_AMMESSO]
# Tabella separata "nefi_ir": si aggiunge al firewall di base senza cancellarlo. Un pacchetto scartato
# da QUALSIASI tabella resta scartato, quindi l'isolamento e' totale. "nft -f" e' atomico: o entra
# tutta la tabella o non cambia niente (un errore non lascia la macchina isolata a meta').
ir_isolation_apply() {
    local allow="$1" in_rule="" out_rule="" fam="ip"
    if [ -n "$allow" ]; then
        case "$allow" in *:*) fam="ip6" ;; esac
        in_rule="$fam saddr $allow accept"
        out_rule="$fam daddr $allow accept"
    fi
    nft delete table inet nefi_ir 2>/dev/null || true
    nft -f - << NFT
table inet nefi_ir {
    chain input {
        type filter hook input priority -10; policy drop;
        iif lo accept
        $in_rule
    }
    chain output {
        type filter hook output priority -10; policy drop;
        oif lo accept
        $out_rule
    }
    chain forward {
        type filter hook forward priority -10; policy drop;
    }
}
NFT
}

# ir_log AZIONE chiave=valore ...   nel registro delle azioni di risposta (e nella cronologia del caso)
ir_log() {
    local case_id
    case_id="$(ir_state_get CASE)"
    if [ -n "$case_id" ]; then
        python3 /opt/nefi/ir/irctl.py --case "$case_id" log "$@" 2>/dev/null || true
    else
        python3 /opt/nefi/ir/irctl.py log "$@" 2>/dev/null || true
    fi
}
