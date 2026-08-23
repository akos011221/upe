#!/bin/bash

SOCKET="/var/run/upe/router.sock"
STATE_DIR="/var/run/upe/state"
MARKER="/tmp/upe_reconciled"

mkdir -p "$STATE_DIR"

echo "UPE Reconciler started. Watching for $SOCKET..."

while true; do
    if [ -S "$SOCKET" ]; then
        if [ ! -f "$MARKER" ]; then
            echo "Router socket detected. Reconciling active pods..."
            for state_file in "$STATE_DIR"/*.txt; do
                if [ -f "$state_file" ]; then
                    echo "Sending $state_file to router..."
                    cat "$state_file" | nc -U "$SOCKET" > /dev/null
                    sleep 0.1
                fi
            done
            touch "$MARKER"
            echo "Reconcilation complete."
        fi
    else
        # If socket disappears, the router crashed. Remove marker so we reconcilate
        # the state when it comes back.
        rm -f "$MARKER"
    fi
    sleep 1
done