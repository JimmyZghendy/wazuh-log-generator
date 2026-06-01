#!/bin/bash
# ============================================================
# Wazuh Log Generator — run and inject into monitored paths
# Usage:
#   ./run_and_copy.sh --all --count 100 --incidents 3
#   ./run_and_copy.sh --all --count 100 --incidents 3 --append
#
# --append  : append to existing log files instead of replacing them.
#             Use this for repeated runs so Wazuh sees new lines each time.
#             Default (no flag): replace files (first run / fresh start).
# ============================================================

APPEND=false
PASSTHROUGH=()

for arg in "$@"; do
    if [[ "$arg" == "--append" ]]; then
        APPEND=true
    else
        PASSTHROUGH+=("$arg")
    fi
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="$SCRIPT_DIR/output"
DEST_DIR="/var/log/wazuh-test"

echo "=================================================="
echo "  Running log generator..."
echo "=================================================="
python3 "$SCRIPT_DIR/generate_logs.py" "${PASSTHROUGH[@]}"
if [[ $? -ne 0 ]]; then
    echo "ERROR: log generator failed"; exit 1
fi

echo ""
echo "=================================================="
echo "  Copying to $DEST_DIR  (append=$APPEND)"
echo "=================================================="
mkdir -p "$DEST_DIR"

for src in "$OUTPUT_DIR"/*; do
    fname="$(basename "$src")"
    dest="$DEST_DIR/$fname"

    if [[ "$APPEND" == "true" ]]; then
        # APPEND: Wazuh file monitor sees new lines added to the inode.
        # This is the correct mode for repeated test runs.
        cat "$src" >> "$dest"
        lines=$(wc -l < "$src")
        echo "  appended $lines lines  ->  $dest"
    else
        # REPLACE: use cp (preserves inode) rather than cat > (truncates).
        # Wazuh inotify tracks inode not filename; cp on existing file keeps
        # the same inode so Wazuh picks up the content difference.
        # On a FRESH start (file doesn't exist yet), both modes behave the same.
        cp "$src" "$dest"
        lines=$(wc -l < "$src")
        echo "  replaced  $lines lines  ->  $dest"
    fi
done

# Set ownership so the Wazuh agent can read
chown wazuh:wazuh "$DEST_DIR"/* 2>/dev/null || \
    echo "  (chown skipped — run as root if Wazuh agent cannot read the files)"

echo ""
echo "Done. Files in $DEST_DIR:"
ls -lh "$DEST_DIR"
echo ""
echo "--- Wazuh ossec-logtest quick check ---"
echo "  tail -f /var/ossec/logs/alerts/alerts.log"
echo "  or: /var/ossec/bin/ossec-logtest < $DEST_DIR/auth.log"
