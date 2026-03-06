#!/bin/bash
# =============================================================================
# scrutiny_run.sh - Scrutiny process launch and trace orchestrator
#
# Usage:
#   sudo bash scrutiny_run.sh <target> <wsl_root> [mode]
#
# Modes:
#   run       (default) - trace target, log to logs/<target>/json/
#   baseline  - trace target, copy JSONL to logs/baselines/<target>/
#
# Part of the Scrutiny project - HoneyBadger Vanguard fork.
# =============================================================================

TARGET="${1:-targetProc2}"
WSLROOT="${2:-/mnt/d/06-WORKSPACE/GitHub/MoSLoF/Scrutiny}"
MODE="${3:-run}"
OUTFILE="/tmp/scrutiny_proc.out"

# Validate target
case "$TARGET" in
    targetProc0|targetProc1|targetProc2) ;;
    *)
        echo "ERROR: Invalid target '$TARGET'. Valid: targetProc0, targetProc1, targetProc2"
        exit 1
        ;;
esac

# Validate mode
case "$MODE" in
    run|baseline) ;;
    *)
        echo "ERROR: Invalid mode '$MODE'. Valid: run, baseline"
        exit 1
        ;;
esac

cd "$WSLROOT" || { echo "ERROR: cannot cd to $WSLROOT"; exit 1; }

if [ ! -x "bin/$TARGET" ]; then
    echo "ERROR: bin/$TARGET not found or not executable"
    exit 1
fi

# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------
echo "============================================================"
echo "  Scrutiny - HoneyBadger Vanguard"
if [ "$MODE" = "baseline" ]; then
    echo "  Mode    : BASELINE CAPTURE"
else
    echo "  Mode    : LIVE TRACE"
fi
echo "  Target  : $TARGET"
echo "============================================================"

# Clean up leftovers
pkill -f "bin/$TARGET" 2>/dev/null || true
rm -f "$OUTFILE"

# Record timestamp before run so we can find the new log after
TIMESTAMP_BEFORE=$(date +%s)

# ---------------------------------------------------------------------------
# Launch target and attach baseliner
# ---------------------------------------------------------------------------
echo "[*] Launching bin/$TARGET..."
bin/"$TARGET" > "$OUTFILE" 2>&1 &
TARGET_PID=$!

# Wait up to 5s for startup line
STARTED=0
for i in $(seq 1 50); do
    sleep 0.1
    if grep -qm1 'Starting (PID' "$OUTFILE" 2>/dev/null; then
        STARTED=1
        break
    fi
done

PROC_LINE=$(grep -m1 'Starting (PID' "$OUTFILE" 2>/dev/null || echo "")
[ -n "$PROC_LINE" ] && echo "[+] $PROC_LINE"

if ! kill -0 "$TARGET_PID" 2>/dev/null; then
    echo "ERROR: PID $TARGET_PID exited before baseliner could attach"
    cat "$OUTFILE"
    exit 1
fi

echo "[*] Attaching baseliner to PID $TARGET_PID..."
bin/baseliner <<< "$TARGET_PID"

echo "[+] Baseliner finished."

# ---------------------------------------------------------------------------
# Post-run: find the JSONL that was just written
# ---------------------------------------------------------------------------
LATEST_JSONL=$(ls -t "logs/$TARGET/json"/*.jsonl 2>/dev/null | head -1)

if [ -z "$LATEST_JSONL" ]; then
    echo "WARNING: No JSONL found in logs/$TARGET/json/"
    echo "============================================================"
    echo "  Done."
    echo "============================================================"
    exit 0
fi

echo "[+] Log: $LATEST_JSONL"

# ---------------------------------------------------------------------------
# Baseline mode: copy JSONL into logs/baselines/<target>/
# ---------------------------------------------------------------------------
if [ "$MODE" = "baseline" ]; then
    BASELINE_DIR="logs/baselines/$TARGET"
    mkdir -p "$BASELINE_DIR"
    BASENAME=$(basename "$LATEST_JSONL")
    DEST="$BASELINE_DIR/$BASENAME"
    cp "$LATEST_JSONL" "$DEST"
    echo "[+] Baseline copy: $DEST"
    echo "$DEST" > /tmp/scrutiny_last_baseline.txt
else
    echo "$LATEST_JSONL" > /tmp/scrutiny_last_run.txt
fi

echo "============================================================"
echo "  Done."
echo "============================================================"
