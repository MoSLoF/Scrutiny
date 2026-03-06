#!/bin/bash
# scrutiny_run.sh - Launches target and attaches baseliner in one session
# Usage: sudo bash scrutiny_run.sh <target> <wsl_root>
# Example: sudo bash scrutiny_run.sh targetProc2 /mnt/d/06-WORKSPACE/GitHub/MoSLoF/Scrutiny

TARGET="${1:-targetProc2}"
WSLROOT="${2:-/mnt/d/06-WORKSPACE/GitHub/MoSLoF/Scrutiny}"
OUTFILE="/tmp/scrutiny_proc.out"

cd "$WSLROOT" || { echo "ERROR: cannot cd to $WSLROOT"; exit 1; }

# Kill any leftovers
pkill -f "bin/$TARGET" 2>/dev/null || true
rm -f "$OUTFILE"

# Launch target in background - stays alive because this bash session stays alive
bin/"$TARGET" > "$OUTFILE" 2>&1 &
TARGET_PID=$!

echo "Launched $TARGET as PID $TARGET_PID"

# Wait up to 5s for binary to write its startup line
for i in $(seq 1 50); do
    sleep 0.1
    if grep -qm1 'Starting (PID' "$OUTFILE" 2>/dev/null; then
        break
    fi
done

LINE=$(grep -m1 'Starting (PID' "$OUTFILE" 2>/dev/null || echo "")
echo "Proc: $LINE"

# Confirm alive
if ! kill -0 "$TARGET_PID" 2>/dev/null; then
    echo "ERROR: PID $TARGET_PID exited before baseliner could attach"
    cat "$OUTFILE"
    exit 1
fi

echo "Attaching baseliner to PID $TARGET_PID..."
echo "$TARGET_PID" | bin/baseliner

echo "Done."
