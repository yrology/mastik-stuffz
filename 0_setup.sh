#!/bin/bash
# =============================================================================
# 0_setup.sh  —  Run ONCE with sudo before anything else
# Fixes libdwarf version issue on Ubuntu 22.04/24.04/25.04
# =============================================================================

set -e

echo "============================================"
echo "  Mastik Side-Channel Toolkit — Setup"
echo "============================================"
echo ""

# ── 1. Install dependencies ──────────────────────────────────────────────────
echo "[1/5] Installing build dependencies..."
apt-get update -qq
apt-get install -y --no-install-recommends \
    build-essential git binutils-dev libdwarf-dev libelf-dev libssl-dev

# ── 2. Clone Mastik ──────────────────────────────────────────────────────────
echo ""
echo "[2/5] Cloning Mastik..."
MASTIK_DIR="$HOME/Mastik"

# If run with sudo, HOME might be /root. Use SUDO_USER's home instead.
if [ -n "$SUDO_USER" ]; then
    REAL_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
    MASTIK_DIR="$REAL_HOME/Mastik"
fi

if [ ! -d "$MASTIK_DIR" ]; then
    git clone https://github.com/0xADE1A1DE/Mastik.git "$MASTIK_DIR"
    # Fix ownership if cloned as root on behalf of another user
    [ -n "$SUDO_USER" ] && chown -R "$SUDO_USER:$SUDO_USER" "$MASTIK_DIR"
else
    echo "  Already cloned at $MASTIK_DIR"
fi

# ── 3. Build Mastik ──────────────────────────────────────────────────────────
echo "[3/5] Building Mastik..."
echo "  NOTE: Using --disable-debug-symbols to bypass libdwarf API mismatch"
echo "        (Ubuntu 22.04+ ships libdwarf 0.4+ which removed dwarf_init)"
cd "$MASTIK_DIR"
./configure --disable-debug-symbols 2>&1 | grep -E "error|warning|checking for bfd|checking for elf|checking for dwarf" || true
make 2>&1 | grep -E "error|Error|warning" | grep -v "^Makefile" || true

if [ -f "$MASTIK_DIR/src/libmastik.a" ]; then
    echo "  ✅ Build successful: libmastik.a found"
else
    echo "  ❌ Build FAILED — libmastik.a not found"
    exit 1
fi

# ── 4. Kernel security settings ──────────────────────────────────────────────
echo ""
echo "[4/5] Configuring kernel for experiments..."
echo 0 > /proc/sys/kernel/randomize_va_space
echo "  ASLR disabled: $(cat /proc/sys/kernel/randomize_va_space)"
echo 1 > /proc/sys/kernel/perf_event_paranoid
echo "  perf_event_paranoid: $(cat /proc/sys/kernel/perf_event_paranoid)"

# ── 5. Detect puts() offset in libc ──────────────────────────────────────────
echo ""
echo "[5/5] Detecting system libc puts() offset..."
LIBC_PATH=$(ldconfig -p | grep "libc.so.6" | grep "x86-64" | head -1 | awk '{print $NF}')
PUTS_OFFSET=$(readelf -s "$LIBC_PATH" | grep " puts@@" | awk '{print $2}')
echo "  libc path   : $LIBC_PATH"
echo "  puts offset : 0x$PUTS_OFFSET"

# Write config for build script
ASSIGN_DIR="$(cd "$(dirname "$0")" && pwd)"
cat > "$ASSIGN_DIR/config.env" << ENVEOF
MASTIK_DIR=$MASTIK_DIR
LIBC_PATH=$LIBC_PATH
PUTS_OFFSET=0x$PUTS_OFFSET
export LD_LIBRARY_PATH=$MASTIK_DIR/src
ENVEOF
[ -n "$SUDO_USER" ] && chown "$SUDO_USER:$SUDO_USER" "$ASSIGN_DIR/config.env"

echo ""
echo "============================================"
echo "  Setup complete!"
echo ""
echo "  NEXT: cd ~/Downloads/mastik_assignment"
echo "        bash 1_build.sh"
echo "============================================"
