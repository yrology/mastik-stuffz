#!/bin/bash
# =============================================================================
# 1_build.sh  —  Build all attack demos
# Run from ~/Downloads/mastik_assignment/ (or wherever you extracted the tar)
# =============================================================================

set -e
ASSIGN_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$ASSIGN_DIR"

# ── Find Mastik ───────────────────────────────────────────────────────────────
# Check config.env first (written by 0_setup.sh)
if [ -f "$ASSIGN_DIR/config.env" ]; then
    source "$ASSIGN_DIR/config.env"
    MASTIK="$MASTIK_DIR"
fi

# Fallbacks
if [ -z "$MASTIK" ] || [ ! -d "$MASTIK" ]; then
    for candidate in "$HOME/Mastik" "/home/$USER/Mastik" "/root/Mastik" "/home/claude/Mastik"; do
        if [ -d "$candidate/src" ]; then
            MASTIK="$candidate"
            break
        fi
    done
fi

if [ -z "$MASTIK" ] || [ ! -f "$MASTIK/src/libmastik.a" ]; then
    echo "[!] Cannot find Mastik or libmastik.a."
    echo "    Run: sudo bash 0_setup.sh"
    echo "    (Must use --disable-debug-symbols on Ubuntu 22+)"
    exit 1
fi

echo "Using Mastik at: $MASTIK"
export LD_LIBRARY_PATH="$MASTIK/src"

INC="-I$MASTIK"
# Use static linking (-lmastik from .a) so LD_LIBRARY_PATH isn't needed at runtime
LIB="$MASTIK/src/libmastik.a -lbfd -lelf"
FLAGS="-O0 -g"

echo ""
echo "Building all attack demos..."
echo ""

build() {
    local src="$1"
    local out="${src%.c}"
    echo -n "  $src ... "
    gcc $FLAGS -o "$out" "$src" $INC $LIB 2>&1 && echo "OK → ./$out" || echo "FAILED ↑"
}

build calibrate.c
build attack1_flush_reload.c
build victim1.c
build attack2_prime_probe.c
build attack3_flush_flush.c
build attack4_aes_key_recovery.c

echo ""
echo "── Attack 5: OpenSSL AES-CBC (needs libssl-dev) ──────────────────────"

# Check libssl-dev is installed
if pkg-config --exists openssl 2>/dev/null || [ -f /usr/include/openssl/aes.h ]; then
    echo -n "  attack5_openssl_aes.c ... "
    gcc $FLAGS -o attack5_openssl_aes attack5_openssl_aes.c $INC $LIB -lssl -lcrypto \
        -Wno-deprecated-declarations 2>&1 && echo "OK → ./attack5_openssl_aes" || echo "FAILED ↑"

    echo -n "  victim_openssl_aes.c  ... "
    gcc $FLAGS -o victim_openssl_aes victim_openssl_aes.c -lssl -lcrypto \
        -Wno-deprecated-declarations 2>&1 && echo "OK → ./victim_openssl_aes" || echo "FAILED ↑"
else
    echo "  [skipped] libssl-dev not found."
    echo "  Install it with: sudo apt-get install libssl-dev"
    echo "  Then re-run: bash 1_build.sh"
fi

echo ""
echo "✅ Done! Run attacks (no LD_LIBRARY_PATH needed — statically linked):"
echo ""
echo "  sudo bash 0_setup.sh       ← once per reboot (re-disables ASLR)"
echo "  ./calibrate                ← always run first to get thresholds"
echo ""
echo "  Attacks 1-4 (two terminals each):"
echo "    Terminal 1: ./attack1_flush_reload   Terminal 2: ./victim1"
echo "    Terminal 1: ./attack2_prime_probe    Terminal 2: ./victim1"
echo "    Terminal 1: ./attack3_flush_flush    Terminal 2: ./victim1"
echo "    Single:     ./attack4_aes_key_recovery"
echo ""
echo "  Attack 5 — OpenSSL AES-CBC Prime+Probe (two terminals):"
echo "    Terminal 1: ./attack5_openssl_aes"
echo "    Terminal 2: ./victim_openssl_aes"
echo ""
echo "  See HOW_TO_RUN.md for full details."
