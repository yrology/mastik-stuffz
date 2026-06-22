/*
 * calibrate.c  —  Find correct timing thresholds for THIS system
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * WHAT IT DOES:
 *   Measures actual cache hit/miss timing on your specific CPU and prints
 *   the right thresholds to use in attacks 1, 2, and 3.
 *   Always run this first on a new machine!
 *
 * BUILD:
 *   gcc -O0 -o calibrate calibrate.c \
 *       -I$HOME/Mastik -L$HOME/Mastik/src -lmastik
 *
 * RUN:
 *   LD_LIBRARY_PATH=$HOME/Mastik/src ./calibrate
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <mastik/low.h>
#include "mastik_shared.h"

#define LIBC_PATH   "/lib/x86_64-linux-gnu/libc.so.6"
#define PUTS_OFFSET  0x87be0
#define N            500    /* measurements per test */

static uint32_t measure_reload_hot(void *ptr) {
    volatile char x = *(char*)ptr; (void)x;   /* warm the line */
    mfence();
    uint32_t t1 = rdtscp();
    x = *(char*)ptr;                           /* reload */
    return rdtscp() - t1;
}

static uint32_t measure_reload_cold(void *ptr) {
    clflush(ptr);
    mfence();
    uint64_t d = rdtscp64() + 100000; while(rdtscp64()<d){}
    mfence();
    uint32_t t1 = rdtscp();
    volatile char x = *(char*)ptr; (void)x;   /* cold reload */
    return rdtscp() - t1;
}

static uint32_t measure_flush_hot(void *ptr) {
    volatile char x = *(char*)ptr; (void)x;   /* warm first */
    mfence();
    uint32_t t1 = rdtscp();
    clflush(ptr);                              /* flush hot */
    return rdtscp() - t1;
}

static uint32_t measure_flush_cold(void *ptr) {
    clflush(ptr); mfence();
    uint64_t d = rdtscp64() + 100000; while(rdtscp64()<d){}
    mfence();
    uint32_t t1 = rdtscp();
    clflush(ptr);                              /* flush cold */
    return rdtscp() - t1;
}

int main(void) {
    void *ptr = shared_map_offset(LIBC_PATH, PUTS_OFFSET);
    if (!ptr) { perror("mmap"); return 1; }

    printf("╔══════════════════════════════════════════════════════╗\n");
    printf("║        CALIBRATION — Timing Thresholds              ║\n");
    printf("╚══════════════════════════════════════════════════════╝\n\n");
    printf("Measuring %d samples each...\n\n", N);

    /* ── Flush+Reload thresholds ──────────────────────────────────────── */
    uint64_t hot_sum = 0, cold_sum = 0;
    uint32_t hot_min = ~0u, cold_max = 0;

    for (int i = 0; i < N; i++) {
        uint32_t h = measure_reload_hot(ptr);
        uint32_t c = measure_reload_cold(ptr);
        hot_sum += h;
        cold_sum += c;
        if (h < hot_min) hot_min = h;
        if (c > cold_max) cold_max = c;
    }

    uint32_t fr_hot_avg  = hot_sum  / N;
    uint32_t fr_cold_avg = cold_sum / N;
    uint32_t fr_threshold = (fr_hot_avg + fr_cold_avg) / 2;

    printf("── Flush+Reload (Attack 1) ──────────────────────────\n");
    printf("  Cache HIT  (hot reload) avg : %4u cycles\n", fr_hot_avg);
    printf("  Cache MISS (cold reload) avg: %4u cycles\n", fr_cold_avg);
    printf("  Minimum hot reload          : %4u cycles\n", hot_min);
    printf("  ✓ Suggested THRESHOLD       : %4u cycles\n", fr_threshold);
    printf("    (anything < threshold = HIT)\n\n");

    /* ── Flush+Flush thresholds ──────────────────────────────────────── */
    uint64_t fh_sum = 0, fc_sum = 0;
    for (int i = 0; i < N; i++) {
        fh_sum += measure_flush_hot(ptr);
        fc_sum += measure_flush_cold(ptr);
    }

    uint32_t ff_hot_avg  = fh_sum / N;
    uint32_t ff_cold_avg = fc_sum / N;
    uint32_t ff_threshold = (ff_hot_avg + ff_cold_avg) / 2;

    printf("── Flush+Flush (Attack 3) ──────────────────────────\n");
    printf("  Flush time when line IS   cached: %4u cycles\n", ff_hot_avg);
    printf("  Flush time when line NOT cached : %4u cycles\n", ff_cold_avg);
    printf("  ✓ Suggested FF_THRESHOLD : %4u cycles\n", ff_threshold);
    printf("    (anything > threshold = HIT for Flush+Flush)\n\n");

    /* ── Summary ─────────────────────────────────────────────────────── */
    printf("── Update your attack files with these values ───────\n");
    printf("  attack1_flush_reload.c → #define THRESHOLD  %u\n", fr_threshold);
    printf("  attack3_flush_flush.c  → #define FF_THRESHOLD %u\n", ff_threshold);
    printf("  attack2_prime_probe.c  → #define THRESHOLD  400  (usually fine)\n\n");

    return 0;
}
