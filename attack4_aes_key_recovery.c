/*
 * attack4_aes_key_recovery.c  —  AES key byte recovery via L1 Prime+Probe
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * WHAT IT DOES:
 *   Recovers AES encryption key bytes by observing cache access patterns
 *   during AES encryption. This is the attack that breaks AES in OpenSSL
 *   (table-based AES, not AES-NI).
 *
 * HOW IT WORKS:
 *   Table-based AES uses 4 lookup tables (T0–T3), each 1KB.
 *   Which table entry is accessed during encryption depends on:
 *       index = plaintext_byte XOR key_byte
 *   So if we know the plaintext and observe which cache lines were accessed,
 *   we can determine key_byte = plaintext_byte XOR observed_index.
 *
 *   This is a SAME-PROCESS attack — spy and victim share address space.
 *   The attack does 1000 encryptions, measuring cache patterns each time,
 *   then applies statistical analysis to find the most likely key byte.
 *
 * NOTE:
 *   This is a wrapper that runs Mastik's built-in ST-L1PP-AES demo.
 *   That demo is already compiled at $HOME/Mastik/demo/ST-L1PP-AES.
 *
 * BUILD the runner:
 *   gcc -O0 -o attack4_aes_key_recovery attack4_aes_key_recovery.c
 *
 * OR just run the Mastik binary directly:
 *   LD_LIBRARY_PATH=$HOME/Mastik/src $HOME/Mastik/demo/ST-L1PP-AES
 *
 * EXPECTED OUTPUT:
 *   Key byte  0 Guess: 0x2-   ← first nibble of key byte 0
 *   Key byte  1 Guess: 0x7-
 *   ...
 *   (each row is a heatmap of 256 candidate values; brightest = best guess)
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(void) {
    char *mastik_dir = getenv("HOME");
    if (!mastik_dir) mastik_dir = "/root";

    char bin[512];
    snprintf(bin, sizeof(bin), "%s/Mastik/demo/ST-L1PP-AES", mastik_dir);

    char lib[512];
    snprintf(lib, sizeof(lib), "%s/Mastik/src", mastik_dir);

    printf("╔══════════════════════════════════════════════════════╗\n");
    printf("║        ATTACK 4: AES Key Recovery via L1 P+P        ║\n");
    printf("╠══════════════════════════════════════════════════════╣\n");
    printf("║ Method: Differential cache analysis on AES T-tables  ║\n");
    printf("║ Target: AES-128, 10 key bytes recovered             ║\n");
    printf("║ Binary: %-44s║\n", bin);
    printf("╚══════════════════════════════════════════════════════╝\n\n");
    printf("Running Mastik's AES side-channel demo...\n\n");

    setenv("LD_LIBRARY_PATH", lib, 1);
    execl(bin, "ST-L1PP-AES", NULL);

    /* Only reaches here if execl fails */
    perror("execl failed — did you run 0_setup.sh?");
    fprintf(stderr, "Expected binary at: %s\n", bin);
    return 1;
}
