/*
 * victim_openssl_aes.c  —  OpenSSL AES-CBC victim using T-table path
 * ─────────────────────────────────────────────────────────────────────────────
 * Uses AES_cbc_encrypt() (lowercase API) which calls AES_encrypt() internally.
 * AES_encrypt() uses software T-tables — NOT AES-NI hardware.
 * This makes it vulnerable to Prime+Probe cache side-channel attacks.
 *
 * WHY NOT EVP_aes_128_cbc()?
 *   EVP uses AES-NI on modern CPUs (no table lookups → no cache leak).
 *   AES_cbc_encrypt() forces the software T-table implementation.
 *
 * BUILD:
 *   gcc -O0 -o victim_openssl_aes victim_openssl_aes.c -lssl -lcrypto
 *
 * RUN:
 *   ./victim_openssl_aes
 *   (run WHILE attack5_openssl_aes.c is running in another terminal)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/aes.h>    /* AES_cbc_encrypt, AES_set_encrypt_key */

/* ── Secret key — the spy will try to recover these bytes ──────────────── */
static const unsigned char KEY[16] = {
    0x2b, 0x7e, 0x15, 0x16,
    0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88,
    0x09, 0xcf, 0x4f, 0x3c
};

/* Fixed IV for CBC mode */
static const unsigned char IV_TEMPLATE[16] = {
    0x00, 0x01, 0x02, 0x03,
    0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b,
    0x0c, 0x0d, 0x0e, 0x0f
};

int main(void) {
    AES_KEY aes_key;
    unsigned char plaintext[16];
    unsigned char ciphertext[16];
    unsigned char iv[16];

    /* Set up the encryption key (expands into round keys) */
    if (AES_set_encrypt_key(KEY, 128, &aes_key) != 0) {
        fprintf(stderr, "[victim] AES_set_encrypt_key failed\n");
        return 1;
    }

    printf("[victim] AES-CBC encryption started\n");
    printf("[victim] Using AES_cbc_encrypt() — T-table software path\n");
    printf("[victim] Key: ");
    for (int i = 0; i < 16; i++) printf("%02x ", KEY[i]);
    printf("\n");
    printf("[victim] Encrypting 1 block every 200ms...\n\n");

    int count = 0;
    while (1) {
        /* Use a different plaintext each time (known to spy via stdout) */
        for (int i = 0; i < 16; i++)
            plaintext[i] = (count * 16 + i) & 0xff;

        /* Reset IV each block (so we're really doing ECB via CBC) */
        memcpy(iv, IV_TEMPLATE, 16);

        /* ── THIS CALL LEAKS KEY BYTES VIA T-TABLE ACCESS PATTERN ── */
        AES_cbc_encrypt(plaintext, ciphertext, 16, &aes_key, iv, AES_ENCRYPT);

        printf("[victim #%4d] pt=%02x%02x%02x%02x... ct=%02x%02x%02x%02x...\n",
               count,
               plaintext[0], plaintext[1], plaintext[2], plaintext[3],
               ciphertext[0], ciphertext[1], ciphertext[2], ciphertext[3]);
        fflush(stdout);

        count++;
        usleep(200000);   /* 200ms between encryptions */
    }

    return 0;
}
