/*
 * victim1.c  —  Victim for Attack 1 (Flush+Reload)
 * ─────────────────────────────────────────────────────────────────────────────
 * Simulates a victim process that calls puts() at regular intervals.
 * Run this WHILE attack1_flush_reload is running in another terminal.
 *
 * BUILD:  gcc -O0 -o victim1 victim1.c
 * RUN:    ./victim1
 */

#include <stdio.h>
#include <unistd.h>

int main(void) {
    printf("[victim] Starting — will call puts() every 300ms\n");
    fflush(stdout);

    for (int i = 1; i <= 30; i++) {
        usleep(300000);   /* 300ms */
        puts("victim: calling puts()");   /* <── spy should detect this */
        fflush(stdout);
    }

    printf("[victim] Done.\n");
    return 0;
}
