/*
 * Self-Guard Library Usage Example
 * Demonstrates practical runtime integrity monitoring
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "self_guard.h"

/* ANSI color codes for output */
#define COLOR_GREEN  "\x1b[32m"
#define COLOR_YELLOW "\x1b[33m"
#define COLOR_RED    "\x1b[31m"
#define COLOR_RESET  "\x1b[0m"

static const char* state_to_string(sg_security_state_t state) {
    switch (state) {
        case SG_SAFE:        return COLOR_GREEN "SAFE" COLOR_RESET;
        case SG_WARNING:     return COLOR_YELLOW "WARNING" COLOR_RESET;
        case SG_COMPROMISED: return COLOR_RED "COMPROMISED" COLOR_RESET;
        default:             return "UNKNOWN";
    }
}

static const char* result_to_string(sg_result_t result) {
    switch (result) {
        case SG_OK:               return "OK";
        case SG_ERR_INIT:         return "INIT_ERROR";
        case SG_ERR_NOT_INIT:     return "NOT_INITIALIZED";
        case SG_ERR_ALREADY_INIT: return "ALREADY_INITIALIZED";
        case SG_ERR_INTERNAL:     return "INTERNAL_ERROR";
        default:                  return "UNKNOWN_ERROR";
    }
}

int main(void) {
    sg_result_t result;
    sg_security_state_t state;
    int debugger_present;

    printf("=== Self-Guard Runtime Integrity Protection Demo ===\n\n");

    /* ========================================
     * Step 1: Initialize the library
     * ======================================== */
    printf("[*] Initializing Self-Guard...\n");
    result = sg_init();
    if (result != SG_OK) {
        fprintf(stderr, "[!] Initialization failed: %s\n", result_to_string(result));
        return EXIT_FAILURE;
    }
    printf("[+] Initialization: %s\n\n", COLOR_GREEN "SUCCESS" COLOR_RESET);

    /* ========================================
     * Step 2: Take baseline snapshot
     * ======================================== */
    printf("[*] Taking baseline snapshot...\n");
    result = sg_snapshot();
    if (result != SG_OK) {
        fprintf(stderr, "[!] Snapshot failed: %s\n", result_to_string(result));
        sg_shutdown();
        return EXIT_FAILURE;
    }
    
    state = sg_get_security_state();
    printf("[+] Snapshot complete. Security state: %s\n\n", state_to_string(state));

    /* ========================================
     * Step 3: Quick debugger check
     * ======================================== */
    printf("[*] Performing debugger detection...\n");
    debugger_present = sg_detect_debugger();
    
    if (debugger_present == 1) {
        printf("[!] %sDEBUGGER DETECTED%s - Hardware breakpoints active!\n\n", 
               COLOR_RED, COLOR_RESET);
    } else if (debugger_present == 0) {
        printf("[+] No debugger detected (hardware registers clean)\n\n");
    } else {
        fprintf(stderr, "[!] Debugger check failed\n\n");
    }

    /* ========================================
     * Step 4: Continuous monitoring loop
     * ======================================== */
    printf("[*] Starting continuous monitoring (10 iterations)...\n");
    printf("[*] Try attaching a debugger (gdb -p %d) to see detection\n\n", getpid());

    for (int i = 0; i < 10; i++) {
        sleep(1);

        /* Perform comprehensive integrity check */
        result = sg_check_integrity(SG_CHECK_ALL);
        
        state = sg_get_security_state();
        
        printf("[Iteration %2d] Integrity check: %-10s | State: %s\n",
               i + 1,
               result == SG_OK ? COLOR_GREEN "PASS" COLOR_RESET : COLOR_RED "FAIL" COLOR_RESET,
               state_to_string(state));

        /* Respond to state changes */
        if (state == SG_COMPROMISED) {
            printf("\n[!] %sSECURITY BREACH DETECTED!%s\n", COLOR_RED, COLOR_RESET);
            printf("[!] Possible causes:\n");
            printf("    - Debugger attached\n");
            printf("    - Memory tampering\n");
            printf("    - Code modification\n");
            printf("[!] Terminating for safety...\n\n");
            break;
        } else if (state == SG_WARNING) {
            printf("    ^-- Suspicious activity (timing anomalies)\n");
        }
    }

    /* ========================================
     * Step 5: Shutdown and cleanup
     * ======================================== */
    printf("\n[*] Shutting down Self-Guard...\n");
    result = sg_shutdown();
    if (result != SG_OK) {
        fprintf(stderr, "[!] Shutdown failed: %s\n", result_to_string(result));
        return EXIT_FAILURE;
    }
    
    printf("[+] Shutdown complete. All resources cleaned.\n");
    printf("\n=== Demo Complete ===\n");

    return EXIT_SUCCESS;
}