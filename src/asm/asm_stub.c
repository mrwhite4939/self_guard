/*
 * Self-Guard Portable C Fallback
 * 
 * Used when:
 * - Architecture is not x86_64 or ARM64
 * - Assembly is disabled (safety/portability)
 * - Compiler doesn't support inline assembly
 * 
 * Trade-offs:
 * - Lower precision timing
 * - No hardware register access
 * - Statistical detection only
 */

#include "self_guard_asm.h"
#include <time.h>
#include <string.h>
#include <stdio.h>

/* Compile this fallback only if no native assembly is available */
#if !defined(__x86_64__) && !defined(_M_X64) && !defined(__aarch64__) && !defined(__arm64__)

/* ============================================
 * Portable Timing via clock_gettime
 * ============================================ */

uint64_t sg_get_cycle_counter(void) {
    struct timespec ts;
    
#if defined(CLOCK_MONOTONIC_RAW)
    /* Linux: raw monotonic clock (no NTP adjustment) */
    if (clock_gettime(CLOCK_MONOTONIC_RAW, &ts) == 0) {
        return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
    }
#endif

#if defined(CLOCK_MONOTONIC)
    /* Fallback: standard monotonic clock */
    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
        return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
    }
#endif

    /* Last resort: wall clock time (not monotonic) */
    if (clock_gettime(CLOCK_REALTIME, &ts) == 0) {
        return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
    }

    return 0;
}

/* ============================================
 * Heuristic Debugger Detection
 * ============================================ */

int sg_low_level_check(void) {
    /*
     * C-level detection methods:
     * 1. Check /proc/self/status (Linux)
     * 2. Check parent process name (Linux)
     * 3. Check timing consistency
     * 
     * This is significantly weaker than hardware methods
     */
    
#if defined(__linux__)
    /* Check TracerPid in /proc/self/status */
    FILE* f = fopen("/proc/self/status", "r");
    if (f != NULL) {
        char line[256];
        while (fgets(line, sizeof(line), f) != NULL) {
            if (strncmp(line, "TracerPid:", 10) == 0) {
                int tracer_pid = 0;
                if (sscanf(line + 10, "%d", &tracer_pid) == 1) {
                    fclose(f);
                    return (tracer_pid != 0) ? 1 : 0;
                }
            }
        }
        fclose(f);
    }
#endif

    /* No debugger detected (or method unavailable) */
    return 0;
}

/* ============================================
 * Timing Check via clock_gettime
 * ============================================ */

int sg_timing_check(void) {
    uint64_t start = sg_get_cycle_counter();
    
    /* Volatile to prevent optimization */
    volatile int dummy = 0;
    for (int i = 0; i < 10; i++) {
        dummy += i;
    }
    
    uint64_t end = sg_get_cycle_counter();
    uint64_t delta = end - start;
    
    /* 
     * Threshold in nanoseconds (less precise than RDTSC)
     * Normal: <1000ns
     * Debugged: >100000ns
     */
    return (delta > 100000) ? 1 : 0;
}

/* ============================================
 * Portable Memory Checksumming
 * ============================================ */

uint32_t sg_checksum_memory(const void* start, size_t length) {
    const uint8_t* data = (const uint8_t*)start;
    uint32_t checksum = 0;
    
    if (start == NULL || length == 0) {
        return 0;
    }
    
    for (size_t i = 0; i < length; i++) {
        /* Rotate left by 1 bit */
        checksum = (checksum << 1) | (checksum >> 31);
        /* XOR in current byte */
        checksum ^= data[i];
    }
    
    return checksum;
}

const char* sg_get_implementation(void) {
    return "c-fallback";
}

#endif /* Fallback implementation */