/*
 * Self-Guard Low-Level Detection API
 * Unified C interface across all architectures
 *
 * Design Philosophy:
 * - Same function signatures on all platforms
 * - Architecture-specific implementations selected at compile-time
 * - Safe fallback to C when assembly unavailable
 */

#ifndef SELF_GUARD_ASM_H
#define SELF_GUARD_ASM_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================
 * Unified Low-Level API
 * 
 * These functions have identical signatures
 * across all architectures and operating systems.
 * ============================================ */

/**
 * Get high-resolution cycle counter
 * 
 * Architecture mapping:
 * - x86_64: RDTSC (Time Stamp Counter)
 * - ARM64: CNTVCT_EL0 (Virtual Counter)
 * - Fallback: clock_gettime(CLOCK_MONOTONIC)
 * 
 * Returns: 64-bit monotonic counter value
 * 
 * Security note: Used for timing attack detection.
 * Single-stepping causes observable timing deltas.
 */
uint64_t sg_get_cycle_counter(void);

/**
 * Perform low-level security checks
 * 
 * Checks performed (architecture-dependent):
 * - x86_64: Debug registers (DR0-DR7), CPUID features
 * - ARM64: MRS-based register inspection
 * - Fallback: Statistical analysis only
 * 
 * Returns:
 *   0 = No threat detected
 *   1 = Threat detected (debugger, tampering)
 *  -1 = Check unavailable on this platform
 */
int sg_low_level_check(void);

/**
 * Timing-based anomaly detection
 * 
 * Measures execution time of controlled code sequence.
 * Debuggers/instrumentation cause significant delays.
 * 
 * Returns:
 *   0 = Normal timing
 *   1 = Timing anomaly detected
 */
int sg_timing_check(void);

/**
 * Calculate checksum of memory region
 * 
 * Parameters:
 *   start  - Start address of region
 *   length - Length in bytes
 * 
 * Returns: 32-bit checksum
 * 
 * Algorithm: XOR-based rolling checksum (fast, deterministic)
 */
uint32_t sg_checksum_memory(const void* start, size_t length);

/**
 * Get implementation information
 * 
 * Returns string describing current backend:
 * - "x86_64-native"
 * - "arm64-native"
 * - "c-fallback"
 */
const char* sg_get_implementation(void);

#ifdef __cplusplus
}
#endif

#endif /* SELF_GUARD_ASM_H */