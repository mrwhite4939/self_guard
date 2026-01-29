/*
 * Self-Guard Runtime Integrity Protection Library
 * Public API Header
 *
 * Security Model:
 * - Detects debuggers, memory tampering, and timing attacks
 * - Thread-safe state management
 * - Zero-trust verification model
 */

#ifndef SELF_GUARD_H
#define SELF_GUARD_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================
 * Security State Definitions
 * ============================================ */

typedef enum {
    SG_SAFE = 0,        /* All integrity checks passed */
    SG_WARNING = 1,     /* Suspicious activity detected */
    SG_COMPROMISED = 2  /* Active tampering confirmed */
} sg_security_state_t;

/* ============================================
 * Return Codes
 * ============================================ */

typedef enum {
    SG_OK = 0,
    SG_ERR_INIT = -1,
    SG_ERR_NOT_INIT = -2,
    SG_ERR_ALREADY_INIT = -3,
    SG_ERR_INTERNAL = -4
} sg_result_t;

/* ============================================
 * Integrity Check Flags
 * ============================================ */

#define SG_CHECK_DEBUGGER   (1 << 0)
#define SG_CHECK_TIMING     (1 << 1)
#define SG_CHECK_MEMORY     (1 << 2)
#define SG_CHECK_STACK      (1 << 3)
#define SG_CHECK_ALL        (0xFFFFFFFF)

/* ============================================
 * Public API Functions
 * ============================================ */

/*
 * Initialize the security library
 * MUST be called before any other function
 * 
 * Returns: SG_OK on success, error code otherwise
 * Side effects: Allocates internal state, takes memory snapshot
 */
sg_result_t sg_init(void);

/*
 * Take a snapshot of current process state
 * Used as baseline for future integrity checks
 *
 * Returns: SG_OK on success, SG_ERR_NOT_INIT if not initialized
 * Side effects: Updates internal baseline checksums
 */
sg_result_t sg_snapshot(void);

/*
 * Perform comprehensive integrity check
 *
 * Parameters:
 *   flags - Bitmask of SG_CHECK_* values
 *
 * Returns: SG_OK if all checks pass, error code on failure
 * Side effects: May update security state to WARNING/COMPROMISED
 */
sg_result_t sg_check_integrity(uint32_t flags);

/*
 * Fast debugger detection check
 * Uses hardware registers and timing analysis
 *
 * Returns: 1 if debugger detected, 0 otherwise, -1 on error
 */
int sg_detect_debugger(void);

/*
 * Get current security state
 *
 * Returns: Current state (SG_SAFE, SG_WARNING, SG_COMPROMISED)
 *          Returns SG_COMPROMISED if not initialized
 */
sg_security_state_t sg_get_security_state(void);

/*
 * Shutdown library and cleanup resources
 * Zeros all sensitive memory before deallocation
 *
 * Returns: SG_OK on success
 * Side effects: Invalidates all internal state
 */
sg_result_t sg_shutdown(void);

#ifdef __cplusplus
}
#endif

#endif /* SELF_GUARD_H */