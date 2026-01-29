/*
 * Self-Guard Runtime Integrity Protection Library
 * C Implementation Layer
 *
 * Responsibilities:
 * - Public API implementation
 * - Input validation
 * - C++ core orchestration
 */

#include "self_guard.h"
#include <string.h>
#include <stdio.h>

/* Forward declarations for C++ core functions */
extern int guard_core_init(void);
extern int guard_core_shutdown(void);
extern int guard_core_snapshot(void);
extern int guard_core_check_integrity(uint32_t flags);
extern int guard_core_detect_debugger(void);
extern int guard_core_get_state(void);

/* Global initialization flag (protected by C++ layer mutex) */
static volatile int sg_initialized = 0;

/* ============================================
 * API Implementation
 * ============================================ */

sg_result_t sg_init(void) {
    if (sg_initialized) {
        return SG_ERR_ALREADY_INIT;
    }

    int result = guard_core_init();
    if (result != 0) {
        return SG_ERR_INIT;
    }

    sg_initialized = 1;
    return SG_OK;
}

sg_result_t sg_snapshot(void) {
    if (!sg_initialized) {
        return SG_ERR_NOT_INIT;
    }

    int result = guard_core_snapshot();
    if (result != 0) {
        return SG_ERR_INTERNAL;
    }

    return SG_OK;
}

sg_result_t sg_check_integrity(uint32_t flags) {
    if (!sg_initialized) {
        return SG_ERR_NOT_INIT;
    }

    /* Validate flags - must have at least one check enabled */
    if (flags == 0) {
        return SG_ERR_INTERNAL;
    }

    int result = guard_core_check_integrity(flags);
    if (result != 0) {
        return SG_ERR_INTERNAL;
    }

    return SG_OK;
}

int sg_detect_debugger(void) {
    if (!sg_initialized) {
        return -1;
    }

    return guard_core_detect_debugger();
}

sg_security_state_t sg_get_security_state(void) {
    if (!sg_initialized) {
        /* Fail-secure: assume compromised if not initialized */
        return SG_COMPROMISED;
    }

    int state = guard_core_get_state();
    
    /* Validate state is within enum range */
    if (state < SG_SAFE || state > SG_COMPROMISED) {
        return SG_COMPROMISED;
    }

    return (sg_security_state_t)state;
}

sg_result_t sg_shutdown(void) {
    if (!sg_initialized) {
        return SG_ERR_NOT_INIT;
    }

    int result = guard_core_shutdown();
    sg_initialized = 0;

    if (result != 0) {
        return SG_ERR_INTERNAL;
    }

    return SG_OK;
}