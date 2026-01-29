/*
 * Self-Guard Assembly Backend: ARM64 (AArch64)
 * 
 * Platform: ARM64 / AArch64
 * OS: Linux, Android (Termux), macOS (Apple Silicon)
 * Assembler: GAS (GNU Assembler)
 * 
 * ABI: ARM64 Procedure Call Standard (AAPCS64)
 * - Arguments: X0-X7
 * - Return: X0
 * - Callee-saved: X19-X28
 */

#if defined(__aarch64__) || defined(__arm64__)

.text
.align 4

/* ============================================
 * sg_get_cycle_counter
 * 
 * Read ARM64 Virtual Counter (CNTVCT_EL0)
 * 
 * Alternative to x86 RDTSC
 * Requires: Generic Timer extension (standard on ARMv8)
 * 
 * Returns: X0 = 64-bit counter value
 * ============================================ */

#if defined(__APPLE__)
    .globl _sg_get_cycle_counter
    .p2align 2
    _sg_get_cycle_counter:
#else
    .globl sg_get_cycle_counter
    .type sg_get_cycle_counter, @function
    sg_get_cycle_counter:
#endif

    /* Read virtual counter (user-accessible) */
    mrs     x0, CNTVCT_EL0
    
    /* Instruction barrier for precise timing */
    isb
    
    ret

#if !defined(__APPLE__)
    .size sg_get_cycle_counter, .-sg_get_cycle_counter
#endif


/* ============================================
 * sg_low_level_check
 * 
 * ARM64 debugger detection
 * 
 * Methods:
 * 1. Check MDSCR_EL1 (Monitor Debug System Control Register)
 *    - Requires EL1; will fault in userspace
 * 2. Check for single-step flag (handled in exception)
 * 
 * Returns: X0 = detection result
 * ============================================ */

#if defined(__APPLE__)
    .globl _sg_low_level_check
    .p2align 2
    _sg_low_level_check:
#else
    .globl sg_low_level_check
    .type sg_low_level_check, @function
    sg_low_level_check:
#endif

    /* 
     * ARM64 debug detection is limited in userspace
     * We use timing-based heuristics instead
     * 
     * Alternative: Check for ptrace via /proc/self/status (in C layer)
     */
    
    mov     x0, #0            /* Default: no debugger */
    
    /* 
     * Attempt to read MDSCR_EL1 (will fault if unprivileged)
     * This fault can be caught by signal handler
     */
    
#if defined(__linux__)
    /* On Linux, this typically faults - handled by C wrapper */
    /* mrs     x1, MDSCR_EL1 */  /* Commented out - requires EL1 */
#endif
    
    ret

#if !defined(__APPLE__)
    .size sg_low_level_check, .-sg_low_level_check
#endif


/* ============================================
 * sg_timing_check
 * 
 * Timing-based anomaly detection on ARM64
 * ============================================ */

#if defined(__APPLE__)
    .globl _sg_timing_check
    .p2align 2
    _sg_timing_check:
#else
    .globl sg_timing_check
    .type sg_timing_check, @function
    sg_timing_check:
#endif

    stp     x19, x30, [sp, #-16]!  /* Save frame pointer and link register */
    
    /* First timestamp */
    mrs     x19, CNTVCT_EL0
    isb
    
    /* NOP sled */
    .rept 10
    nop
    .endr
    
    /* Second timestamp */
    mrs     x0, CNTVCT_EL0
    isb
    
    /* Calculate delta */
    sub     x0, x0, x19
    
    /* Threshold: 1000 cycles (adjust for ARM clock rate) */
    mov     x1, #1000
    cmp     x0, x1
    b.hi    1f                /* Branch if higher (anomaly) */
    
    mov     x0, #0            /* Normal timing */
    b       2f
    
1:  mov     x0, #1            /* Anomaly detected */

2:  ldp     x19, x30, [sp], #16
    ret

#if !defined(__APPLE__)
    .size sg_timing_check, .-sg_timing_check
#endif


/* ============================================
 * sg_checksum_memory
 * 
 * Parameters:
 *   X0 = start address
 *   X1 = length
 * 
 * Returns: W0 = 32-bit checksum
 * ============================================ */

#if defined(__APPLE__)
    .globl _sg_checksum_memory
    .p2align 2
    _sg_checksum_memory:
#else
    .globl sg_checksum_memory
    .type sg_checksum_memory, @function
    sg_checksum_memory:
#endif

    stp     x19, x20, [sp, #-16]!
    
    mov     w19, #0           /* W19 = checksum accumulator */
    mov     x20, #0           /* X20 = index */
    
    cbz     x1, .Lchk_done    /* Check if length == 0 */

.Lchk_loop:
    ldrb    w2, [x0, x20]     /* Load byte */
    ror     w19, w19, #31     /* Rotate right by 31 = rotate left by 1 */
    eor     w19, w19, w2      /* XOR in byte */
    
    add     x20, x20, #1
    cmp     x20, x1
    b.lt    .Lchk_loop

.Lchk_done:
    mov     w0, w19           /* Return checksum in W0 */
    ldp     x19, x20, [sp], #16
    ret

#if !defined(__APPLE__)
    .size sg_checksum_memory, .-sg_checksum_memory
#endif

#endif /* __aarch64__ || __arm64__ */