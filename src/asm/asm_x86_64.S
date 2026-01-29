/*
 * Self-Guard Assembly Backend: x86_64
 * 
 * Platform: x86_64 (AMD64, Intel 64)
 * OS: Linux, macOS, Windows (with MinGW/MSVC)
 * Assembler: GAS (AT&T/Intel syntax)
 * 
 * ABI Compliance:
 * - System V AMD64 ABI (Linux, macOS)
 * - Microsoft x64 calling convention (Windows)
 */

#if defined(__x86_64__) || defined(_M_X64)

/* Use Intel syntax for readability */
.intel_syntax noprefix

.text

/* ============================================
 * sg_get_cycle_counter
 * 
 * Read x86 Time Stamp Counter (RDTSC)
 * 
 * Returns: RAX = 64-bit TSC value
 * ============================================ */

#if defined(__APPLE__)
    /* macOS requires underscore prefix */
    .globl _sg_get_cycle_counter
    _sg_get_cycle_counter:
#elif defined(_WIN32)
    /* Windows MSVC/MinGW */
    .globl sg_get_cycle_counter
    sg_get_cycle_counter:
#else
    /* Linux and other Unix-like */
    .globl sg_get_cycle_counter
    .type sg_get_cycle_counter, @function
    sg_get_cycle_counter:
#endif

    /* Preserve callee-saved registers */
    push    rbx
    push    rcx
    push    rdx

    /* Serialize execution to ensure accurate timing */
    xor     eax, eax
    cpuid                     /* CPUID acts as serializing instruction */

    /* Read Time Stamp Counter */
    rdtsc                     /* EDX:EAX = TSC */
    
    /* Combine into 64-bit result */
    shl     rdx, 32
    or      rax, rdx          /* RAX = full 64-bit timestamp */

    /* Restore registers */
    pop     rdx
    pop     rcx
    pop     rbx
    
    ret

#if !defined(__APPLE__) && !defined(_WIN32)
    .size sg_get_cycle_counter, .-sg_get_cycle_counter
#endif


/* ============================================
 * sg_low_level_check
 * 
 * Check hardware debug registers
 * 
 * Security:
 * - Reading DR0-DR7 requires privilege on Windows
 * - May fault; handled by exception
 * 
 * Returns: 
 *   RAX = 1 if debugger detected
 *   RAX = 0 if clean
 * ============================================ */

#if defined(__APPLE__)
    .globl _sg_low_level_check
    _sg_low_level_check:
#elif defined(_WIN32)
    .globl sg_low_level_check
    sg_low_level_check:
#else
    .globl sg_low_level_check
    .type sg_low_level_check, @function
    sg_low_level_check:
#endif

    push    rbx
    xor     rax, rax          /* Default: no debugger */

    /* 
     * Platform-specific debug register check
     * On macOS/Windows: May require SEH/Mach exception handling
     * On Linux: Works in user-mode if ptrace not active
     */

#if defined(__linux__)
    /* Linux allows reading DR registers in user mode */
    mov     rbx, dr0
    test    rbx, rbx
    jnz     .Ldbg_found

    mov     rbx, dr1
    test    rbx, rbx
    jnz     .Ldbg_found

    mov     rbx, dr2
    test    rbx, rbx
    jnz     .Ldbg_found

    mov     rbx, dr3
    test    rbx, rbx
    jnz     .Ldbg_found

    /* Check DR7 control register */
    mov     rbx, dr7
    and     rbx, 0xFF
    test    rbx, rbx
    jnz     .Ldbg_found

#else
    /* macOS/Windows: Use alternative detection */
    /* Check for debugger via CPUID or PEB (handled in C layer) */
    xor     rax, rax
#endif

    jmp     .Lcheck_done

.Ldbg_found:
    mov     rax, 1

.Lcheck_done:
    pop     rbx
    ret

#if !defined(__APPLE__) && !defined(_WIN32)
    .size sg_low_level_check, .-sg_low_level_check
#endif


/* ============================================
 * sg_timing_check
 * 
 * Detect timing anomalies via RDTSC
 * ============================================ */

#if defined(__APPLE__)
    .globl _sg_timing_check
    _sg_timing_check:
#elif defined(_WIN32)
    .globl sg_timing_check
    sg_timing_check:
#else
    .globl sg_timing_check
    .type sg_timing_check, @function
    sg_timing_check:
#endif

    push    rbx
    push    rcx
    push    rdx

    /* First timestamp */
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    mov     rbx, rax

    /* NOP sled (should execute in <100 cycles) */
    .rept 10
    nop
    .endr

    /* Second timestamp */
    rdtsc
    shl     rdx, 32
    or      rax, rdx

    /* Calculate delta */
    sub     rax, rbx

    /* Threshold: 1000 cycles */
    cmp     rax, 1000
    ja      .Ltiming_anomaly

    xor     rax, rax
    jmp     .Ltiming_done

.Ltiming_anomaly:
    mov     rax, 1

.Ltiming_done:
    pop     rdx
    pop     rcx
    pop     rbx
    ret

#if !defined(__APPLE__) && !defined(_WIN32)
    .size sg_timing_check, .-sg_timing_check
#endif


/* ============================================
 * sg_checksum_memory
 * 
 * Parameters:
 *   RDI (Linux/macOS) / RCX (Windows) = start address
 *   RSI (Linux/macOS) / RDX (Windows) = length
 * 
 * Returns: EAX = 32-bit checksum
 * ============================================ */

#if defined(__APPLE__)
    .globl _sg_checksum_memory
    _sg_checksum_memory:
#elif defined(_WIN32)
    .globl sg_checksum_memory
    sg_checksum_memory:
    /* Windows x64 ABI: RCX=arg1, RDX=arg2 */
    mov     rdi, rcx
    mov     rsi, rdx
#else
    .globl sg_checksum_memory
    .type sg_checksum_memory, @function
    sg_checksum_memory:
#endif

    push    rbx
    push    rcx
    
    xor     eax, eax
    xor     ecx, ecx
    
    test    rsi, rsi
    jz      .Lchk_done

.Lchk_loop:
    movzx   ebx, byte ptr [rdi + rcx]
    rol     eax, 1
    xor     eax, ebx
    
    inc     rcx
    cmp     rcx, rsi
    jl      .Lchk_loop

.Lchk_done:
    pop     rcx
    pop     rbx
    ret

#if !defined(__APPLE__) && !defined(_WIN32)
    .size sg_checksum_memory, .-sg_checksum_memory
#endif

#endif /* __x86_64__ || _M_X64 */