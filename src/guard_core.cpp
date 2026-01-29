/*
 * Self-Guard Runtime Integrity Protection Library
 * C++ Security Core
 *
 * Responsibilities:
 * - Security state management
 * - Integrity verification orchestration
 * - Thread-safe access control
 *
 * CRITICAL FIX: All C-callable functions wrapped in extern "C"
 */

#include <cstdint>
#include <cstring>
#include <mutex>
#include <atomic>
#include <new>

extern "C" {
    #include "self_guard.h"
    #include "self_guard_asm.h"
}

/* ============================================
 * Platform-Specific Code Section Detection
 * ============================================ */

namespace {

struct CodeSection {
    const void* start;
    size_t size;
    bool available;
};

#if defined(__linux__) && !defined(__ANDROID__)
/* Linux ELF: Use linker-provided symbols */
extern "C" {
    extern char __executable_start;
    extern char __etext;
}

CodeSection get_code_section() {
    CodeSection section;
    section.start = static_cast<const void*>(&__executable_start);
    section.size = static_cast<size_t>(
        reinterpret_cast<uintptr_t>(&__etext) - 
        reinterpret_cast<uintptr_t>(&__executable_start)
    );
    section.available = true;
    return section;
}

#elif defined(__APPLE__)
/* macOS: Use Mach-O segment introspection */
#include <mach-o/getsect.h>
#include <mach-o/dyld.h>

CodeSection get_code_section() {
    CodeSection section;
    
    /* Get __TEXT segment (contains executable code) */
    unsigned long size = 0;
    const struct mach_header_64* header = 
        reinterpret_cast<const struct mach_header_64*>(
            _dyld_get_image_header(0)
        );
    
    const uint8_t* text = getsectiondata(
        header,
        "__TEXT",
        "__text",
        &size
    );
    
    if (text != nullptr && size > 0) {
        section.start = static_cast<const void*>(text);
        section.size = static_cast<size_t>(size);
        section.available = true;
    } else {
        section.start = nullptr;
        section.size = 0;
        section.available = false;
    }
    
    return section;
}

#elif defined(__ANDROID__)
/* Android: Use /proc/self/maps parsing */
#include <stdio.h>
#include <stdlib.h>

CodeSection get_code_section() {
    CodeSection section;
    section.start = nullptr;
    section.size = 0;
    section.available = false;
    
    FILE* maps = fopen("/proc/self/maps", "r");
    if (maps == nullptr) {
        return section;
    }
    
    char line[512];
    while (fgets(line, sizeof(line), maps) != nullptr) {
        unsigned long start_addr, end_addr;
        char perms[5];
        
        if (sscanf(line, "%lx-%lx %4s", &start_addr, &end_addr, perms) == 3) {
            /* Look for executable segment (r-xp) */
            if (perms[0] == 'r' && perms[2] == 'x') {
                section.start = reinterpret_cast<const void*>(start_addr);
                section.size = static_cast<size_t>(end_addr - start_addr);
                section.available = true;
                break;
            }
        }
    }
    
    fclose(maps);
    return section;
}

#else
/* Generic fallback: Code section unavailable */
CodeSection get_code_section() {
    CodeSection section;
    section.start = nullptr;
    section.size = 0;
    section.available = false;
    return section;
}
#endif

} /* anonymous namespace */

/* ============================================
 * Security State Manager
 * ============================================ */

class SecurityStateManager {
private:
    std::atomic<sg_security_state_t> current_state;
    std::mutex state_mutex;
    
    /* Baseline integrity data */
    struct MemoryBaseline {
        uint32_t code_checksum;
        uint64_t baseline_tsc;
        uint8_t initialized;
        uint8_t padding[7]; /* Explicit padding for alignment */
    } baseline;

    /* Secure memory clearing */
    static void secure_zero(void* ptr, size_t size) {
        volatile uint8_t* p = static_cast<volatile uint8_t*>(ptr);
        for (size_t i = 0; i < size; ++i) {
            p[i] = 0;
        }
    }

public:
    SecurityStateManager() : current_state(SG_COMPROMISED) {
        secure_zero(&baseline, sizeof(baseline));
    }

    ~SecurityStateManager() {
        secure_zero(&baseline, sizeof(baseline));
    }

    bool initialize() {
        std::lock_guard<std::mutex> lock(state_mutex);
        
        if (baseline.initialized) {
            return false;
        }

        /* Take initial snapshot */
        baseline.baseline_tsc = sg_get_cycle_counter();
        baseline.initialized = 1;
        current_state.store(SG_SAFE, std::memory_order_release);
        
        return true;
    }

    bool shutdown() {
        std::lock_guard<std::mutex> lock(state_mutex);
        
        if (!baseline.initialized) {
            return false;
        }

        secure_zero(&baseline, sizeof(baseline));
        current_state.store(SG_COMPROMISED, std::memory_order_release);
        
        return true;
    }

    bool take_snapshot() {
        std::lock_guard<std::mutex> lock(state_mutex);
        
        if (!baseline.initialized) {
            return false;
        }

        /* Get code section */
        CodeSection code = get_code_section();
        
        if (code.available) {
            baseline.code_checksum = sg_checksum_memory(code.start, code.size);
        } else {
            /* If code section unavailable, checksum our own data structure */
            baseline.code_checksum = sg_checksum_memory(&baseline, sizeof(baseline));
        }
        
        return true;
    }

    bool check_integrity(uint32_t flags) {
        std::lock_guard<std::mutex> lock(state_mutex);
        
        if (!baseline.initialized) {
            return false;
        }

        bool suspicious = false;
        bool compromised = false;

        /* Debugger detection */
        if (flags & SG_CHECK_DEBUGGER) {
            int dbg_result = sg_low_level_check();
            if (dbg_result > 0) {
                compromised = true;
            }
        }

        /* Timing analysis */
        if (flags & SG_CHECK_TIMING) {
            int timing_result = sg_timing_check();
            if (timing_result > 0) {
                suspicious = true;
            }
        }

        /* Memory integrity */
        if (flags & SG_CHECK_MEMORY) {
            CodeSection code = get_code_section();
            
            if (code.available) {
                uint32_t current_checksum = sg_checksum_memory(code.start, code.size);
                
                if (current_checksum != baseline.code_checksum) {
                    compromised = true;
                }
            } else {
                /* Fallback: check our own structure integrity */
                uint32_t current_checksum = sg_checksum_memory(&baseline, sizeof(baseline));
                
                /* This is a weaker check but better than nothing */
                if (current_checksum != baseline.code_checksum) {
                    suspicious = true;
                }
            }
        }

        /* Update state based on findings */
        if (compromised) {
            current_state.store(SG_COMPROMISED, std::memory_order_release);
        } else if (suspicious) {
            /* Only downgrade to WARNING if not already COMPROMISED */
            sg_security_state_t expected = SG_SAFE;
            current_state.compare_exchange_strong(expected, SG_WARNING, 
                                                   std::memory_order_release);
        }

        return true;
    }

    int detect_debugger() const {
        /* No lock needed - read-only atomic operation */
        return sg_low_level_check();
    }

    sg_security_state_t get_state() const {
        return current_state.load(std::memory_order_acquire);
    }
};

/* Global state manager (singleton pattern) */
static SecurityStateManager* g_state_manager = nullptr;

/* ============================================
 * C Interface Implementation
 * CRITICAL: extern "C" prevents name mangling
 * ============================================ */

extern "C" {

int guard_core_init(void) {
    if (g_state_manager != nullptr) {
        return -1;
    }

    g_state_manager = new(std::nothrow) SecurityStateManager();
    if (g_state_manager == nullptr) {
        return -1;
    }

    if (!g_state_manager->initialize()) {
        delete g_state_manager;
        g_state_manager = nullptr;
        return -1;
    }

    return 0;
}

int guard_core_shutdown(void) {
    if (g_state_manager == nullptr) {
        return -1;
    }

    g_state_manager->shutdown();
    delete g_state_manager;
    g_state_manager = nullptr;

    return 0;
}

int guard_core_snapshot(void) {
    if (g_state_manager == nullptr) {
        return -1;
    }

    return g_state_manager->take_snapshot() ? 0 : -1;
}

int guard_core_check_integrity(uint32_t flags) {
    if (g_state_manager == nullptr) {
        return -1;
    }

    return g_state_manager->check_integrity(flags) ? 0 : -1;
}

int guard_core_detect_debugger(void) {
    if (g_state_manager == nullptr) {
        return -1;
    }

    return g_state_manager->detect_debugger();
}

int guard_core_get_state(void) {
    if (g_state_manager == nullptr) {
        return SG_COMPROMISED;
    }

    return static_cast<int>(g_state_manager->get_state());
}

} /* extern "C" */