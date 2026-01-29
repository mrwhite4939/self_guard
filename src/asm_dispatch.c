/*
 * Architecture Dispatcher
 * Provides implementation info for compiled backend
 * 
 * IMPORTANT: Only compiles when assembly backends are active
 * Falls back to stub implementation otherwise
 */

#include "self_guard_asm.h"

/* Only provide dispatcher if using native assembly */
#if defined(__x86_64__) || defined(_M_X64) || defined(__aarch64__) || defined(__arm64__)

const char* sg_get_implementation(void) {
#if defined(__x86_64__) || defined(_M_X64)
    return "x86_64-native";
#elif defined(__aarch64__) || defined(__arm64__)
    return "arm64-native";
#else
    return "unknown-native";
#endif
}

#endif /* Native assembly dispatcher */