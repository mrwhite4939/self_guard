# Self-Guard Portable Makefile
# Supports: Linux (x86_64, ARM64), macOS (Intel, Apple Silicon), Android (Termux)

# Detect architecture
ARCH := $(shell uname -m)
OS := $(shell uname -s)

# Compiler settings
CC := gcc
CXX := g++
AS := as
AR := ar

CFLAGS := -std=c11 -O2 -Wall -Wextra -Werror -fPIC -fstack-protector-strong -D_FORTIFY_SOURCE=2 -Iinclude
CXXFLAGS := -std=c++17 -O2 -Wall -Wextra -Werror -fPIC -fstack-protector-strong -D_FORTIFY_SOURCE=2 -Iinclude
ASFLAGS :=
LDFLAGS := -lpthread

# Source files
COMMON_SRC := src/self_guard.c src/guard_core.cpp

# Architecture-specific assembly
ifeq ($(ARCH),x86_64)
    ASM_SRC := src/asm/asm_x86_64.S src/asm_dispatch.c
    ASFLAGS += --64
    $(info Building for x86_64 with native assembly)
else ifeq ($(ARCH),aarch64)
    ASM_SRC := src/asm/asm_arm64.S src/asm_dispatch.c
    $(info Building for ARM64 with native assembly)
else ifeq ($(ARCH),arm64)
    ASM_SRC := src/asm/asm_arm64.S src/asm_dispatch.c
    $(info Building for ARM64 (Apple Silicon) with native assembly)
else
    ASM_SRC := src/asm/asm_stub.c
    $(warning Using C fallback for $(ARCH))
endif

# Object files
OBJS := self_guard.o guard_core.o

# Compile assembly or stub
ifeq ($(suffix $(firstword $(ASM_SRC))),.S)
    OBJS += asm_native.o asm_dispatch.o
else
    OBJS += asm_stub.o
endif

# Targets
.PHONY: all clean test

all: libself_guard.a demo

libself_guard.a: $(OBJS)
	$(AR) rcs $@ $^
	@echo "✓ Library built successfully: $@"

self_guard.o: src/self_guard.c include/self_guard.h
	$(CC) $(CFLAGS) -c $< -o $@

guard_core.o: src/guard_core.cpp include/self_guard.h include/self_guard_asm.h
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Assembly compilation (x86_64 or ARM64)
asm_native.o: $(filter %.S,$(ASM_SRC))
	$(AS) $(ASFLAGS) -o $@ $<

asm_dispatch.o: src/asm_dispatch.c include/self_guard_asm.h
	$(CC) $(CFLAGS) -c $< -o $@

# C fallback compilation
asm_stub.o: src/asm/asm_stub.c include/self_guard_asm.h
	$(CC) $(CFLAGS) -c $< -o $@

demo: examples/main.c libself_guard.a
	$(CC) $(CFLAGS) -o $@ $< -L. -lself_guard -lstdc++ $(LDFLAGS)
	@echo "✓ Demo built successfully: $@"

test: demo
	@echo "Running Self-Guard demo..."
	./demo

clean:
	rm -f *.o libself_guard.a demo
	rm -f src/asm/*.o
	@echo "✓ Cleaned build artifacts"

# Verification target
verify:
	@echo "Compiler: $(CC) / $(CXX)"
	@echo "Architecture: $(ARCH)"
	@echo "OS: $(OS)"
	@echo "Assembly sources: $(ASM_SRC)"
	@echo ""
	@echo "Testing compilation with strict warnings..."
	@$(MAKE) clean
	@$(MAKE) all CFLAGS="$(CFLAGS) -Werror" CXXFLAGS="$(CXXFLAGS) -Werror"
	@echo ""
	@echo "✓ All files compile cleanly with -Werror"

help:
	@echo "Self-Guard Makefile"
	@echo "Detected: $(OS) / $(ARCH)"
	@echo ""
	@echo "Targets:"
	@echo "  all    - Build library and demo"
	@echo "  test   - Build and run demo"
	@echo "  verify - Verify clean compilation with -Werror"
	@echo "  clean  - Remove build artifacts"
	@echo ""
	@echo "Architecture support:"
	@echo "  x86_64  - Native assembly (RDTSC, debug registers)"
	@echo "  ARM64   - Native assembly (CNTVCT_EL0)"
	@echo "  Other   - C fallback (clock_gettime)"