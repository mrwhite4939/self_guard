CMakeLists.txt
cmake_minimum_required(VERSION 3.15)
project(self_guard C CXX ASM)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

# Enable assembly
enable_language(ASM)

# Security flags
if(UNIX)
    add_compile_options(
        -Wall -Wextra -Werror
        -fstack-protector-strong
        -D_FORTIFY_SOURCE=2
        -fPIC
    )
endif()

# Source files
set(COMMON_SOURCES
    src/self_guard.c
    src/guard_core.cpp
    src/asm_dispatch.c
)

# Architecture-specific assembly selection
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64")
    message(STATUS "Building for x86_64")
    list(APPEND COMMON_SOURCES src/asm/asm_x86_64.S)
    
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64|ARM64")
    message(STATUS "Building for ARM64")
    list(APPEND COMMON_SOURCES src/asm/asm_arm64.S)
    
else()
    message(STATUS "Using C fallback for ${CMAKE_SYSTEM_PROCESSOR}")
    list(APPEND COMMON_SOURCES src/asm/asm_stub.c)
endif()

# Library
add_library(self_guard STATIC ${COMMON_SOURCES})
target_include_directories(self_guard PUBLIC include)

# Example executable
add_executable(demo examples/main.c)
target_link_libraries(demo self_guard)

if(UNIX AND NOT APPLE)
    target_link_libraries(demo pthread)
endif()

# Platform-specific linking
if(APPLE)
    # macOS-specific settings
    target_compile_definitions(self_guard PRIVATE __APPLE__)
elseif(WIN32)
    # Windows-specific settings
    target_compile_definitions(self_guard PRIVATE _WIN32)
endif()

# Install targets
install(TARGETS self_guard ARCHIVE DESTINATION lib)
install(FILES include/self_guard_asm.h DESTINATION include)