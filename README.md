# Self‑Guard 🛡️

[![C](https://img.shields.io/badge/Language-C-blue)](https://www.iso.org/standard/74528.html) 
[![C++](https://img.shields.io/badge/Language-C++-lightgrey)](https://isocpp.org/) 
[![License: MIT](https://img.shields.io/badge/License-MIT-green)](LICENSE) 
[![Build Status](https://img.shields.io/badge/Build-Passing-brightgreen)](https://github.com/) 
[![Email](https://img.shields.io/badge/Contact-mrwhite4939@gmail.com-red)](mailto:mrwhite4939@gmail.com)

---

## 🔥 Overview

**Self‑Guard** is a production-grade **runtime integrity protection library** designed to detect, prevent, and alert on attempts to tamper with applications during execution. Its three-layer architecture ensures a comprehensive approach to runtime security:

1. **C Public API (`self_guard.h`)** – Clean interface for initialization, integrity checks, and shutdown.  
2. **C++ Security Core (`guard_core.cpp`)** – Thread-safe orchestration and state management.  
3. **Assembly Engine (`asm_guard.S`)** – Hardware-level low-latency detection (timing, debug registers, code integrity).  

Self‑Guard is ideal for applications requiring high-assurance runtime integrity like DRM, Anti-Cheat systems, EDR, and critical infrastructure.

---

## 🛠️ Features

- **Memory Integrity Checks:** Detects inline code modifications and memory tampering.  
- **Debugger Detection:** Hardware breakpoint detection (DR0–DR3, DR7) and anti-debugging measures.  
- **Timing Attack Detection:** Monitors instruction timing to detect single-stepping or instrumentation.  
- **Execution Flow Protection:** Monitors for anomalies in program execution paths.  
- **Thread-Safe State Management:** Uses mutexes and atomic operations to prevent race conditions.  
- **Fail-Secure Defaults:** Uninitialized state or errors default to `SG_COMPROMISED`.  

---

## ⚙️ Security States

| State             | Meaning |
|------------------|---------|
| `SG_SAFE`         | All integrity checks passed |
| `SG_WARNING`      | Suspicious activity detected |
| `SG_COMPROMISED`  | Active tampering detected |

---

## 📚 Use Cases

- **Anti-Cheat Systems:** Detect game hackers using debuggers or memory editors.  
- **Digital Rights Management (DRM):** Prevent unauthorized license bypass or tampering.  
- **Endpoint Detection & Response (EDR):** Monitor for malicious process injections.  
- **Critical Infrastructure:** SCADA/ICS runtime integrity monitoring.  

---

## 🔧 Building Instructions

### Prerequisites

- GCC 7.0+ / G++ 7.0+  
- GNU Assembler (`as`)  
- Linux x86_64 (or compatible)  

### Compilation Steps

```bash
# Compile assembly layer
as --64 -o asm_guard.o src/asm_guard.S

# Compile C++ security core
g++ -c -std=c++17 -O2 -Wall -Wextra -fPIC -fstack-protector-strong \
    -D_FORTIFY_SOURCE=2 -o guard_core.o src/guard_core.cpp

# Compile C API layer
gcc -c -std=c11 -O2 -Wall -Wextra -fPIC -fstack-protector-strong \
    -D_FORTIFY_SOURCE=2 -Iinclude -o self_guard.o src/self_guard.c

# Create static library
ar rcs libself_guard.a self_guard.o guard_core.o asm_guard.o

# Compile example/demo program
gcc -std=c11 -O2 -Wall -Wextra -Iinclude -o demo examples/main.c \
    -L. -lself_guard -lstdc++ -pthread
```
### Run demo
```Bash
./demo
```

One-Line Build:
```Bash
as --64 -o asm_guard.o src/asm_guard.S && \
g++ -c -std=c++17 -O2 -Wall -Wextra -fPIC -fstack-protector-strong \
-D_FORTIFY_SOURCE=2 -o guard_core.o src/guard_core.cpp && \
gcc -c -std=c11 -O2 -Wall -Wextra -fPIC -fstack-protector-strong \
-D_FORTIFY_SOURCE=2 -Iinclude -o self_guard.o src/self_guard.c && \
ar rcs libself_guard.a self_guard.o guard_core.o asm_guard.o && \
gcc -std=c11 -O2 -Wall -Wextra -Iinclude -o demo examples/main.c \
-L. -lself_guard -lstdc++ -pthread
```


---

### 📖 Example Usage
```C
#include "self_guard.h"

int main(void) {
    if (sg_init() != SG_OK) return -1;

    sg_snapshot();

    while (1) {
        sg_check_integrity(SG_CHECK_ALL);

        if (sg_get_security_state() == SG_COMPROMISED) {
            abort(); // Security breach detected
        }
    }

    sg_shutdown();
    return 0;
}
```

---

### 🔬 Security Guarantees

Memory Safety: No undefined behavior, bounds-checked arrays, RAII cleanup.

No Dangerous Functions: Banned: strcpy, sprintf, gets.

Thread-Safe: Mutex-protected state and atomic operations.

Fail-Secure: Defaults to SG_COMPROMISED on error or uninitialized state.

Compiler Hardening: -fstack-protector-strong, -D_FORTIFY_SOURCE=2, -fPIC, -O2.



---

### ⚠️ Limitations

Cannot detect kernel-mode rootkits.

Some checks may be bypassed in virtual machines.

Continuous monitoring adds minor overhead (~2–5%).

TOCTTOU: time-of-check vs time-of-use gaps are possible.



---

### 📜 License

MIT License – See [LICENSE] file.


---

### 📬 Contact

Email: mrwhite4939@gmail.com
