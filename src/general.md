# General Notes — Anti-Cheat Research

Quick reference for concepts learned while studying UltimateAntiCheat
and related resources.

---

## Anti-Cheat Configuration Flags

| Flag | Purpose |
|---|---|
| Networking | Report detections to remote server |
| SecureBoot | Enforce UEFI Secure Boot |
| DSE | Driver Signature Enforcement — only signed drivers allowed |
| NoKDBG | Block kernel debugger presence |
| AntiDebugging | Detect attached debuggers |
| IntegrityCheck | IAT validation, hooks, checksums |
| ThreadIntegrity | Detect unknown threads running inside the process |
| Hypervisor | Detect VM or hypervisor environment |
| RunAsAdmin | Require elevated privileges to run |
| UsingDriver | Enable kernel mode (Ring 0) component |

---

## Build Modes

| | Debug | Release |
|---|---|---|
| Strings | Plain text in binary | Encrypted at compile time |
| Allowed parent processes | VS, explorer, bash, zsh... | explorer, launcher only |
| Protections | More lenient for testing | Full enforcement |

---

## Key Concepts (quick reference)

**IAT** — Import Address Table. Stores addresses of functions imported from DLLs.
Hook = replace a function address with malicious code.
Detection = verify each address points inside the legitimate DLL's memory range.

**TLS Callback** — runs BEFORE main(). Used for early-stage anti-debug checks
before a debugger has a chance to pause execution.

**VEH** — Vectored Exception Handler. Intercepts exceptions before the default
Windows handler. Used to catch ACCESS_VIOLATION on protected memory regions
and detect hardware breakpoints via debug registers (DR0-DR7).

**DSE** — Driver Signature Enforcement. Windows only loads digitally signed drivers.
BYOVD = Bring Your Own Vulnerable Driver —> loads a legitimate signed driver with
a vulnerability to disable DSE, then loads an unsigned cheat driver.

**KDBG** — Kernel Debugger structure. Present when the system is being debugged
at kernel level (WinDbg kernel mode). Strong indicator of an analysis environment.

**Pragma / Linker directives**
- `#pragma comment(linker, "/ALIGN:0x10000")` — aligns each PE section to its own
  64KB memory region, enabling section remapping for anti-tamper.
- `#pragma comment(linker, "/INCLUDE:_tls_used")` — forces linker to include TLS
  structures so Windows recognizes and executes TLS callbacks.

**String obfuscation**
- Debug builds: strings stored as plain text. Visible in hex editor.
- Release builds: strings encrypted at compile time via `make_encrypted()`,
  decrypted at runtime only when needed. The author says the best option in
  release would be to use LLVM.

**Ring 0 / Ring 3**
- Ring 3 = usermode. Where normal applications and basic anti-cheat run.
- Ring 0 = kernel mode. Same privilege level as the OS.
  Kernel-level anti-cheat (EAC, BattlEye, Vanguard) operates here.

---

## Reference Repos

- https://github.com/AlSch092/UltimateAntiCheat
- https://github.com/AlSch092/DetectionEngine
