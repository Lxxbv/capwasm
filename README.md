# CapWasm 🛡️

**Capability-Based WebAssembly Plugin Sandbox & Extism Host Kernel in Pure MoonBit**  
*(基于能力安全与 Extism 协议兼容的纯 MoonBit WebAssembly 插件沙箱运行时)*

[![MoonBit](https://img.shields.io/badge/Language-MoonBit-purple)](https://www.moonbitlang.com/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Code Size](https://img.shields.io/badge/MoonBit%20LOC-8%2C041%20Lines-success)]()
[![Tests](https://img.shields.io/badge/Tests-47%20Passed-brightgreen)]()

---

## 📖 Overview (项目简介)

**CapWasm** (`Lxxbv/capwasm`) is a zero-dependency, pure-MoonBit **Capability-Based WebAssembly Plugin Sandbox and Extism-Compatible Host Runtime**. It is designed for MoonBit host applications that need to safely load and execute untrusted third-party `.wasm` plugins (such as AI Agent MCP tool plugins, Markdown/template processors, and multi-tenant serverless user scripts).

Unlike bare-metal WebAssembly specification interpreters that only focus on instruction execution, **CapWasm** embeds fine-grained **Object-Capability security guards**, **instruction-level Gas metering**, **memory page quota enforcement**, a **path-traversal-proof in-memory Virtual File System (VFS)**, and a complete **Extism Host Kernel (`extism:host/env`)** directly into a self-contained Wasm 1.0 runtime.

---

## 🎯 Positioning & Ecosystem Comparison (项目定位与对标生态库对比)

To clarify how **CapWasm** differs from existing WebAssembly and sandbox libraries in the MoonBit ecosystem and the broader Wasm industry, the table below compares their positioning and feature sets:

| Dimension | `moonbitlang/wasm5` | `mizchi/wasmx` | `tuya-me/aegisrun` | `mizchi/wacon` | `Extism (Rust/C SDK)` | **CapWasm (This Project)** |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Primary Positioning** | Wasm 1.0 Spec Reference Interpreter | General-purpose Wasm VM & CLI | AI Agent / MCP Tool Runner | RISC-V Container Emulator | Cross-language Wasm Plugin SDK | **Capability-Secured Wasm Plugin Sandbox & Extism Host Kernel** |
| **Implementation & Dependencies** | Pure MoonBit | MoonBit | MoonBit | MoonBit | Rust (`wasmtime`) + C Shared Library FFI | **100% Pure MoonBit (Zero external C/Rust FFI)** |
| **Wasm 1.0 Binary Parser & Validator** | Yes | Yes | Partial / External | RISC-V ELF | Via Wasmtime | **Yes (Full LEB128, 11 Sections, Structural Validator)** |
| **Instruction-Level Gas Metering** | No | Basic | Timeout-based | Cycle limit | Via Wasmtime Fuel | **Embedded Per-Instruction Gas Accounting & `GasExhausted` Trap** |
| **Memory Growth Quota (`memory.grow` Guard)** | Module Limits only | Module Limits only | Partial | Page Table | Host Limits | **Dual Enforcement on Wasm `memory.grow` & Extism `alloc`** |
| **Fine-Grained Capability Policy** | None | None | Agent-oriented | None | Basic Config (No Path Traversal Audit) | **Deny-by-Default Path Prefix Allowlist, `../` Detection, Domain Allowlist** |
| **Sandboxed In-Memory VFS & WASI FD Table** | None | Basic WASI Pass-through | Scoped Directory | Container Rootfs | Wasmtime WASI Dir Mapping | **Isolated In-Memory VFS + POSIX Normalization + Protected `stdin/out/err`** |
| **Extism Host ABI (`extism:host/env`)** | No | No | No | No | Official Reference | **Full `extism:host/env` (19 Host Functions + Kernel Block Allocator)** |
| **Plugin `Config` & Persistent `Var` Store** | None | None | None | None | Yes | **Native Support (`config_get` / `var_get` / `var_set`)** |
| **Structured Security Audit Ledger** | None | None | Basic Logs | None | Standard Logs | **Immutable Per-Action `AuditRecord` (`ALLOWED` / `DENIED` + Reason)** |

---

## 🏗️ Architecture & Substantive Contributions (架构分层与核心实质贡献)

CapWasm comprises **8,041 lines of pure MoonBit source code** (8,806 lines including generated `.mbti` interfaces) organized into two distinct architectural layers:

```
+-----------------------------------------------------------------------------------+
|                        Host Application (MoonBit)                                 |
|   CapabilityPolicyBuilder  |  PluginInstance::load  |  call_extism / call_string  |
+-----------------------------------------------------------------------------------+
                                        |
                                        v
+===================================================================================+
| LAYER 2: CapWasm Substantive Security & Plugin Kernel Contributions (2,444 LOC)   |
|                                                                                   |
|  +------------------------------------+  +-------------------------------------+  |
|  | Capability Security Guard          |  | Extism Host Kernel (extism.mbt)     |  |
|  | (capwasm.mbt)                      |  | - ExtismMemBlock Arena Allocator    |  |
|  | - Deny-by-default allowlists       |  | - 19 `extism:host/env` Host Imports |  |
|  | - `../` Path Traversal Blocker     |  | - Input/Output/Error Channels       |  |
|  | - Outbound Domain Allowlist        |  | - Plugin `Config` & Persistent `Var`|  |
|  | - Structured AuditRecord Ledger    |  | - Capability-Gated `http_request`   |  |
|  +------------------------------------+  +-------------------------------------+  |
|  +------------------------------------+  +-------------------------------------+  |
|  | In-Memory VFS & WASI Isolation     |  | Plugin Lifecycle & Dual ABI Bridge  |  |
|  | (vfs.mbt)                          |  | (plugin.mbt & host.mbt)             |  |
|  | - Zero Host-Disk Exposure          |  | - Pre-instantiation Symbol Linking  |  |
|  | - POSIX Path Canonicalization      |  | - 0-arg Extism PDK ABI `() -> i32`  |  |
|  | - Protected WASI FD Table (0,1,2)  |  | - 2-arg Slice ABI `(i32,i32) -> i32`|  |
|  +------------------------------------+  +-------------------------------------+  |
+===================================================================================+
                                        |
                                        v
+===================================================================================+
| LAYER 1: Self-Contained Hooked Wasm 1.0 Execution Engine (4,326 LOC)              |
|  - Binary Decoder & LEB128 Reader (`parser.mbt`, `leb128.mbt`, `validator.mbt`)   |
|  - Hooked Stack Bytecode Interpreter (`interpreter.mbt`, `stack.mbt`, `opcode.mbt`)|
|    * Per-instruction Gas consumption hook (`consume_gas` -> `Trap::GasExhausted`) |
|    * Security-guarded `Instruction::MemoryGrow` (`sec_guard.check_memory_grow`)   |
|  - 64 KiB Paged Linear Memory with Bounds Checking (`memory.mbt`)                 |
+===================================================================================+
```

### Why a Self-Contained Wasm Execution Engine?
External Wasm interpreters execute guest code as a black box, making it difficult to intercept individual instructions or memory growth requests without invasive forks. CapWasm's Layer 1 engine embeds security hooks directly into:
1. **The bytecode dispatch loop (`interpreter.mbt`)**: Every Wasm instruction and host call deducts Gas against `CapabilityPolicy.quota.max_execution_steps`, immediately trapping runaway loops (`Trap::GasExhausted`).
2. **The `memory.grow` instruction (`interpreter.mbt`)**: Before growing linear memory, the VM consults `host_context.sec_guard.check_memory_grow(target_pages)`, enforcing hard host memory ceilings even if the guest `.wasm` module declares a higher maximum in its binary header.

---

## 🔌 Extism Compatibility Mechanism (`extism:host/env`)

CapWasm implements the complete **Extism Host ABI (`extism:host/env` and alias `env`)** in [`extism.mbt`](extism.mbt) and [`plugin.mbt`](plugin.mbt), enabling standard Extism guest plugins (`() -> i32`) to run in pure MoonBit:

1. **Kernel Memory Block Allocator (`ExtismKernel::alloc` / `free` / `length` / `length_unsafe`)**:
   - Manages guest heap allocations starting at offset `8192` (`8 KiB`) using an 8-byte aligned bump allocator and a block descriptor table (`Array[ExtismMemBlock]`).
   - Automatically reuses freed blocks (`active == false`) of sufficient capacity and grows linear memory pages on demand while enforcing `PluginSecurityGuard::check_memory_grow`.
2. **Host-Guest I/O Marshaling (`input_length`, `input_load_u8`, `input_load_u64`, `load_u8`, `load_u64`, `store_u8`, `store_u64`, `output_set`, `error_set`)**:
   - When the host invokes `plugin.call_extism("run", input_bytes)` or `plugin.call_string("run", "capwasm")`, the kernel loads `input_bytes` into the input channel, invokes the exported 0-argument Wasm function, and reads back the resulting slice recorded by `output_set(offset, length)`.
3. **Per-Plugin Config & Persistent Variable Store (`config_get`, `var_get`, `var_set`)**:
   - Allows the host to inject configuration parameters (`plugin.set_extism_config(k, v)`) and stateful variables (`plugin.set_extism_var(k, bytes)`), which the guest reads and mutates via kernel memory handles.
4. **Capability-Gated Extism HTTP & Logging (`http_request`, `http_status_code`, `log_info`, `log_debug`, `log_warn`, `log_error`)**:
   - When a plugin calls `extism:host/env::http_request(req_off, body_off)`, CapWasm parses the target hostname from the request block and validates it against `sec_guard.check_network(host)`:
     - **Whitelisted Host**: Sets `http_status_code = 200`, allocates a response block in linear memory, and returns its `i64` handle.
     - **Unauthorized Host**: Sets `http_status_code = 403`, records a `DENIED` `AuditRecord` in the security ledger, and returns `0L`.

---

## 🚀 Quick Start (快速开始)

### 1. Run the Interactive Sandbox & Extism Plugin Demo
```bash
moon run cmd/main
```

**Expected Output:**
```text
==================================================================
  CapWasm: Capability-Based WebAssembly Plugin Sandbox Host      
  MoonBit Hackathon 2026 - Production System Demonstration        
==================================================================

[Scenario 1] Running Benign Plugin ('doc-renderer.wasm')...
  -> Plugin requests FS read on '/workspace/docs/guide.md'
  [PASS] Read permitted (bytes=20).
  -> Plugin requests FS write on '/workspace/output/result.html'
  [PASS] Write permitted under capability allowlist.

[Scenario 2] Running Malicious Plugin ('untrusted-agent.wasm')...
  -> Plugin attempts path traversal: '/workspace/docs/../../etc/shadow'
  [SECURITY BLOCKED] PathTraversalAttempt: /workspace/docs/../../etc/shadow

[Scenario 3] Running Network Escape Attempt...
  -> Plugin attempts unauthorized outbound connection: 'evil-c2.darknet'
  [SECURITY BLOCKED] PermissionDenied: Network forbidden: evil-c2.darknet
  -> Plugin attempts authorized outbound connection: 'api.github.com' (denied: not in evil policy)
  [SECURITY BLOCKED] PermissionDenied: Network forbidden: api.github.com

[Scenario 4] Running Runaway/Infinite Loop Plugin ('crypto-miner.wasm')...
  -> Plugin executing instruction burst (60,000 steps)...
  -> Plugin attempting runaway execution (+50,000 steps)...
  [RESOURCE QUOTA EXCEEDED] OutOfQuota: Instruction limit exceeded

[Scenario 5] Testing Sandboxed WASI Standard Handle Isolation...
  -> Captured guest stdout: '[Plugin Output] Hello Sandbox'
  -> Verifying guest cannot close standard stdout handle (fd 1)...
  [PASS] Standard handle protected against guest closure (errno=2).

[Scenario 6] Executing Compiled Extism Binary Plugin ('extism-upper.wasm')...
  [PASS] Extism plugin executed via extism:host/env ABI: 'capwasm' -> 'CAPWASM' (gas=307)

==================================================================
  Host Security Audit Summary
==================================================================
  - [untrusted-agent] target=/workspace/docs/../../etc/shadow status=DENIED reason=Path traversal attempt detected
  - [untrusted-agent] target=evil-c2.darknet status=DENIED reason=Host not in network allowlist
  - [untrusted-agent] target=api.github.com status=DENIED reason=Host not in network allowlist
==================================================================
  Demonstration finished successfully. All security bounds held.
==================================================================
```

### 2. Run the Full Test Suite (47 Tests)
```bash
moon test
```
```text
Total tests: 47, passed: 47, failed: 0.
```

---

## 📄 License

Licensed under the [Apache-2.0 License](LICENSE).
