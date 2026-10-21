# CapWasm

Capability-Based WebAssembly Plugin Sandbox Host for MoonBit.

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![MoonBit](https://img.shields.io/badge/language-MoonBit-purple.svg)](https://www.moonbitlang.com)
[![Build Status](https://img.shields.io/badge/tests-passed-brightgreen.svg)]()

---

## Overview

CapWasm is a lightweight, capability-based WebAssembly plugin host framework implemented in pure MoonBit. It is designed to provide secure, sandboxed execution environments for untrusted third-party `.wasm` modules embedded within MoonBit host applications.

Following the principle of least privilege, CapWasm isolates plugin instances and requires host applications to grant capabilities explicitly (e.g., path-scoped filesystem access, network host allowlists, clock access, and execution resource quotas). Any privileged interaction attempted without authorization is trapped, denied, and recorded in a structured audit log.

---

## Key Features

- **Capability-Based Authorization**: Fine-grained access control over filesystem, outbound network endpoints, environment variables, and system timers.
- **Path Traversal Mitigation**: Built-in canonicalization and relative segment checks (`..`) to prevent sandbox escape attempts.
- **Resource Quotas & Gas Limiting**: Instruction step counting and memory page ceilings to guard host processes against runaway execution and denial-of-service loops.
- **Structured Audit Logging**: Comprehensive trace collection capturing target operations, permission checks, timestamps, and violation rationales.
- **Extism-Style Host-Plugin ABI**: Linear memory slice descriptors (`MemorySlice`) for safe, efficient data marshaling without heavy runtime overhead.

---

## Architecture

```
+-----------------------------------------------------------+
|                   Host Application                        |
+-----------------------------------------------------------+
|                     CapWasm Host Engine                   |
+-----------------------------+-----------------------------+
|    Capability Security      |     Host-Plugin ABI         |
|  - Path Traversal Guard     |  - MemorySlice Bridge       |
|  - Network Allowlist        |  - Zero-Copy Data Exchange  |
|  - Step / Gas Quota Limiter |                             |
+-----------------------------+-----------------------------+
|             Host Functions & Audit Logger                 |
+-----------------------------------------------------------+
|       Underlying Wasm Runtime (wasm5 / wasmx)             |
+-----------------------------------------------------------+
|                 Sandboxed Plugin (.wasm)                  |
+-----------------------------------------------------------+
```

---

## Quick Start

### Prerequisites

- MoonBit toolchain (`moon`) installed.

### Run Unit Tests

Execute the automated test suite verifying capability boundaries, path traversal rejection, network isolation, and execution step limits:

```bash
moon test
```

Expected output:
```text
Total tests: 6, passed: 6, failed: 0.
```

### Run Interactive Demonstration

Run the reference host demonstration showcasing benign versus malicious plugin handling:

```bash
moon run cmd/main
```

The CLI program simulates three execution scenarios:
1. **Benign Plugin (`doc-renderer.wasm`)**: Successfully executes permitted filesystem read/write operations under configured path boundaries.
2. **Malicious Plugin (`untrusted-agent.wasm`)**: Attempts directory traversal and unauthorized external network connection; trapped and rejected by the security guard.
3. **Runaway Plugin (`crypto-miner.wasm`)**: Exceeds allotted step quota; safely terminated by the instruction monitor.

---

## API Usage

### Defining a Capability Policy

```moonbit
let policy = @capwasm.CapabilityPolicyBuilder::new()
  .allow_read_path("./workspace/docs/")
  .allow_write_path("./workspace/output/")
  .allow_network_host("api.trusted.com")
  .build()
```

### Creating a Security Guard and Enforcing Checks

```moonbit
let sec_guard = @capwasm.PluginSecurityGuard::new("plugin-1", policy)

// Host imports validate operations against the guard prior to execution:
match sec_guard.check_fs_read("./workspace/docs/guide.md") {
  Ok(_) => {
    // Proceed with safe host execution
  }
  Err(err) => {
    // Trap and log security violation
    println("Access denied: \{err}")
  }
}
```

---

## Ecosystem Comparison

| Feature | CapWasm | moonbitlang/wasm5 | tuya-me/aegisrun | mizchi/wacon |
| :--- | :--- | :--- | :--- | :--- |
| **Layer & Focus** | Application Plugin Host | Wasm Bytecode Interpreter | AI Agent MCP Tool Sandbox | RISC-V Container Runtime |
| **Capability Policy Model** | Yes (Fine-grained allowlists) | No (Low-level imports only) | Specialized for MCP tools | No |
| **Path Traversal Defense** | Built-in | No | Limited | No |
| **General Application Embeddability** | High (Any MoonBit app) | Library building block | Low (Tied to Agent workflows) | Specialized |

---

## Project Proposal

For complete project background, ecosystem gap analysis, and milestone roadmaps for the MoonBit Hackathon 2026, refer to [PROJECT_PROPOSAL.md](PROJECT_PROPOSAL.md).

---

## License

This project is licensed under the [Apache-2.0 License](LICENSE).
