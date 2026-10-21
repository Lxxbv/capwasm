# CapWasm 🛡️

> **Capability-Based WebAssembly Plugin Sandbox Host for MoonBit**  
> 为 MoonBit 打造的安全、轻量级通用 WASM 插件沙箱框架。

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![MoonBit](https://img.shields.io/badge/Language-MoonBit-purple.svg)](https://www.moonbitlang.com)
[![Build Status](https://img.shields.io/badge/tests-6%20passed-brightgreen.svg)]()

---

## 🌟 核心特性 (Features)

- 🔒 **基于能力模型的安全沙箱 (Capability-Based Security)**: 细粒度控制插件的文件读写、网络域名白名单、系统时钟等特权操作。
- 🚫 **零信任防御与路径穿越阻断 (Path Traversal Protection)**: 内建智能路径检测，主动抵御 `../` 目录逃逸与越权窥探。
- ⚡ **抗死循环与配额限制 (Resource Quota & Gas Limit)**: 动态监测执行步数与内存页数，自动熔断恶意死循环或资源耗竭型插件。
- 📝 **全链路安全审计日志 (Structured Audit Trail)**: 完整记录每一次宿主系统调用交互（目标、判定结果、原因）。
- 🔌 **轻量级 Host-Plugin ABI (Extism-Style Protocol)**: 极简的线性内存切片传递设计，无需繁重复杂的 Component Model 运行时即可完成高频高效数据交换。

---

## 🏗️ 架构分层 (Architecture)

```
+-----------------------------------------------------------+
|                   Host Application                        |
+-----------------------------------------------------------+
|                     CapWasm Host Engine                   |
+-----------------------------+-----------------------------+
|    Capability Security      |     Host-Plugin ABI         |
|  - Path Traversal Guard     |  - MemorySlice Bridge       |
|  - Network Allowlist        |  - Zero-Copy String Bridge  |
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

## 🚀 快速上手 (Quick Start)

### 1. 运行测试套件
```bash
moon test
```
输出：
```text
Total tests: 6, passed: 6, failed: 0.
```

### 2. 运行交互式沙箱演示
```bash
moon run cmd/main
```

控制台将模拟执行三个典型插件：
1. **正常插件 (`doc-renderer.wasm`)**：合规路径读写，顺利通过并完成任务。
2. **恶意插件 (`untrusted-agent.wasm`)**：尝试跨目录读取敏感信息及恶意网络外联，被宿主安全拦截并记录审计日志。
3. **恶意死循环插件 (`crypto-miner.wasm`)**：尝试无限循环耗尽算力，触发步数配额熔断。

---

## 💻 核心 API 示例 (Core API Usage)

### 定义权限策略 (Capability Policy)
```moonbit
let policy = @capwasm.CapabilityPolicyBuilder::new()
  .allow_read_path("./workspace/docs/")
  .allow_write_path("./workspace/output/")
  .allow_network_host("api.myservice.com")
  .build()
```

### 创建并执行受控插件
```moonbit
let sec_guard = @capwasm.PluginSecurityGuard::new("plugin-1", policy)

// 宿主导入函数在执行前调用安全校验：
match sec_guard.check_fs_read("./workspace/docs/sample.md") {
  Ok(_) => println("Access granted")
  Err(e) => println("Access denied: \{e}")
}
```

---

## 📊 生态位与差异化对比

| 特性 | CapWasm | moonbitlang/wasm5 | tuya-me/aegisrun | mizchi/wacon |
| :--- | :--- | :--- | :--- | :--- |
| **层级定位** | 应用级插件宿主框架 | 字节码解释引擎 | AI Agent MCP 专用运行时 | RISC-V 容器运行时 |
| **Capability 策略模型** | ✅ 细粒度白名单 | ❌ 仅底层导入接口 | ⚠️ 绑死 MCP 工具模型 | ❌ |
| **路径逃逸防御** | ✅ 内建支持 | ❌ | ⚠️ 有限支持 | ❌ |
| **通用应用扩展能力** | ✅ 任意 MoonBit 软件 | ⚠️ 需自行开发 | ❌ 专为 Agent 设计 | ❌ |

---

## 📄 比赛申报与立项报告

完整项目立项书详见：[PROJECT_PROPOSAL.md](PROJECT_PROPOSAL.md)

## 📜 许可证 (License)

本项目采用 [Apache-2.0](LICENSE) 开源许可证。
