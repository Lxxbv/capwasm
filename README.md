# CapWasm

**基于能力安全与 Extism/WASI 双协议栈兼容的纯 MoonBit WebAssembly 插件沙箱运行时**  
*(Capability-Based WebAssembly Plugin Sandbox & Extism/WASI Host Kernel in Pure MoonBit)*

[![MoonBit](https://img.shields.io/badge/Language-MoonBit-purple)](https://www.moonbitlang.com/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Code Size](https://img.shields.io/badge/Pure%20MoonBit%20LOC-10%2C643%20Lines-success)]()
[![Tests](https://img.shields.io/badge/Tests-50%20Passed%20(100%25)-brightgreen)]()

---

## 一、 项目简介与核心定位 (Overview & Positioning)

**CapWasm** (`Lxxbv/capwasm`) 是一个 100% 纯 MoonBit 编写、零外部 C/Rust FFI 依赖的 **能力安全（Capability-based Security）WebAssembly 插件沙箱与 Extism/WASI 宿主内核**。

它并非单纯用于执行数值指令的底层 Wasm 规范参考解释器，而是定位于 **“MoonBit 原生宿主应用的安全插件接入底座”**，专为 **AI Agent (MCP) 工具插件、多租户 Serverless 规则脚本、Markdown/文档渲染扩展** 等需要动态加载不可信第三方 `.wasm` 插件的场景设计：
1. **默认零信任与防越权逃逸**：通过能力策略（`CapabilityPolicy`）与虚拟目录挂载（`ExtismPathMount`），拦截 `../` 路径穿越、未授权文件读写、未授权环境变量读取与非法外联域名请求；
2. **多维资源配额熔断（防 DoS）**：同时对 **单步指令 Gas 消耗**、**`memory.grow` 线性内存扩页**、**Extism 持久化变量容量 (`max_var_bytes`)** 与 **HTTP 响应体积 (`max_http_response_bytes`)** 实施硬上限拦截；
3. **真实 Extism + WASI Preview1 插件无缝接入**：原生实现 **`ExtismManifest` JSON 解析与 FNV-1a 指纹校验**、**19 个 `extism:host/env` 宿主函数** 与 **19 个 `wasi_snapshot_preview1` 系统调用**，使标准 `wasm32-wasi` 编译的 Extism 插件无需任何外部 FFI 即可在纯 MoonBit 宿主中安全运行。

---

## 二、 与对标的类似生态库定位及功能对比 (Ecosystem Comparison)

下表将 **CapWasm** 与 MoonBit 社区现有的 Wasm/沙箱类项目（`moonbitlang/wasm5`、`mizchi/wasmx`、`tuya-me/aegisrun`、`mizchi/wacon`）以及业界主流插件框架 `Extism (Rust/C SDK)` 进行定位与功能对比：

| 对比维度 | `moonbitlang/wasm5` | `mizchi/wasmx` | `tuya-me/aegisrun` | `mizchi/wacon` | `Extism (Rust/C SDK)` | **CapWasm (本项目)** |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **核心定位** | Wasm 1.0 规范教学/参考解释器 | 通用 Wasm 虚拟机与 CLI 运行器 | AI Agent / MCP 工具安全执行器 | RISC-V 容器模拟器环境 | 跨语言通用 Wasm 插件宿主 SDK | **MoonBit 原生能力安全插件沙箱 + Extism/WASI 宿主内核** |
| **实现方式与外部依赖** | 纯 MoonBit | MoonBit | MoonBit | MoonBit | 依赖 Rust `wasmtime` + C `libextism` FFI | **100% 纯 MoonBit 自包含（零 C/Rust FFI 外部依赖）** |
| **Wasm 二进制解析、校验与编译** | 仅解析执行 | 仅解析执行 | 依赖外部或简化 | 面向 RISC-V ELF | 依赖 Wasmtime | **支持完整 11 节二进制解码 + 静态校验 + `pdk.mbt` 二进制编码器** |
| **指令级 Gas 计费与死循环熔断** | 不支持 | 基础限制 | 侧重调用超时控制 | 模拟器周期限制 | 依赖 Wasmtime Fuel | **分派环路内嵌单步 Gas 扣减 + `Trap::GasExhausted` 强熔断** |
| **多维内存与状态配额门控** | 仅模块自身 Limits | 仅模块自身 Limits | 部分支持 | 页表限制 | 宿主 `max_pages` / `max_var_bytes` | **四重门控：`memory.grow` 页上限、Extism `alloc`、`max_var_bytes`、`max_http_response_bytes`** |
| **细粒度能力安全策略 (`CapabilityPolicy`)** | 无 | 无 | 面向 Agent 工具 | 无 | 基础配置（无内置路径穿越审计账本） | **默认全拒绝白名单、`../` 路径穿越拦截、`*.domain` 通配符域名白名单、环境变量白名单** |
| **沙箱内存 VFS 与虚拟目录挂载** | 无 | 基础 WASI 透传 | 受限目录访问 | 容器镜像 Rootfs | 依赖 Wasmtime WASI Dir Mapping | **纯内存 `VirtualFileSystem` + `ExtismPathMount` (`ro:` 只读挂载映射) + 标准句柄防关闭** |
| **`wasi_snapshot_preview1` 覆盖度** | 无 | 基础 I/O | 部分 | 无（RISC-V syscall） | 依赖 Wasmtime WASI | **完整实现 19 个核心 WASI preview1 系统调用（含 `path_open`/`fd_read`/`clock`/`random`）** |
| **Extism 协议 (`extism:host/env` + Manifest)** | 不支持 | 不支持 | 不支持 | 不支持 | 官方参考实现 | **完整实现 `ExtismManifest` JSON 解析、FNV-1a 指纹校验与 19 个 `extism:host/env` 宿主函数** |
| **结构化安全审计账本 (`AuditRecord`)** | 无 | 无 | 基础日志 | 无 | 普通运行日志 | **每次文件/网络/时钟/环境变量鉴权均生成不可篡改的 `ALLOWED`/`DENIED` 审计记录** |

---

## 三、 现有底座之外的实质贡献详解 (Substantive Contributions Beyond Base VM)

CapWasm 共包含 **10,643 行纯 MoonBit 源码**（含 `.mbti` 接口文件共 **11,495 行**）。其中，底层受控 Wasm 1.0 执行底座为 **4,415 行**，而 **构建在底座之上的沙箱安全、WASI 虚拟化与 Extism 插件内核实质贡献代码达 4,540 行（另有 1,688 行测试与演示代码）**：

```
+---------------------------------------------------------------------------------------+
|                            MoonBit Host Application                                   |
|  ExtismManifest::from_json  |  PluginInstance::load_from_manifest  |  call_string     |
+---------------------------------------------------------------------------------------+
                                           |
                                           v
+=======================================================================================+
| LAYER 2: 现有底座之外的核心实质贡献 — 沙箱安全、WASI 与 Extism 插件内核 (4,540 行)      |
|                                                                                       |
|  +---------------------------------------+  +--------------------------------------+  |
|  | 1. Extism Manifest 与挂载引擎          |  | 2. Extism 宿主内核 (extism.mbt, 881行)|  |
|  |    (manifest.mbt, 562 行)             |  | - ExtismMemBlock Arena 内存块分配器  |  |
|  | - ExtismManifest JSON 解析器          |  | - 19 个 `extism:host/env` 宿主函数   |  |
|  | - 64-bit FNV-1a 二进制完整性指纹校验   |  | - Config 与 `max_var_bytes` 状态存储 |  |
|  | - `ro:` 只读虚拟目录挂载映射           |  | - 域名白名单门控 `http_request`      |  |
|  +---------------------------------------+  +--------------------------------------+  |
|  +---------------------------------------+  +--------------------------------------+  |
|  | 3. WASI Preview1 系统调用层           |  | 4. 内存 VFS、能力守卫与 PDK 编译器    |  |
|  |    (wasi.mbt, 790 行)                 |  |    (vfs/capwasm/pdk/plugin, 2,307行) |  |
|  | - 19 个 `wasi_snapshot_preview1` 函数 |  | - 纯内存 VFS + POSIX 路径规范化      |  |
|  | - `path_open`/`fd_read`/`fd_write`    |  | - `../` 路径穿越拦截 + `*.domain` 匹配|  |
|  | - 受控虚拟时钟 `clock_time_get` & PRNG |  | - `WasmModule::encode_to_bytes` 编译器|  |
|  +---------------------------------------+  +--------------------------------------+  |
+=======================================================================================+
                                           |
                                           v
+=======================================================================================+
| LAYER 1: 内嵌安全钩子的受控 Wasm 1.0 执行底座 (4,415 行)                               |
|  - 指令分派环路内嵌单步 Gas 扣减 (`consume_gas` -> `Trap::GasExhausted`)               |
|  - `Instruction::MemoryGrow` 联动 `sec_guard.check_memory_grow` 硬上限拦截            |
|  - `TableInstance` + `Instruction::CallIndirect` 动态函数表与运行时 `FuncType` 签名校验|
|  - 完整 `i32`/`i64` 算术/访存指令集、结构化 `block`/`loop`/`if`/`else`/`br_table`      |
+=======================================================================================+
```

---

## 四、 Extism 兼容机制与真实插件接入证明 (`extism:host/env` + `wasi_snapshot_preview1`)

CapWasm 通过四阶段全链路机制接入标准 Extism 插件：
1. **Manifest 解析与二进制哈希校验 ([`manifest.mbt`](manifest.mbt))**：通过 `ExtismManifest::from_json` 解析插件配置、内存/变量配额、域名白名单与虚拟挂载表（如 `"ro:/host/tenant_a/docs": "/docs"`），并在加载前校验 `.wasm` 镜像的 64 位 FNV-1a 指纹。
2. **42 个宿主导入符号全量预链接 ([`plugin.mbt`](plugin.mbt))**：实例化前自动向 `Linker` 注册 **19 个 `extism:host/env`（含 `env` 别名）函数**、**19 个 `wasi_snapshot_preview1` 系统调用** 与 **4 个 `capwasm` 原生函数**。
3. **Arena 内存块分配与双 ABI 自动调度 ([`extism.mbt`](extism.mbt))**：`ExtismKernel` 在插件线性内存偏移 `8192` 处维护 8 字节对齐的 Arena 分配器（支持 `free` 块复用与受控扩页），并通过 `output_set(offset, len)` 回收插件输出，同时兼容零参 `() -> i32` 与切片 `(i32, i32) -> i32` 两种 ABI。
4. **WASI 虚拟挂载与能力门控协同 ([`wasi.mbt`](wasi.mbt))**：插件内调用 WASI `path_open("/docs/hello.txt")` 时，自动经由 `resolve_mounted_path` 映射至宿主 VFS 的 `/host/tenant_a/docs/hello.txt`，并通过 `PluginSecurityGuard` 记录结构化审计日志 `AuditRecord`。

---

## 五、 快速开始与一键验证 (Quick Start)

### 1. 运行全部 50 项单元与端到端集成测试
```bash
moon test
```
```text
Total tests: 50, passed: 50, failed: 0.
```

### 2. 运行 7 大场景交互式沙箱与 Extism Manifest 演示程序
```bash
moon run cmd/main
```
```text
==================================================================
  CapWasm: Capability-Based WebAssembly Plugin Sandbox Host      
  MoonBit Hackathon 2026 - Production System Demonstration        
==================================================================
...
[Scenario 6] Executing Compiled Extism Binary Plugin ('extism-upper.wasm')...
  [PASS] Extism plugin executed via extism:host/env ABI: 'capwasm' -> 'CAPWASM' (gas=307)

[Scenario 7] Loading Plugin via ExtismManifest JSON with FNV-1a Hash & Path Mounts...
  [PASS] Manifest-loaded plugin verified (FNV-1a=a16a6ff014273bbf) & executed: 'MANIFEST'
```

---

## 六、 开源协议 (License)

本项目基于 [Apache-2.0 License](LICENSE) 开源。详细项目申报书请参阅 [`PROJECT_PROPOSAL.md`](PROJECT_PROPOSAL.md)。
