# 2026 MoonBit 国产基础软件开源大赛 · 10月黑客松项目申报书

---

## 一、 基本信息

| 申报条目 | 详细内容 |
| :--- | :--- |
| **项目名称** | **CapWasm** — 基于能力安全（Capability-based Security）与 Extism 协议兼容的 MoonBit WebAssembly 插件沙箱 |
| **项目仓库** | `https://github.com/Lxxbv/capwasm` |
| **包名 (Module)** | `Lxxbv/capwasm` (`v0.1.0`) |
| **开源协议** | Apache-2.0 |
| **当前完成度** | **已完成核心工程闭环（纯 MoonBit 源码 8,041 行，含接口定义共 8,806 行，通过 47 项单元与端到端集成测试）** |

---

## 二、 项目定位与对标生态库对比说明（回应初审反馈 1）

### 2.1 项目核心定位
**CapWasm** 并非单纯重复造轮子的通用 WebAssembly 解释器，而是定位于 **“MoonBit 原生宿主应用的安全插件接入底座（Capability-Secured & Extism-Compatible Plugin Host Sandbox）”**。它专门解决宿主程序在动态加载第三方或不可信 `.wasm` 插件（如 AI Agent 工具插件、Markdown/文档渲染扩展、多租户 Serverless 规则脚本）时面临的三大核心痛点：
1. **权限失控风险**：防止恶意插件通过路径穿越（`../../etc/passwd`）越权读写宿主文件，或向未授权外部域名（`evil.c2`）发起数据外带请求；
2. **资源耗尽攻击（DoS）**：防止插件通过死循环（`loop { br 0 }`）或恶意内存暴涨（`memory.grow`）拖垮宿主进程；
3. **跨语言复杂数据交互困难**：原生 Wasm 仅支持数值类型（`i32`/`i64`/`f32`/`f64`），CapWasm 完整实现了业界主流的 **Extism Host Kernel (`extism:host/env`)** 内存块管理与 I/O 协议，使宿主可以直接向 `.wasm` 插件传递 `String` / `Bytes` 并配置插件级 `Config` 与持久化变量 `Var`。

### 2.2 与对标生态库的定位及功能对比

为明确 CapWasm 在 MoonBit 生态及业界 Wasm 生态中的差异化定位与实质价值，下表将 CapWasm 与 MoonBit 社区现有的 Wasm/沙箱相关项目（`moonbitlang/wasm5`、`mizchi/wasmx`、`tuya-me/aegisrun`、`mizchi/wacon`）以及业界主流插件框架 `Extism (Rust/C SDK)` 进行全方位对比：

| 对比维度 | `moonbitlang/wasm5` | `mizchi/wasmx` | `tuya-me/aegisrun` | `mizchi/wacon` | `Extism (Rust/C SDK)` | **CapWasm (本项目)** |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **核心定位** | Wasm 1.0 规范教学/验证解释器 | 通用 Wasm 虚拟机与底层执行器 | AI Agent / MCP 工具安全执行器 | RISC-V 模拟器容器环境 | 跨语言通用 Wasm 插件宿主 SDK | **MoonBit 原生能力安全 Wasm 插件沙箱与 Extism 宿主内核** |
| **实现语言与外部依赖** | 纯 MoonBit | MoonBit | MoonBit | MoonBit | Rust (`wasmtime`) + C 动态库 FFI | **100% 纯 MoonBit 自包含实现（零 C/Rust FFI 依赖）** |
| **Wasm 1.0 二进制解析与校验** | 支持 | 支持 | 依赖外部或简化 | 面向 RISC-V ELF | 依赖 Wasmtime | **支持（含完整 LEB128、11 类 Section 解析与结构校验器）** |
| **指令级 Gas 计费与死循环熔断** | 不支持 | 基础限制 | 侧重调用超时 | 模拟器周期限制 | 依赖 Wasmtime Epoch/Fuel | **内嵌式指令级精确 Gas 计费 + `GasExhausted` 强熔断** |
| **线性内存页数硬上限 (`memory.grow` 门控)** | 仅遵循模块自身 Limits | 仅遵循模块自身 Limits | 部分支持 | 页表限制 | 宿主 Limits 配置 | **在 `memory.grow` 指令与 Extism `alloc` 双路径强制拦截宿主配额** |
| **细粒度能力安全策略 (`CapabilityPolicy`)** | 无 | 无 | 有（面向 Agent 工具） | 无 | 基础配置（无内置路径穿越审计） | **支持目录前缀读写白名单、`../` 路径穿越拦截、域名白名单** |
| **沙箱内存虚拟文件系统 (VFS) 与 WASI 隔离** | 无 | 基础 WASI 透传 | 受限目录访问 | 镜像文件系统 | 依赖 Wasmtime WASI 目录映射 | **内置纯内存 VFS + 路径规范化 + `WasiFdTable` 标准句柄防篡改** |
| **Extism Host ABI (`extism:host/env`) 兼容** | 不支持 | 不支持 | 不支持 | 不支持 | 原生标准制定者 | **完整实现 `extism:host/env` 19 个宿主函数与内核内存块分配器** |
| **插件级 `Config` 与持久化 `Var` 存储** | 无 | 无 | 无 | 无 | 支持 | **原生支持 (`config_get` / `var_get` / `var_set`)** |
| **结构化安全审计账本 (`AuditRecord`)** | 无 | 无 | 基础日志 | 无 | 仅普通运行日志 | **内置每次 I/O 与网络鉴权的 ALLOWED / DENIED 结构化审计账本** |

> **对比总结**：
> - 相较于 **`moonbitlang/wasm5` 与 `mizchi/wasmx`**：后两者聚焦于“如何运行标准 Wasm 指令”，属于纯净的底层虚拟机；而 **CapWasm** 聚焦于“宿主如何安全可控地接入不可信插件”，在自包含 Wasm 执行引擎之上构建了完整的 **能力权限守卫、内存虚拟文件系统（VFS）、Extism 内核内存分配器与安全审计体系**。
> - 相较于 **`Extism` 官方 SDK**：Extism 官方宿主依赖庞大的 Rust `wasmtime` 与 C 动态库（`libextism`），无法在纯 MoonBit 多后端（wasm-gc / js / native）环境中零依赖运行；**CapWasm** 用纯 MoonBit 实现了 `extism:host/env` 宿主内核协议，让 MoonBit 应用无需任何外部 C/Rust FFI 即可直接加载运行遵循 Extism ABI 的 `.wasm` 插件。

---

## 三、 现有底座之外的实质贡献说明（回应初审反馈 2）

针对评审提出的“现有底座之外的实质贡献尚未说明清楚”的问题，本项目将全部 **8,041 行纯 MoonBit 源码** 清晰划分为 **“第一层：定制化受控 Wasm 1.0 执行底座”** 与 **“第二层：CapWasm 沙箱安全与 Extism 插件内核实质贡献”** 两大层次：

### 3.1 为什么要自建底层 Wasm 执行底座？（内嵌式安全钩子需求）
通用的外部 Wasm 解释器通常将模块执行视为黑盒，难以在不侵入修改解释器源码的前提下实现 **单步指令级 Gas 计费中断** 与 **线性内存动态扩容（`memory.grow`）的宿主策略联动拦截**。因此，CapWasm 构建了自包含的底层执行引擎（`leb128.mbt`、`types.mbt`、`opcode.mbt`、`parser.mbt`、`validator.mbt`、`memory.mbt`、`stack.mbt`、`interpreter.mbt`），并在以下三个关键路径植入了沙箱钩子：
1. **指令分派环路内嵌 Gas 计费**：在 `WasmInstance::execute_bytecode` 每条指令分派前及 Host 函数调用前强制执行 `consume_gas`，一旦超出 `CapabilityPolicy.quota.max_execution_steps` 立即抛出 `Trap::GasExhausted` 并转化为 `SecurityError::OutOfQuota`；
2. **`Instruction::MemoryGrow` 与安全守卫直连**：当插件执行 Wasm 原生 `memory.grow` 指令时，解释器不仅检查 Wasm 模块自身的 `Limits`，还会主动调用 `host_context.sec_guard.check_memory_grow(target_pages)`，若超出宿主授予的 `max_memory_pages` 页数上限，直接拒绝扩容并返回 `-1`；
3. **实例化前置符号链接 (`Linker` + `HostContext`)**：将 `LinearMemory` 与 `PluginSecurityGuard` 注入 `HostContext`，使所有宿主导入函数在同一安全上下文中执行。

### 3.2 底座之上的四大核心实质贡献（核心沙箱与插件层）

在基础 Wasm 字节码解释器之上，CapWasm 的核心实质贡献体现在以下四个独立模块（合计 **2,444 行核心沙箱业务代码 + 939 行配套测试**）：

#### 实质贡献 1：基于 Object-Capability 模型的细粒度权限守卫与审计账本 (`capwasm.mbt`, 398 行)
- **最小权限策略构建器 (`CapabilityPolicyBuilder`)**：默认采用“零信任全拒绝（Deny-by-Default）”策略，宿主通过链式 API 显式授予可读路径前缀（`allow_read_path`）、可写路径前缀（`allow_write_path`）、允许通信的外部域名白名单（`allow_network_host`）、最大内存页数（`max_memory_pages`）与最大指令步数（`max_execution_steps`）。
- **路径穿越实时检测 (`contains_path_traversal`)**：在白名单前缀匹配前，强制扫描路径中的 `..` 序列，任何试图通过 `/workspace/docs/../../etc/shadow` 绕过前缀白名单的行为均被立即识别为 `SecurityError::PathTraversalAttempt`。
- **全链路结构化审计 (`AuditRecord`)**：无论插件的 `FsRead`、`FsWrite`、`NetConnect` 请求被放行还是拦截，`PluginSecurityGuard` 均会记录包含 `plugin_id`、`action`、`target`、`allowed`、`reason` 的不可篡改审计条目，供宿主合规审查。

#### 实质贡献 2：防逃逸沙箱内存虚拟文件系统与 WASI 标准句柄保护 (`vfs.mbt`, 476 行)
- **内存态虚拟文件系统 (`VirtualFileSystem`)**：插件的所有文件读写操作（如 `capwasm::fs_read`、`capwasm::fs_write`）均被重定向至宿主显式挂载的内存虚拟文件节点，与宿主机物理操作系统磁盘完全隔离。
- **POSIX 路径规范化引擎 (`normalize_path`)**：自动折叠多余斜杠 `//`、当前目录 `.` 并安全消解相对路径段，确保沙箱内文件寻址的一致性与安全性。
- **WASI 文件描述符表隔离 (`WasiFdTable`)**：为每个插件实例维护独立的虚拟文件描述符映射表，预分配并锁定标准句柄 `fd 0 (stdin)`、`fd 1 (stdout)`、`fd 2 (stderr)`。实现 `wasi_snapshot_preview1::fd_write` scatter/gather `iovs` 向量化写入，将插件标准输出安全捕获至宿主内存缓冲区，并严禁插件通过 `close_fd` 恶意关闭标准句柄。

#### 实质贡献 3：完整的 Extism Host Kernel 与 `extism:host/env` 协议实现 (`extism.mbt`, 776 行)
- 完整实现了 Extism 插件生态的宿主内核状态机（`ExtismKernel`），包括：**内核内存块分配器（`ExtismMemBlock` 分配与空闲块复用表）**、**主客体 I/O 缓冲区通道**、**插件级只读配置表（`configs`）**、**插件级跨调用持久化变量存储（`vars`）** 以及 **受能力门控保护的 `http_request` 与分级日志系统**（详见第四节）。

#### 实质贡献 4：高阶插件实例编排器与双模式 ABI 调度器 (`plugin.mbt`, 669 行 + `host.mbt`, 125 行)
- **实例化前全量符号注入**：`PluginInstance::load` 在解析并校验 `.wasm` 模块后，自动向 `Linker` 注册 `extism:host/env`（及别名 `env`）、`capwasm`、`wasi_snapshot_preview1` 共 **24 个宿主导入函数**，随后完成模块实例化与数据段初始化。
- **双模式 ABI 自动识别与分派 (`PluginInstance::call_extism` / `call_string`)**：自动检查目标导出函数的类型签名，无缝兼容 **标准 Extism Guest PDK 零参 ABI (`() -> i32`)** 与 **轻量级线性内存切片 ABI (`(ptr: i32, len: i32) -> i32`)**。

---

## 四、 Extism 兼容机制详解（回应初审反馈 3）

为了清晰证明 CapWasm 所承诺的插件接入能力，本节详细说明 `extism.mbt` 与 `plugin.mbt` 中实现的 **Extism Host ABI (`extism:host/env`)** 底层机制。

### 4.1 Extism 主客体交互架构与内存块生命周期

在标准 Extism 协议中，编译为 `.wasm` 的插件导出函数签名为 `() -> i32`（不直接接收指针参数，返回 `0` 表示成功，非 `0` 表示错误）。宿主与插件之间的所有变长数据（输入字节流、输出字节流、配置项、持久化变量、HTTP 请求与响应）均通过 **`ExtismKernel` 管理的 64 位内存块句柄（`i64` offset）** 进行传递：

```
Host Application (MoonBit)                        Guest Plugin (.wasm)
    │                                                     │
    ├─ 1. plugin.call_string("run", "capwasm")            │
    ├─ 2. kernel.begin_call(input_bytes)                  │
    ├─ 3. instance.invoke("run", []) ────────────────────►│
    │                                                     ├─ 4. call env.input_length() -> 7L
    │                                                     ├─ 5. call env.alloc(7L) -> 8192L (Kernel Block)
    │                                                     ├─ 6. loop:
    │                                                     │       call env.input_load_u8(i)
    │                                                     │       transform byte (e.g. to uppercase)
    │                                                     │       call env.store_u8(8192L + i, byte)
    │                                                     ├─ 7. call env.output_set(8192L, 7L)
    │◄─────────────────────── 8. return i32.const 0 ──────┤
    ├─ 9. Read mem[output_offset .. +output_length]       │
    └─ 10. Return Ok("CAPWASM")                           │
```

### 4.2 已完整实现的 `extism:host/env`（含 `env` 别名）19 个标准宿主函数清单

CapWasm 在 `extism.mbt` 的 `register_extism_host_functions` 中同时针对 `"extism:host/env"` 与 `"env"` 两个命名空间完整注册了以下 19 个标准宿主函数：

| 分类 | 导入函数名 | Wasm 签名 | CapWasm 内核实现机制说明 |
| :--- | :--- | :--- | :--- |
| **输入通道** | `input_length` | `() -> (i64)` | 返回当前调用 `kernel.input_data` 缓冲区的字节长度 |
| | `input_load_u8` | `(i64) -> (i32)` | 从 `kernel.input_data` 指定偏移安全读取 1 字节无符号整数 |
| | `input_load_u64` | `(i64) -> (i64)` | 从 `kernel.input_data` 指定偏移按小端序读取 8 字节 `u64` |
| **内核内存分配器** | `alloc` | `(i64) -> (i64)` | 在插件线性内存堆区（起始偏移 `8192`）分配 8 字节对齐的内存块并登记 `ExtismMemBlock`。优先复用已释放且容量足够的空闲块；若线性内存不足则自动触发按页扩容，并强制调用 `sec_guard.check_memory_grow` 校验内存配额，超限则返回 `0L` |
| | `free` | `(i64) -> ()` | 将 `ExtismMemBlock` 标记为 `active = false`，供后续 `alloc` 复用 |
| | `length` | `(i64) -> (i64)` | 查询指定句柄在 `kernel.blocks` 中登记的有效块长度（未分配或已释放返回 `0L`） |
| | `length_unsafe` | `(i64) -> (i64)` | 与 `length` 一致，返回内核块字节长度 |
| **内核内存读写** | `load_u8` | `(i64) -> (i32)` | 从插件线性内存指定偏移读取 1 字节（含边界检查） |
| | `load_u64` | `(i64) -> (i64)` | 从插件线性内存指定偏移按小端序读取 8 字节 `i64`（含边界检查） |
| | `store_u8` | `(i64, i32) -> ()` | 向插件线性内存指定偏移写入 1 字节（含边界检查） |
| | `store_u64` | `(i64, i64) -> ()` | 向插件线性内存指定偏移按小端序写入 8 字节 `i64`（含边界检查） |
| **输出与错误** | `output_set` | `(i64, i64) -> ()` | 记录插件输出数据在线性内存中的偏移 `output_offset` 与长度 `output_length` |
| | `error_set` | `(i64) -> ()` | 根据块句柄读取插件写入的 UTF-8 错误信息并存入 `kernel.error_message` |
| **插件配置与变量** | `config_get` | `(i64) -> (i64)` | 读取键名内存块，在 `kernel.configs` 中查找对应配置值；若存在则自动调用 `alloc` 分配新内存块写入 UTF-8 值并返回块句柄，不存在返回 `0L` |
| | `var_get` | `(i64) -> (i64)` | 读取变量名内存块，在 `kernel.vars` 中查找持久化字节数组，分配新块写入并返回句柄 |
| | `var_set` | `(i64, i64) -> ()` | 读取键名块与值块内容，更新插件级持久化状态表 `kernel.vars` |
| **能力门控 HTTP** | `http_request` | `(i64, i64) -> (i64)` | 读取请求描述块，通过 `extract_host_from_extism_request` 提取目标域名，并强制调用 **`sec_guard.check_network(host)`**：若域名在白名单内，设置状态码 `200`、分配响应内存块并返回句柄；若域名未授权，设置状态码 `403`、写入安全审计账本并返回 `0L` |
| | `http_status_code` | `() -> (i32)` | 返回最近一次 `http_request` 的 HTTP 状态码（如 `200` 或 `403`） |
| **分级日志** | `log_info` / `log_debug` / `log_warn` / `log_error` | `(i64) -> ()` | 从指定内存块读取日志文本，按级别打标后存入 `kernel.logs` 审计队列 |

---

## 五、 代码规模与测试验证清单

本项目所有代码均为 **100% 纯 MoonBit 自研实现**，仓库内代码结构、行数统计与测试覆盖如下表所示：

| 层次划分 | 模块文件 | 代码行数 | 核心职责说明 |
| :--- | :--- | :---: | :--- |
| **Layer 2: 沙箱安全与 Extism 插件内核（实质贡献层）** | `extism.mbt` | 776 行 | Extism 内核内存分配器、`extism:host/env` 19 个宿主函数、Config/Var 存储、能力门控 HTTP |
| | `plugin.mbt` | 669 行 | `PluginInstance` 生命周期管理、`capwasm`/`wasi` 宿主注入、双模式 Extism ABI 调度器 |
| | `vfs.mbt` | 476 行 | 内存虚拟文件系统 (`VirtualFileSystem`)、路径规范化、`WasiFdTable` 标准句柄隔离 |
| | `capwasm.mbt` | 398 行 | `CapabilityPolicy` 最小权限策略、`PluginSecurityGuard` 路径穿越与网络门控、`AuditRecord` 审计 |
| | `host.mbt` | 125 行 | `HostContext` 运行时上下文、`HostFunction` 回调包装与 `Linker` 符号解析器 |
| **Layer 1: 内嵌安全钩子的受控 Wasm 1.0 执行底座** | `interpreter.mbt` | 1,528 行 | 栈式字节码执行引擎（支持完整 `i32`/`i64` 运算、结构化 `block`/`loop`/`if`/`else`/`br_table`、指令级 Gas 计费、受 `sec_guard` 门控的 `memory.grow`） |
| | `parser.mbt` | 948 行 | Wasm 1.0 二进制流解码器（11 类 Section 完整解析与嵌套块深度追踪） |
| | `memory.mbt` | 341 行 | 64 KiB 分页式沙箱线性内存引擎（含越界 Trap 保护与多类型读写） |
| | `leb128.mbt` | 288 行 | LEB128 变长整数编解码器与二进制读取器 (`BinaryReader`) |
| | `opcode.mbt` | 284 行 | Wasm 1.0 操作码定义与结构化指令 AST (`Instruction`) |
| | `types.mbt` | 283 行 | Wasm 核心类型系统（`ValueType`、`FuncType`、`Limits`、`ImportEntry`、`ExportEntry` 等） |
| | `module.mbt` | 206 行 | 静态模块结构 (`WasmModule`) 与导入导出符号索引查询 |
| | `stack.mbt` | 192 行 | 深度受限操作数栈 (`OperandStack`)、调用帧 (`CallFrame`) 与控制流帧 (`ControlFrame`) |
| | `error.mbt` | 134 行 | 统一异常体系（`Trap`、`DecodeError`、`LinkError`） |
| | `validator.mbt` | 122 行 | 模块静态结构与安全边界校验器 (`ModuleValidator`) |
| **CLI 演示与自动化测试套件（47 项测试）** | `cmd/main/main.mbt` | 195 行 | 六大安全与插件场景端到端交互式演示程序（含编译态 Extism `.wasm` 插件实机运行） |
| | `plugin_test.mbt` | 307 行 | 插件加载、Extism 内核分配器、真实 `extism:host/env` 二进制插件端到端转换、HTTP 权限拦截测试 |
| | `interpreter_test.mbt` | 232 行 | 栈式解释器、`if/else` 分支、`i64` 算术、Gas 死循环熔断、`memory.grow` 权限上限测试 |
| | `parser_test.mbt` | 164 行 | Wasm 二进制模块解析与静态结构校验测试 |
| | `capwasm_test.mbt` + `_wbtest.mbt` | 143 行 | 能力安全策略、路径穿越拦截、域名白名单、审计日志测试 |
| | `leb128_test.mbt` | 127 行 | LEB128 有符号/无符号整数边界编解码测试 |
| | `vfs_test.mbt` | 103 行 | 内存虚拟文件系统、POSIX 路径规范化、WASI 标准句柄防关闭测试 |
| **合计** | **23 个 `.mbt` 源码文件** | **8,041 行** | **含 `.mbti` 接口文件共 8,806 行，`moon test` 47 项测试 100% 通过** |

### 本地一键复现与验证命令
```bash
# 1. 运行全部 47 项单元与端到端集成测试
moon test

# 2. 运行交互式安全沙箱与 Extism 二进制插件演示程序
moon run cmd/main
```
