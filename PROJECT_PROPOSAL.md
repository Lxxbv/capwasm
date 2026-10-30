# CapWasm 项目申报书

## 一、 基本信息

- **项目名称**：**CapWasm** — 基于能力安全与 Extism/WASI 协议的纯 MoonBit WebAssembly 插件沙箱
- **项目仓库**：`https://github.com/Lxxbv/capwasm`（包名：`Lxxbv/capwasm`，开源协议：Apache-2.0）
- **当前进度**：已完成核心研发与测试闭环（纯 MoonBit 源码 10,735 行，50 项单元与集成测试 100% 通过）

---

## 二、 项目定位与成熟生态库对比

### 2.1 项目定位
**CapWasm** 是面向 MoonBit 宿主应用的**零外部依赖 WebAssembly 插件安全沙箱与 Extism 宿主运行时**，解决宿主动态加载第三方不可信 `.wasm` 插件（如 AI Agent 工具扩展、多租户 Serverless 规则脚本、文档处理插件）时的权限隔离、资源熔断与跨语言数据交互问题。

### 2.2 与其他语言成熟生态库的功能对比

| 对比维度 | `Extism` (Rust / C `libextism`) | `Wasmtime` + `cap-std` (Rust) | `Wazero` (Go) | `Wasmer` (Rust / C) | **CapWasm (MoonBit)** |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **核心定位** | 跨语言通用 Wasm 插件框架 | 字节码联盟官方能力安全运行时 | 纯 Go 零依赖 Wasm 沙箱运行时 | 通用云原生 Wasm 容器运行时 | **纯 MoonBit 能力安全插件沙箱 + Extism 宿主内核** |
| **实现方式与依赖** | Rust `wasmtime` + C FFI 动态库 | Rust + OS 原生 `cap-std` 句柄 | 100% 纯 Go（零 CGO 依赖） | Rust / C++ + 系统级编译器依赖 | **100% 纯 MoonBit（零 C/Rust FFI 外部依赖）** |
| **Extism Host ABI (`extism:host/env`)** | 官方标准（独立内核内存 Arena） | 不内置（需上层封装） | 不内置（被 Extism Go SDK 底层调用） | 不内置 | **完整实现 19 个宿主函数 + 独立 `kernel_memory` Arena** |
| **Manifest 与二进制校验** | JSON Manifest + 标准 `SHA-256` | 无内置 Manifest 规范 | 无内置 Manifest 规范 | WAPM/WASIX 清单 | **兼容 Extism JSON Manifest + 标准 FIPS 180-4 `SHA-256`** |
| **WASI 虚拟文件系统隔离** | 依赖 Wasmtime 目录映射 | OS 目录句柄级隔离 | 内置内存 `fstest.MapFS` / 只读挂载 | 虚拟 VFS + 宿主机目录映射 | **纯内存 `VirtualFileSystem` + `ro:` 只读挂载 + 19 个 WASI preview1** |
| **网络与环境变量能力控制** | `allowed_hosts` 域名白名单 | WASI Socket 句柄级门控 | 默认阻断网络，按需注入 | 策略配置放行 | **`*.domain` 通配符域名白名单 + 环境变量白名单 + `../` 路径穿越拦截** |
| **多维资源熔断与安全审计** | Fuel 计费 + `max_pages` / `max_var_bytes` | Fuel / Epoch 中断 | Context 超时与页上限 | Metering 中间件 | **单步 Gas 熔断 + 扩页/`max_var_bytes`/`max_http_response_bytes` 门控 + `AuditRecord` 账本** |

> **与 MoonBit 社区邻近库的互补边界**：社区现有的 `moonbitlang/wasm5` 与 `mizchi/wasmx` 定位于纯粹的底层 Wasm 规范指令解释与 CLI 执行，`tuya-me/aegisrun` 定位于上层 Agent 任务编排；**CapWasm** 则填补了两者之间的 **“受控插件宿主内核层”**（类似 Go 生态中 `Wazero` + `Extism Host` 的组合），为 MoonBit 应用提供开箱即用的插件权限守卫、内存态 VFS 与 Extism/WASI 双协议栈接入能力。

---

## 三、 核心架构与 Extism 兼容契约

CapWasm 由 **受控 Wasm 1.0 执行底座（4,415 行）** 与 **底座之上的沙箱安全及 Extism/WASI 插件内核层（4,628 行）** 组成：

1. **双内存空间隔离契约（消除主客体内存冲突，`extism.mbt` 866 行）**：
   - 严格遵循官方 Extism 内存模型，`ExtismKernel` 维护独立的宿主内核内存空间（`kernel_memory : LinearMemory`），与客体插件自身的 Wasm 线性内存（`instance.memories[0]`）完全物理隔离，绝不侵入或覆盖客体 `.wasm` 模块的 C/Rust/Go/MoonBit 栈空间、数据段与堆分配器。
   - `extism:host/env`（及兼容别名 `env`）的全部 **19 个宿主函数**（`alloc`、`free`、`length`、`length_unsafe`、`load_u8/u64`、`store_u8/u64`、`input_length`、`input_load_u8/u64`、`output_set`、`error_set`、`config_get`、`var_get/set`、`http_request`、`http_status_code`、`log_*`）统一通过 64 位句柄在 `kernel_memory` 中完成数据交换与空闲块复用，并受 `max_memory_pages`、`max_var_bytes` 与 `max_http_response_bytes` 配额门控。
2. **标准 Extism Manifest 与 FIPS 180-4 `SHA-256` 校验契约（`manifest.mbt` 665 行）**：
   - `ExtismManifest::from_json` 原生解析标准 Extism 清单字段（`wasm[].path`、`wasm[].hash`、`max_pages`、`max_var_bytes`、`max_http_response_bytes`、`config`、`allowed_hosts`、`allowed_paths`）；
   - 内置纯 MoonBit 实现的 **FIPS 180-4 `SHA-256`** 算法（`compute_wasm_sha256`），在加载插件前对 `.wasm` 字节码执行标准 64 位十六进制 SHA-256 摘要比对，篡改即拒绝实例化。
3. **能力门控的 `wasi_snapshot_preview1` 与内存态 VFS（`wasi.mbt` 790 行 + `vfs.mbt` 500 行 + `capwasm.mbt` 492 行）**：
   - 针对 `wasm32-wasi` 编译的真实 Extism 插件，完整实现 **19 个 WASI preview1 系统调用**（`path_open`、`fd_read`、`fd_write`、`fd_seek`、`fd_close`、`fd_prestat_get`、`fd_prestat_dir_name`、`environ_get`、`clock_time_get`、`random_get`、`proc_exit` 等）；
   - 所有文件操作通过 `resolve_mounted_path` 映射至纯内存 `VirtualFileSystem`（支持 `ro:` 只读挂载与 `../` 路径穿越拦截），每次文件、网络、时钟与环境变量访问均由 `PluginSecurityGuard` 鉴权并写入 `AuditRecord` 审计账本。
4. **内嵌安全钩子的受控执行底座与二进制编译器（`interpreter.mbt` 1,617 行 + `pdk.mbt` 501 行 + `plugin.mbt` 689 行）**：
   - 字节码解释器在分派环路内嵌单步 Gas 计费熔断（`Trap::GasExhausted`）与 `memory.grow` 宿主页上限拦截，完整支持 `i32`/`i64` 指令集、嵌套控制流及 `TableInstance` + `CallIndirect` 动态函数表签名校验；`pdk.mbt` 提供完整 11 节 Wasm 二进制编码器以支持端到端闭环验证。

---

## 四、 模块清单与本地验证

| 模块划分 | 核心文件与代码量 |
| :--- | :--- |
| **沙箱安全与 Extism/WASI 内核层（4,628 行）** | `extism.mbt` (866行)、`wasi.mbt` (790行)、`plugin.mbt` (689行)、`manifest.mbt` (665行)、`pdk.mbt` (501行)、`vfs.mbt` (500行)、`capwasm.mbt` (492行)、`host.mbt` (125行) |
| **受控 Wasm 1.0 执行底座（4,415 行）** | `interpreter.mbt` (1,617行)、`parser.mbt` (948行)、`memory.mbt` (341行)、`leb128.mbt` (288行)、`opcode.mbt` (284行)、`types.mbt` (283行)、`module.mbt` (206行)、`stack.mbt` (192行)、`error.mbt` (134行)、`validator.mbt` (122行) |
| **CLI 演示与测试套件（1,692 行，50 项测试）** | `cmd/main/main.mbt` (234行)、`plugin_test.mbt` (684行) 及 5 个专项测试文件（共 774 行） |

```bash
moon test           # 运行全部 50 项单元测试与 Extism/WASI 集成测试（50 passed, 0 failed）
moon run cmd/main   # 运行包含能力隔离、WASI VFS、Extism SHA-256 Manifest 加载的 7 大场景演示
```
