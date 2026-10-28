# 2026 MoonBit 国产基础软件开源大赛 · 10月黑客松项目申报书

## 一、 基本信息

| 申报条目 | 详细内容 |
| :--- | :--- |
| **项目名称** | **CapWasm** — 基于能力安全（Capability-based Security）与 Extism 协议兼容的 MoonBit WebAssembly 插件沙箱 |
| **项目仓库** | `https://github.com/Lxxbv/capwasm`（包名：`Lxxbv/capwasm`，开源协议：Apache-2.0） |
| **工程完成度** | **已完成全栈开发与闭环测试（纯 MoonBit 源码 10,643 行，含 `.mbti` 接口共 11,495 行，50 项单元与端到端测试 100% 通过）** |

---

## 二、 项目定位与对标类似生态库对比说明（回应评审意见 1）

### 2.1 项目核心定位
**CapWasm** 定位于 **“MoonBit 原生宿主应用的能力安全插件沙箱与 Extism 宿主内核（Capability-Secured & Extism-Compatible Plugin Host Sandbox）”**。
它并非单纯用于执行数值计算的底层 Wasm 规范解释器，而是专为 **AI Agent (MCP) 工具扩展、多租户 Serverless 规则脚本、Markdown/文档处理插件** 等需要动态加载不可信第三方 `.wasm` 插件的宿主场景设计，解决三大工程痛点：
1. **默认零信任与防越权逃逸**：通过能力安全策略（`CapabilityPolicy`）与虚拟目录挂载（`ExtismPathMount`），拦截 `../` 路径穿越、未授权文件读写、未授权环境变量读取与非法外联域名请求；
2. **多维资源配额熔断（防 DoS）**：同时对 **单步指令 Gas 消耗**、**`memory.grow` 线性内存扩页**、**Extism 持久化变量容量 (`max_var_bytes`)** 与 **HTTP 响应体积 (`max_http_response_bytes`)** 实施硬性上限门控；
3. **真实 Extism + WASI 插件无缝接入**：原生实现 **Extism Manifest 配置解析器**、**19 个 `extism:host/env` 宿主函数** 与 **19 个 `wasi_snapshot_preview1` 系统调用**，使标准 `wasm32-wasi` 编译的 Extism 插件无需任何外部 C/Rust FFI 即可在纯 MoonBit 宿主中安全运行。

### 2.2 与对标的类似生态库定位及功能对比

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

> **对比结论**：
> 1. **与 `moonbitlang/wasm5`、`mizchi/wasmx` 对比**：后两者聚焦于底层 Wasm 指令执行，缺乏插件宿主所需的权限隔离、虚拟文件系统与跨语言数据编组协议；**CapWasm** 的核心价值在于底座之上的 **4,540 行沙箱安全、WASI 虚拟化与 Extism 插件内核架构**。
> 2. **与 `Extism (Rust/C SDK)` 对比**：官方 Extism 强依赖 Rust `wasmtime` 与 C 动态库 FFI，无法在纯 MoonBit 多后端环境中零依赖编译部署；**CapWasm** 用纯 MoonBit 完整实现了 Extism Manifest、Arena 内存块分配器与 `extism:host/env` + `wasi_snapshot_preview1` 双协议栈。

---

## 三、 现有底座之外的实质贡献详解（回应评审意见 2）

本项目共 **10,643 行纯 MoonBit 代码**。其中，底层 Wasm 1.0 执行引擎为 **4,415 行**，而 **构建在底座之上的沙箱安全、WASI 虚拟化与 Extism 插件内核实质贡献代码达 4,540 行（另有 1,456 行测试与 232 行演示程序）**，实质贡献代码量超过底层虚拟机本身：

### 3.1 现有底座之上的六大核心实质贡献模块（共 4,540 行）

1. **`manifest.mbt`（562 行）— Extism Manifest 规范解析器、二进制指纹校验与虚拟目录挂载引擎**：
   - 实现纯 MoonBit 的 `ExtismManifest::from_json` 解析器，支持解析 `wasm` 路径与哈希、`max_pages`、`max_http_response_bytes`、`max_var_bytes`、`config`、`allowed_hosts`、`allowed_paths`（含 `ro:/host/dir` 只读挂载前缀）及 `allowed_env_vars`；
   - 实现 64 位 **FNV-1a 二进制完整性指纹校验 (`verify_wasm_fingerprint`)**，在加载 `.wasm` 字节码前自动拦截被篡改的插件镜像；
   - 实现客体到宿主的虚拟路径映射引擎 `resolve_mounted_path`（例如将插件内的 `/docs/hello.txt` 安全重定向至宿主 VFS 的 `/host/tenant_a/docs/hello.txt`，并在只读挂载点上强制拦截写请求）。
2. **`extism.mbt`（881 行）— Extism 宿主内核 (`ExtismKernel`) 与 19 个 `extism:host/env` 宿主函数**：
   - 实现基于插件线性内存的 **Arena Bump Allocator (`ExtismMemBlock`)**，支持 8 字节对齐分配、空闲块标记复用（`free`）与按需自动扩页（联动 `sec_guard.check_memory_grow`）；
   - 实现主客体变长数据 I/O 通道（`input_length`、`input_load_u8/u64`、`load_u8/u64`、`store_u8/u64`、`output_set`、`error_set`）；
   - 实现插件只读配置表（`config_get`）、受 `max_var_bytes` 配额保护的跨调用持久化状态存储（`var_get`、`var_set`），以及受 `sec_guard.check_network` 域名白名单与 `max_http_response_bytes` 双重门控的 `http_request` / `http_status_code` 和四级日志接口。
3. **`wasi.mbt`（790 行）— 受能力门控的完整 `wasi_snapshot_preview1` 系统调用层（19 个 Syscall）**：
   - 针对真实 Extism 插件（通常以 `wasm32-wasi` 编译）的运行时依赖，完整实现 19 个标准 WASI preview1 系统调用：`args_sizes_get`、`args_get`、`environ_sizes_get`、`environ_get`、`clock_res_get`、`clock_time_get`、`fd_prestat_get`、`fd_prestat_dir_name`、`fd_fdstat_get`、`fd_fdstat_set_flags`、`path_open`、`fd_read`、`fd_write`、`fd_seek`、`fd_sync`、`fd_close`、`path_unlink_file`、`random_get`、`proc_exit`；
   - 每个系统调用均与 `PluginSecurityGuard` 深度联动：如 `path_open` 自动经由 `resolve_mounted_path` 转换虚拟路径并执行 `check_fs_read`/`check_fs_write`；`environ_get` 仅暴露白名单允许的环境变量；`clock_time_get` 受 `check_clock` 门控并提供确定性虚拟单调时钟。
4. **`pdk.mbt`（501 行）— Extism Guest PDK 与全功能 Wasm 1.0 二进制编译器 (`WasmModule::encode_to_bytes`)**：
   - 实现将结构化 `WasmModule` AST 完整编码为标准 WebAssembly 1.0 `.wasm` 二进制字节码的编译器（自动计算 11 类 Section 的 LEB128 长度帧与完整指令集编码），支持在纯 MoonBit 中直接构建编译符合 Extism/WASI ABI 的 `.wasm` 插件并进行端到端闭环验证。
5. **`vfs.mbt`（500 行）— 纯内存虚拟文件系统 (`VirtualFileSystem`) 与 WASI 文件描述符表 (`WasiFdTable`)**：
   - 提供与宿主机物理磁盘完全隔离的内存文件节点（支持 `create_file`、`read_file`、`write_file`、`remove_file`、`seek`）、POSIX 路径规范化（`canonicalize_path`）以及锁定保护 `stdin(0)/stdout(1)/stderr(2)` 的虚拟文件描述符表。
6. **`capwasm.mbt`（492 行）+ `plugin.mbt`（689 行）+ `host.mbt`（125 行）— 能力安全守卫、审计账本与插件生命周期编排器**：
   - 实现 `CapabilityPolicyBuilder`、支持 `*.domain.com` 通配符匹配的 `PluginSecurityGuard`、不可篡改的 `AuditRecord` 审计账本，以及支持从 `ExtismManifest` 一键实例化并注入全部 **42 个宿主导入函数** 的 `PluginInstance::load_from_manifest`。

### 3.2 底层 Wasm 1.0 执行底座的定制化安全改造（共 4,415 行）
底层执行引擎（`interpreter.mbt` 1,617 行、`parser.mbt` 948 行等）并非通用黑盒解释器，而是专为插件沙箱定制了四大内核特性：
1. **指令分派环路内嵌单步 Gas 熔断**：每条字节码与宿主调用均触发 `consume_gas`，超限立即抛出 `Trap::GasExhausted`；
2. **`Instruction::MemoryGrow` 宿主配额联动拦截**：在模块自身 `Limits` 之外强制校验 `sec_guard.check_memory_grow(target_pages)`；
3. **完整的函数表与动态间接调用 (`TableInstance` + `CallIndirect`)**：支持 `table` 段与 `elem` 段初始化，并在执行 `call_indirect` 时动态校验 `FuncType` 签名一致性，满足 `wasm32-wasi` 编译产物的函数指针分派需求；
4. **`i32`/`i64` 全指令集与结构化控制流**：完整支持 64 位整数运算/访存（Extism 内存块句柄为 `i64`）及嵌套 `block`/`loop`/`if`/`else`/`br_table`。

---

## 四、 Extism 兼容机制与插件接入能力证明（回应评审意见 3）

CapWasm 通过以下 **四阶段全链路兼容机制**，确保所承诺的 Extism 插件接入能力真实、完整、可验证：

```
[阶段 1: Manifest 解析与校验]  ExtismManifest::from_json -> FNV-1a 哈希校验 -> 生成 CapabilityPolicy 与虚拟挂载表
                                      │
                                      ▼
[阶段 2: 42 个宿主符号预链接]  自动注入 19 个 extism:host/env (含 env 别名) + 19 个 wasi_snapshot_preview1 + 4 个 capwasm
                                      │
                                      ▼
[阶段 3: 内核内存块与双 ABI]   plugin.call_string("run", input) -> ExtismKernel Arena 分配/复用 -> 零参 () -> i32 导出调用
                                      │
                                      ▼
[阶段 4: 能力门控与结果回收]   拦截越权 WASI 文件/网络/变量配额 -> 读取 output_set(offset, len) -> 更新 Gas 与审计账本
```

1. **协议级 ABI 100% 对齐**：在 `extism.mbt` 中同时向 `"extism:host/env"` 与 `"env"` 命名空间注册全部 **19 个官方 Extism 宿主函数**（`input_length`、`input_load_u8`、`input_load_u64`、`length`、`length_unsafe`、`alloc`、`free`、`load_u8`、`load_u64`、`store_u8`、`store_u64`、`output_set`、`error_set`、`config_get`、`var_get`、`var_set`、`http_request`、`http_status_code`、`log_info/debug/warn/error`）。
2. **WASI Preview1 100% 协同支撑**：在 `wasi.mbt` 中注册全部 **19 个 `wasi_snapshot_preview1` 函数**，使插件在执行 Extism I/O 的同时，可通过标准 WASI `path_open` + `fd_read` + `fd_write` 访问 `ExtismManifest` 中挂载的虚拟目录（如 `/docs` -> `/host/tenant_a/docs`），并通过 `clock_time_get`、`random_get`、`environ_get` 获取受控系统资源。
3. **端到端实机验证闭环（见 `plugin_test.mbt` 与 `cmd/main/main.mbt`）**：
   - **测试验证 1（Extism 字节流转换插件）**：加载编译态 `.wasm` 插件，通过 `input_length` -> `alloc` -> `input_load_u8` -> `store_u8` -> `output_set` 将 `"moonbit"` 转换为 `"MOONBIT"`；
   - **测试验证 2（Extism HTTP 与 Config/Var 配额门控）**：验证 `*.moonbitlang.com` 通配符域名放行（HTTP 200）与未授权域名 `evil.attacker.org` 拦截（HTTP 403 + 审计记录）；
   - **测试验证 3（Manifest + WASI `path_open` + Extism `output_set` 联合插件）**：通过 `ExtismManifest` 挂载只读目录 `/docs` -> `/host/tenant_a/docs`，插件内调用 WASI `path_open("/docs/hello.txt")` 与 `fd_read` 读取宿主 VFS 文件内容，再调用 Extism `alloc` + `store_u8` + `output_set` 将结果返回宿主，完整证明了 Extism + WASI 真实插件接入能力。

---

## 五、 代码结构与本地一键验证

| 模块分层 | 文件清单与代码行数 |
| :--- | :--- |
| **Layer 2: 沙箱安全、WASI 与 Extism 插件内核（4,540 行）** | `extism.mbt` (881行)、`wasi.mbt` (790行)、`plugin.mbt` (689行)、`manifest.mbt` (562行)、`pdk.mbt` (501行)、`vfs.mbt` (500行)、`capwasm.mbt` (492行)、`host.mbt` (125行) |
| **Layer 1: 内嵌安全钩子的受控 Wasm 1.0 底座（4,415 行）** | `interpreter.mbt` (1,617行)、`parser.mbt` (948行)、`memory.mbt` (341行)、`leb128.mbt` (288行)、`opcode.mbt` (284行)、`types.mbt` (283行)、`module.mbt` (206行)、`stack.mbt` (192行)、`error.mbt` (134行)、`validator.mbt` (122行) |
| **演示程序与测试套件（1,688 行，50 项测试）** | `cmd/main/main.mbt` (232行)、`plugin_test.mbt` (687行)、`interpreter_test.mbt` (232行)、`parser_test.mbt` (164行)、`capwasm_test.mbt` (143行)、`leb128_test.mbt` (127行)、`vfs_test.mbt` (103行) |

```bash
moon test           # 运行全部 50 项单元测试与 Extism/WASI 端到端集成测试（50 passed, 0 failed）
moon run cmd/main   # 运行包含 7 大沙箱安全、WASI 隔离与 Extism Manifest 插件加载的交互式演示程序
```
