# CapWasm 项目申报书

项目名称：CapWasm（基于能力安全与 Extism/WASI 协议的 WebAssembly 插件沙箱）  
项目标识：`Lxxbv/capwasm`  
GitHub 仓库：https://github.com/Lxxbv/capwasm  
开源许可证：Apache-2.0  

## 一、 项目目标与场景

本项目旨在为 MoonBit 宿主应用构建零外部依赖的 WebAssembly 插件安全沙箱与 Extism/WASI 运行时，解决宿主在动态加载第三方不可信 `.wasm` 插件（如 AI Agent 动态工具扩展、多租户 Serverless 规则脚本、文档处理流水线）时的权限隔离、资源熔断与跨语言数据交互问题。

与传统无沙箱执行或直接调用 C/Rust FFI 动态库相比，CapWasm 采用纯 MoonBit 实现完整的受控执行底座与安全治理层，具有天然跨平台、零本地依赖编译、细粒度能力鉴权与毫秒级冷启动优势。

## 二、 对标成熟生态库对比与互补边界

### 1. 与其他语言成熟生态库功能对比

| 对比维度 | Extism (Rust / C `libextism`) | Wasmtime + cap-std (Rust) | Wazero (Go) | Wasmer (Rust / C) | CapWasm (MoonBit) |
| :--- | :---: | :---: | :---: | :---: | :---: |
| 核心定位 | 跨语言通用 Wasm 插件框架 | 官方能力安全运行时 | 纯 Go 零依赖 Wasm 沙箱 | 通用 Wasm 容器运行时 | 纯 MoonBit 能力安全插件沙箱 + Extism 宿主内核 |
| 实现方式与依赖 | Rust `wasmtime` + C FFI 动态库 | Rust + OS 原生 `cap-std` 句柄 | 100% 纯 Go（零 CGO） | Rust/C++ 系统级编译器依赖 | 100% 纯 MoonBit（零 C/Rust 外部依赖） |
| Extism ABI (`extism:host/env`) | 官方标准（独立内核内存 Arena） | 不内置（需上层封装） | 不内置 | 不内置 | 完整实现 22 个 Extism 1.x 宿主函数 + 独立 `kernel_memory` Arena |
| Manifest 与校验 | JSON Manifest + 标准 SHA-256 | 无内置 Manifest 规范 | 无内置 Manifest 规范 | WAPM/WASIX 清单 | 兼容 Extism JSON Manifest + FIPS 180-4 SHA-256 摘要防篡改 |
| WASI 虚拟文件系统 | 依赖 Wasmtime 目录映射 | OS 目录句柄级隔离 | 内置内存 `fstest.MapFS` / 只读挂载 | 虚拟 VFS + 宿主机目录映射 | 纯内存 VirtualFileSystem + `ro:` 只读挂载 + 19 个 WASI preview1 |
| 网络与能力控制 | `allowed_hosts` 域名白名单 | WASI Socket 句柄级门控 | 默认阻断网络，按需注入 | 策略配置放行 | `*.domain` 通配符域名白名单 + 环境变量白名单 + `../` 路径穿越拦截 |
| 资源熔断与审计 | Fuel 计费 + `max_pages` / `max_var_bytes` | Fuel / Epoch 中断 | Context 超时与页上限 | Metering 中间件 | 单步 Gas 熔断 + 扩页/`max_var_bytes`/`max_http_response_bytes` 门控 + 审计账本 |

### 2. 与 MoonBit 社区邻近库互补边界说明
MoonBit 社区现有的 `moonbitlang/wasm5` 与 `mizchi/wasmx` 定位于纯粹的底层 Wasm 规范指令解释与 CLI 执行，`tuya-me/aegisrun` 定位于垂直的 AI 工具任务编排。CapWasm 填补的是两者之间的“受控插件宿主内核层”（类似 Go 生态中 Wazero + Extism Host 的结合体），向下管理受控字节码执行，向上为 MoonBit 宿主应用暴露开箱即用的插件安全权限策略与标准 Extism/WASI 双协议栈。

## 三、 交付范围与 Extism 兼容契约

1. **双内存空间物理隔离契约（`extism.mbt`）**：严格遵循官方 Extism 内存安全契约，`ExtismKernel` 维护独立的宿主内核内存空间（`kernel_memory : LinearMemory`），与插件自身线性内存物理隔离，绝不侵入插件自身栈与堆。`extism:host/env` 全部 22 个宿主函数统一通过 64 位句柄在 `kernel_memory` 中交互，受 `max_memory_pages`、`max_var_bytes` 与 `max_http_response_bytes` 配额保护。
2. **标准 Extism Manifest 与 FIPS 180-4 SHA-256 校验（`manifest.mbt`）**：原生解析标准 Extism 清单字段（`wasm[].path`、`wasm[].hash`、`config`、`allowed_hosts`、`allowed_paths` 等），内置纯 MoonBit 实现的 FIPS 180-4 SHA-256 算法，在插件加载前校验二进制摘要，篡改即拒绝加载。
3. **能力门控的 WASI preview1 与内存态 VFS（`wasi.mbt` + `vfs.mbt` + `capwasm.mbt`）**：完整实现 19 个 WASI preview1 系统调用（`path_open`、`fd_read`、`fd_write`、`fd_seek`、`fd_close`、`fd_prestat_get` 等），通过纯内存 `VirtualFileSystem` 实现 `ro:` 只读挂载与 `../` 路径穿越拦截，特权访问由 `PluginSecurityGuard` 实时鉴权并写入结构化审计账本。
4. **受控 Wasm 执行底座与二进制编译器（`interpreter.mbt` + `pdk.mbt` + `plugin.mbt`）**：解释器分派环路内嵌单步 Gas 计费熔断与 `memory.grow` 宿主页上限拦截，支持完整的 `i32`/`i64` 指令集、分支控制流与动态函数表调用（`call_indirect`）；提供完整的 11 节 Wasm 二进制编码器用于端到端验证。

## 四、 测试与里程碑

1. **测试质量**：全套 51 项白盒/黑盒单元测试与端到端集成测试 100% 通过（`moon test`）。覆盖 NIST SHA-256 标准测试向量、Extism 独立内核内存读写、WASI 文件隔离、单步 Gas 熔断以及路径穿越越权拦截。
2. **本地可复现演示**：提供 `cmd/main` 命令行演示程序（`moon run cmd/main`），直观呈现合法插件放行、路径穿越拦截、未授权网络阻断、死循环配额熔断及编译级 Extism 插件端到端调用 7 大真实场景。
3. **工程规范**：严格执行 `moon check`、`moon fmt` 与 `moon info`，生成完整的 `.mbti` 接口定义，全仓 10,674 行纯 MoonBit 代码，无任何外部 C/Rust FFI 依赖。

## 五、 原创与合规说明

本项目为原创 MoonBit 实现，代码与文档采用 Apache-2.0 许可证开源。所有模块均遵循自主架构设计与编码实现，算法名称与 ABI 协议标准遵循 Extism 规范与 WebAssembly 1.0/WASI 公开技术规范。
