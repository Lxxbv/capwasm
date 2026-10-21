# MoonBit Hackathon 2026 项目立项申报书

---

## 一、 项目基本信息

- **项目名称**：`CapWasm`（基于能力模型的 WebAssembly 插件沙箱宿主）
- **英文标识**：`capwasm`
- **一句话介绍**：为 MoonBit 应用提供生产级的轻量级 WASM 插件沙箱框架——按能力授权（文件/网络/时钟/配额），越权直接拦截并审计，实现零信任插件扩展。
- **开源许可证**：Apache-2.0
- **项目仓库**：`https://github.com/Lxxbv/capwasm`（Mooncakes: `Lxxbv/capwasm`）
- **申报赛道**：系统软件与基础设施工具（System-Level Software & Infrastructure）

---

## 二、 立项背景与生态痛点（为什么必须做？）

### 1. 行业趋势与应用扩展需求
现代生产级应用（如 Figma 插件系统、Shopify 脚本、Envoy 过滤器、Obsidian 插件）普遍采用 WebAssembly 作为其插件沙箱标准。原因在于：
- **原生隔离**：Wasm 线性内存天然沙箱化，插件即使崩溃也不会导致主宿主进程崩溃。
- **跨语言支持**：第三方开发者可以使用不同语言编写插件。
- **高性能与秒级冷启动**：相较于传统微服务或容器化插件，Wasm 的执行与销毁开销极低。

### 2. MoonBit 生态的“灵魂契合”与缺口
MoonBit 是当前全球对 WebAssembly 优化最彻底、编译产物体积最小（单插件常在 10KB~50KB 级别）、冷启动速度最快的新一代语言。
- **缺口现状**：检索 Mooncakes 官方全库，目前在 `plugin`、`sandbox`、`wasm-host` 领域仅有零星的垂直工具（如 sqlc 插件生成器、Typst 绑定），**完全缺乏通用的“Wasm 插件宿主与能力安全策略框架”**。
- **生态价值**：开发 `CapWasm` 将为 MoonBit 生态补齐最关键的**应用扩展基石**。无论是 MoonBit 编写的静态站点生成器、编辑器/IDE 插件、轻量数据库引擎还是游戏引擎，均可一键引入 `CapWasm`，轻松获得接入不可信第三方插件的能力。

---

## 三、 竞品分析与生态位辨析（差异化与重复风险控制）

初审阶段最关键的问题是：“生态中已有项目，你们是否在重复造轮子？”
`CapWasm` 与生态相邻项目的关系清晰明了，属于互补协作的上下游关系：

| 项目 / 模块 | 所属组织 | 核心定位与技术栈 | 与 CapWasm 的本质区别与协同关系 |
| :--- | :--- | :--- | :--- |
| **`moonbitlang/wasm5`** | MoonBit 官方 | 纯 MoonBit Wasm Core 1.0 解释器 | **【下游依赖】** `wasm5` 是字节码解释器，负责 opcode 执行；`CapWasm` 是应用级插件框架，负责 Capability 策略控制、Host-Plugin 内存 ABI 编解码与安全审计。两者如 Linux 内核与 Docker 的关系。 |
| **`mizchi/wasmx`** | 社区核心 | 纯 MoonBit Wasm 虚拟机（优化分支） | **【可选底层】** 同属底层引擎，不提供面向应用层的插件生命周期管理与细粒度权限模型。 |
| **`tuya-me/aegisrun`** | 涂鸦智能 | AI Agent 工具安全运行时 | **【垂直应用】** 强绑定 MCP (Model Context Protocol) 工具调用协议；`CapWasm` 定位为通用基础设施，任何 MoonBit 应用均可嵌入。 |
| **`mizchi/wacon`** | 社区核心 | 纯 MoonBit RISC-V 模拟器与极简容器 | **【技术栈不同】** 模拟 RISC-V 硬件指令集以运行 Alpine Linux 系统二进制，并非 Wasm 插件沙箱。 |

**结论**：`CapWasm` 拥有独一无二的生态位，专注于**通用、高安全、基于能力模型的插件宿主框架**。

---

## 四、 系统架构与核心技术方案

### 1. 总体分层架构

```mermaid
graph TD
    A[Host Application (MoonBit App)] --> B[Plugin Host Manager]
    B --> C[Capability Security Guard]
    B --> D[Extism-like Memory Bridge]
    
    subgraph "CapWasm Security & Governance"
        C --> C1[Path Traversal Detector]
        C --> C2[Network Host Allowlist]
        C --> C3[Instruction Step Limiter]
        C --> C4[Audit Log Stream]
    end
    
    subgraph "Execution Layer"
        D --> E[Host Imports: fs, net, clock, abort]
        E --> F[WASM Runtime (wasm5 / wasmx)]
        F --> G[Sandboxed Plugin (.wasm)]
    end
```

### 2. 核心技术创新点

1. **细粒度能力授权模型（Capability-Based Security）**：
   - 彻底摒弃全开/全关的粗粒度权限。
   - 支持前缀目录只读/读写白名单（如仅允许 `./workspace/docs/`），内建路径规范化与目录穿越（`..`）强制检测防御。
   - 网络出口域名精准白名单控制。
2. **轻量级 Host-Plugin ABI 内存传递协议**：
   - 借鉴工业级方案（Extism 设计思想），采用极简切片协议 `(offset: Int, length: Int)`。
   - 宿主与插件在无需庞大 WIT/Component Model 运行时开销的前提下，零内存拷贝直接安全传递字符串与结构化 JSON 数据。
3. **抗死循环与资源耗尽（Resource Quota & Gas Limit）**：
   - 宿主支持配置 `max_execution_steps` 与 `max_memory_pages`。
   - 插件若陷入非预期死循环或恶意消耗算力，宿主将即时中断并上报 `OutOfQuota` 错误。
4. **结构化安全审计轨迹（Audit Trail）**：
   - 记录插件从启动到销毁每一次尝试调用宿主特权操作的详细轨迹（时间、目标、权限判定、拒绝原因），为企业级应用提供审计合规保障。

---

## 五、 原型验证成果（已交付可运行 PoC）

项目不仅停留在设计阶段，**核心领域引擎与能力防御原型已在 MoonBit 原生环境下全部实现并通过验证**：

### 1. 核心单测全部通过（6/6 Passed）
- `plugin sandbox: allowed file read`：合规路径读写正常放行。
- `plugin sandbox: unauthorized path rejected`：越权路径直接拦截。
- `plugin sandbox: path traversal attack blocked`：路径穿越（`../../etc/passwd`）防御生效。
- `plugin sandbox: network isolation`：外部未授权 C2 域名连接彻底阻断。
- `plugin sandbox: step quota limits infinite loop`：步数超限熔断，防死循环。

### 2. 交互式 CLI 演示（`moon run cmd/main`）
已内置可运行的交互式场景展示：
- **场景 1（正常插件）**：`doc-renderer.wasm` 顺利完成文档渲染与输出。
- **场景 2（恶意插件）**：`untrusted-agent.wasm` 试图越权读取密钥与外联恶意域名，宿主控制台瞬间拦截并高亮告警。
- **场景 3（失控插件）**：`crypto-miner.wasm` 触发步数配额熔断并安全退出。

---

## 六、 开发计划与里程碑

- **阶段一（立项与原型打通，已完成）**：
  - [x] 确立 Capability 权限模型与安全边界。
  - [x] 实现目录穿越防御、网络白名单与 Step Quota 熔断机制。
  - [x] 实现审计日志记录体系并完成基础套件自动化测试。
- **阶段二（WASM 解释器深度集成，3 天）**：
  - [ ] 封装 `moonbitlang/wasm5` 运行时，完成 Host Function 动态注入。
  - [ ] 固化 Extism-like ABI 字符串/字节流编解码协议。
- **阶段三（Dogfooding 插件开发与工具链，3 天）**：
  - [ ] 编写纯 MoonBit 编译而成的官方参考插件（Markdown 处理、数据清洗）。
  - [ ] 编写插件开发 SDK（`capwasm-pdk`），让第三方用 MoonBit 编写插件只需 5 行代码。
- **阶段四（文档、验收与发布，2 天）**：
  - [ ] 完善中英文文档、架构图与演示视频。
  - [ ] 发布 `Lxxbv/capwasm` 至 Mooncakes 官方注册表。

---

## 七、 总结

`CapWasm` 紧密扣合 MoonBit 的 WebAssembly 语言核心基因，填补了生态中通用插件沙箱框架的空白。项目架构清晰、技术可行性高、边界定义严密，且已具备可运行的原型支撑，具备极高的实际应用价值与比赛竞争力。
