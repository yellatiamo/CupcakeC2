# Changelog

本文件记录 Cupcake C2 产品版本变更。格式大致遵循 [Keep a Changelog](https://keepachangelog.com/)。

---

## [Unreleased]

### 模块体系 v2：进程内经典 BOF（bof | inject | ad）

> 本节**推翻**下方「产品 BOF：回退隔离路径（iso_host）」的方向，恢复并落地进程内经典 BOF。

- **iso_host 整体退役**：删除通用牺牲宿主；`bof` 成为产品模块——**Agent 进程内**经典 BOF（C 语言 COFF 动态加载，Manual-Map 无文件落地、无新进程），按需加载，Agent 落地不带 Beacon*/BOF 引擎特征。
- **.NET 退役**：`execute_assembly` / `dotnet` 移除；程序集请转 shellcode（如 Donut）后走 `inject`。
- **inject / ad 保持进程隔离**：各自独立的一次性牺牲 worker EXE（`cupcake-inject-worker` / `cupcake-ad-worker`），Job Object 生命周期不变。
- 服务端：产品模块白名单 `bof|inject|ad`；`PluginRequiredModule` bof-exec→`bof`；`EnsureHeavyRuntimeModule` 对旧 id（dotnet/execute_assembly/iso_host）返回退役指引；能力门槛文案与 `module_required` 协议不变。
- **免杀 P0**：模块引擎字符串抹除（日志 `max_level_off`、XOR 常量、`strip=symbols`）；模块 ABI 导出名中性化（`x0..x3`）+ 库名去品牌（`app_rt.dll`，消除导出表 `cupcake_mod_bof.dll`/`mod_*` 特征）；运行时环境变量统一 `APP_*` 前缀；Manual-Map 后 PE 头擦除。
- **构建脚本**：`server/scripts/build-{bof,inject,ad}-module.ps1`；新增 `pe-strip-debug.py`（抹除 RSDS/PDB/POGO 等全部调试目录残留）并接入 `strings-gate.ps1`。
- 面板：模块仓库 / 主机模块页 / 插件中心全部切换为 bof | inject | ad；iso_host 与 .NET 文案清零。

### ~~产品 BOF：回退隔离路径（iso_host）~~（已被上节推翻）

- ~~撤销「Stage0 进程内经典 BOF」实验：产品 `minimal` **不再**编入 `feature=bof`。~~
- ~~`bof_exec` 恢复为 **`run_bof_isolated` + 推送/stage `iso_host`**（与 .NET 共用宿主）。~~
- ~~服务端/面板：BOF 再次要求 `iso_host`；模块能力含 `bof`。~~

### 客户端体积：删冗余

- 产品 `minimal` **去掉 `mem-map`**：Stage0 不对 L2 Manual-Map（`pe_map` 仅可选 feature）。
- 删除遗留 crate **`modules/bof` / `modules/dotnet`**（由 `iso_host` 宿主 PE 承担引擎）。
- 拒绝 stage 旧 id `bof`/`dotnet`；清理误放的嵌套路径与构建垃圾文件。

### iso_host BOF：PPID 管道句柄 + EDR/ghost 秒杀修复（WriteFile failed）

- **现象**：`iso_host` 推送成功（仅缓存宿主 PE，非常驻进程），打 BOF 报 `[STDERR] isolated bof: WriteFile failed err=109`；`exit_code=0xC0000005`（ACCESS_VIOLATION）；防火墙提示「非常规方式执行程序」。
- **根因 1**：`PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` / `NtCreateProcessEx(ParentProcess=spoof)` 时，子进程从**伪装父进程**继承句柄，而非 Agent；Agent 本地 pipe 句柄无效 → 断管。
- **根因 2**：默认优先 **process-ghost / NtCreateProcessEx 零盘拉起**，EDR 判定非常规执行并拦截/致宿主 AV 崩溃。
- **修复**：
  - `spawn.rs`：PPID CreateProcess 前将 stdin/stdout **DuplicateHandle 进伪装父进程**；ghost 路径将 pipe **注入子进程**。
  - `isolated_exec.rs`：**默认关闭 ghost**（`CUPCAKE_GHOST_HOST=1` 才启用）；优先常规 temp + CreateProcess；WriteFile/秒退后 **自动 plain 重试**（无 PPID）；退出码格式化为 `0xC0000005 STATUS_ACCESS_VIOLATION`。
- **宿主落盘策略**：BOF 体仍不落盘；仅 `iso_host` 宿主 EXE 短暂落盘。默认优先 **`%TEMP%` + `.exe`**，多路径回退；避免 `INetCache\~DF*.tmp`（易被 CreateProcess `err=5 ACCESS_DENIED`）。

### MCP 写权限 + Web 面板确认

- **默认只读**：`mcp_read_only=true` 时 MCP 仅可查询。
- **凡增删改均需面板确认**：关闭只读后，MCP 的 POST/PUT/DELETE 一律进入 `mcp_pending_requests`；管理员在面板顶部「MCP 确认」批准后才下发。
- **确认摘要写明用途**：含完整 Shell 命令原文、AD op/参数、目标 agent。
- 控制面（settings/users/maintenance/generate）仍不对 MCP 开放。
- API：`GET/POST /api/mcp/pending`（列表/详情/approve/deny）。
- MCPClient：`ad_exec` / `ad_discover` / `ad_ping` / `push_module` / `wait_mcp_pending`；写操作自动轮询等待批准。

---

## [4.1.0] — 2026-08-09

**BOF 预览版 — 模块体系 v2 重构**

本版是一次**模块体系大版本重构**，在 4.0.0 的产品化基础上将模块系统从"实验性并行"推进到"三层分工明确"的架构。

### 模块体系 v2：经典 BOF + 隔离 worker

- **BOF 引擎产品化**：`iso_host` 退役，`bof` 转为 **Agent 进程内经典 BOF**（Manual-Map 无文件落地、无新进程、按需加载）。Agent 落地不带 Beacon\*/BOF 引擎特征。
- **.NET 退役**：`execute_assembly` / `dotnet` 整体移除；程序集请转 shellcode（如 Donut）后走 `inject` 模块。
- **Desktop 退役**：`desktop_worker` / `desktop_bridge` / `rdp_enable` 移除；远程桌面改由 L2 端口转发 + 独立路径。
- **inject 保持进程隔离**：重构为纯 `main.rs` 入口，lib.rs 移除；一次性牺牲 worker EXE，Job Object 生命周期。
- **AD 模块全新**（`modules/ad`）：取代旧 .NET CLR 路径，原生 Rust 实现，9 个源文件：
  - Tier0 域发现 / LDAP 枚举 / 安全策略查询
  - Kerberoast / AS-REP Roast 带 hashcat 格式输出
  - 域图采集 / ACL 采集
  - DCSync（`ad-dcsync` feature 门控，默认关闭）
- **模块白名单**：服务端产品模块仅 `bof | inject | ad`；旧 id（dotnet/iso_host）返回退役指引。

### 免杀 / OPSEC 加固

- 模块引擎字符串抹除（`max_level_off`、XOR 常量、`strip=symbols`）
- ABI 导出名中性化（`x0..x3`）、库名去品牌（`app_rt.dll`）
- 运行时环境变量统一 `APP_*` 前缀
- Manual-Map 后 PE 头擦除（`release_carrier_mapping` 清零 + NtUnmapViewOfSection）
- 新增 `pe-strip-debug.py`（抹除 RSDS/PDB/POGO 全部调试目录残留）
- 集成 `strings-gate.ps1` 构建门禁
- 符号解析缓存 + 常见 DLL 兜底解析

### 构建与部署

- 构建脚本：`server/scripts/build-{bof,inject,ad}-module.ps1`
- 产品 `minimal` 移除 `mem-map` 依赖（Stage0 不对 L2 Manual-Map）
- 拒绝 stage 旧 id `bof`/`dotnet`；清理误放嵌套路径与构建垃圾文件

### MCP 写权限 + 面板确认

- 默认只读：`mcp_read_only=true` 时 MCP 仅可查询
- 凡增删改均需面板确认：关闭只读后 MCP 写操作进入 `mcp_pending_requests` 队列，管理员批准后才下发
- 确认摘要写明用途（含完整命令/参数/目标 agent）
- API：`GET/POST /api/mcp/pending`（列表/详情/approve/deny）
- MCPClient 新增：`ad_exec` / `ad_discover` / `ad_ping` / `push_module` / `wait_mcp_pending`

### 服务器端重构

- 模块控制器（`module_controller.go`）重构：产品 worker 注册路径
- 插件服务（`plugin_service.go`）重构：SHA-256 部署校验 + 信任链
- 客户端服务（`client_service.go`）重构：模块能力路由
- 前端模块/插件/面板页面同步更新

---

## [4.0.0] — 2026-08-05

**对比基线：`v3.0.5`**

本版是一次 **产品级大版本**，在远程桌面、文件传输、模块信任链、面板安全边界与运维可观测性上相对 3.0.5 做了系统性加固与能力升级。  
本地仓库根目录 `VERSION` = `4.0.0`；Git 标签 **`v4.0.0`**。

### 摘要（相对 v3.0.5 你得到了什么）

| 领域 | v3.0.5 痛点 / 现状 | v4.0.0 修复与改进 |
|------|-------------------|-------------------|
| 大文件上传 | 控制面分块 / base64 易超时、难背压 | Yamux **FILE `0x0E`** 二进制流；`.cupcake.part` 暂存 + 成功后原子 rename；Windows 错误路径 **先关句柄再删 part** |
| 远程桌面 | 能力偏弱 / 易拖垮会话 | L2 desktop 路径完善；RDP 端口转发；默认监听 **loopback**；双向 **idle 超时**；可选 **desktop_worker** 进程隔离（Job Object） |
| 模块 / 插件信任 | 弱校验 / 易被替换 | **HMAC trustchain** + 版本防回滚；插件 **SHA-256** 部署前校验（空 hash 默认拒绝） |
| 面板权限 | 角色边界不清晰 | 完整 **viewer / operator / admin** 路由 RBAC；高危写操作收紧 |
| MCP | 默认 token / 黑名单易误开 | **fail-closed** 白名单；默认只读；审计日志；客户端强制 `C2_API_TOKEN` |
| 公开 Stager | 可被扫、可被刷 | **IP 限速 / 命中次数 / TTL / 审计**（`pkg/stagerguard`） |
| Worker 稳定性 | 管道堵死、输出无界 | Job Object 资源上限；stdout 先读后等；输出 2MiB 封顶；会话退出 `stop_all` |
| 传输安全 | 缺 key 仍可能明文/半开 | Noise PSK **强制**；session crypto 拒绝空 key |
| 运维 | 缺少健康/指标 | `/health`、`/api/metrics`；任务日志保留清理；磁盘配额与上传上限 |
| 仓库卫生 | 本地 `config.json` 易带密码进库 | **停止跟踪** `server/config.json`，改用 `config.example.json` |

---

### 新增功能

#### 文件传输（FILE 流）

- 新增协议 **Yamux stream type `0x0E`（FILE）**，服务端与 agent 对称实现：
  - 客户端：`Client/core/src/file_stream.rs`
  - 服务端：`server/pkg/utils/file_stream.go` + `UploadViaYamux` / `OpenDownloadViaYamux`
- **Put（面板 → agent）**：`chunk_len(u32 BE) + data`，`chunk_len=0` 表示 EOF；写入 `path.cupcake.part`，成功后 rename 为最终路径。
- **Get（agent → 面板）**：status + size + 原始文件体。
- 控制面 `file_upload_chunk` 对 TCP/Yamux agent **降级为兜底**；主路径为二进制流。
- 大文件上传相关 admin HTTP：`ReadTimeout/WriteTimeout` 对长连接场景已做产品侧对齐（见 hardening 文档）。

#### 远程桌面 / RDP

- 完善 **L2 desktop** 模块与面板 Remote Desktop 流程。
- **RDP 端口转发**（agent → 目标 3389 via SOCKS/yamux DESKTOP `0x0D`）。
- Agent 侧 `desktop_bridge`：**120s 读空闲超时**，避免半开连接挂死。
- Server 侧：pipe 两端 idle deadline；**每 agent 并发连接上限**；默认 **`127.0.0.1` 监听**（`CUPCAKE_DESKTOP_LISTEN_HOST` 可覆盖）。
- 新增 **desktop_worker** 骨架与 opt-in 路径（`CUPCAKE_DESKTOP_WORKER=1`）；失败可回退 in-process bridge，避免回归。
- 辅助能力：`rdp_enable` 等启用/探测相关逻辑。

#### 模块 / 插件信任

- `pkg/trustchain`：对 module 元数据做 **HMAC-SHA256** 规范串签名校验。
- **版本防回滚**（`RollbackGuard`）：拒绝低于已发布版本的包。
- 插件上传记录 SHA-256；`DeployPlugin` 前 **VerifyPluginHash**；空 hash 默认 fail-closed（实验室迁移：`CUPCAKE_ALLOW_LEGACY_PLUGIN_HASH=1`）。

#### 安全与权限

- **Origin 严格校验**（CORS / WS）：按 scheme/host/port 解析，拒绝畸形与恶意子域。
- **MCP**：
  - 端点 **显式白名单** + 读/写能力；默认只读。
  - 高危写（文件删/传、杀进程、插件/模块推送、隧道等）**移出 allowlist**。
  - MCP 拒绝/放行写入审计日志。
  - MCPClient 取消硬编码 token，缺 `C2_API_TOKEN` 直接启动失败；command_guard 不可通过配置关闭。
- **RBAC**：viewer / operator / admin 路由矩阵（命令、文件、隧道、模块、生成器等分层）。
- 改密后 **会话 token 轮换**，旧 token 立即失效。
- 公开 **stager** 路径：每 IP 限速、每 id 最大下载次数、审计事件。

#### Worker / 进程隔离

- iso_host / inject 路径：stdout **先读线程再 Wait**，修复管道满导致的死锁。
- 输出 **有界读取**（默认 2MiB），超限杀 Job/进程。
- Job Object：**fail-closed**（限配失败则不创建“裸”job）；进程数 / 内存 / CPU 时间上限；kill-on-close。
- Agent 会话结束与自毁前 **`module_supervisor.stop_all()`**。

#### 运维与工程

- 健康检查：`health_controller`。
- 管理端指标：`/api/metrics`（JSON，非 Prometheus 全文生态）。
- 磁盘配额 / 上传体积门禁 / agent UUID 校验。
- 任务日志按天保留清理（默认 7 天）。
- WebSocket 短期 **ticket** 鉴权（PTY/shell/build logs 等升级路径）。
- GitHub Actions CI（`go vet` / `go test -tags nodonut` 等）。
- 文档：`SECURITY_HARDENING.md`、`MODULE_WORKER_ISOLATION.md`、`DESKTOP_MODULE_DESIGN.md`、`POSTEX_WORKLIST.md` 同步。

---

### 修复（相对 v3.0.5 / 早期 0.0.x 线）

- **文件上传中断 / 失败后 `.part` 残留（Windows）**：错误分支必须 **先 `drop(file)` 关闭句柄**，再 `remove_file`；否则句柄占用导致删除失败。
- **文件上传易失败 / 控制面超时**：主路径改为 yamux 二进制 FILE 流，减少 base64 膨胀与控制面挤占。
- **Inject/iso_host 大输出卡死**：修复 Wait 前未消费 stdout 的死锁。
- **Desktop / RDP 半开连接**：agent 与 server 双侧 idle 超时，避免 ESTABLISHED 僵尸占用。
- **缺 Noise key 仍建连**：TCP/WS/bind 在无 PSK 时拒绝建立会话。
- **Bind 地址被强改 0.0.0.0**：保留配置 host；仅端口时默认 loopback。
- **MCP / 面板权限过宽**：白名单 + RBAC + 高危写隔离。
- **Stager 被扫刷**：限速、命中上限、过期删除。
- **插件可被同名脏文件替换**：部署前 hash 校验。
- **改密后旧 token 仍可用**：强制轮换。
- **仓库泄露本地管理员口令风险**：不再提交 `server/config.json`。

---

### 破坏性变更 / 迁移注意

1. **MCP**：必须配置有效 `C2_API_TOKEN`；默认只读且 allowlist 更严——旧自动化若依赖上传/杀进程/推模块，需改走面板 admin 或收紧后的策略。
2. **插件**：无 hash 的旧记录默认不可部署，实验室需设 `CUPCAKE_ALLOW_LEGACY_PLUGIN_HASH=1` 或重新上传插件。
3. **模块包**：需符合 trustchain 签名与版本规则，低版本包会被拒。
4. **大文件上传**：TCP agent 依赖 Yamux FILE；无 Yamux 的 WS/DNS 仍可能走控制面分块兜底（能力与稳定性不同）。
5. **Desktop 监听**：默认仅本机 `127.0.0.1`，需要远端连 mstsc 时显式设置 `CUPCAKE_DESKTOP_LISTEN_HOST`。
6. **配置**：从 `config.example.json` 复制为本地 `config.json`，勿把真实口令提交回仓库。
7. **Agent 与 Server 需配套**：`CUPCAKE_WIRE_SEED` / AES / Noise 参数必须与 agent 构建一致。

---

### 已知问题（不阻塞 4.0.0，后续单独修）

- **上传失败后 yamux 流关闭，agent 读端偶发感知不到 FIN**（连接仍 ESTABLISHED、`.part` 可能残留）：与 Go `hashicorp/yamux` v0.1.2 关流语义 / agent 侧无读超时兜底相关。  
  **建议后续**：agent put 循环加 idle 读超时；或 server 失败路径更明确收尾（慎用整会话掐 TCP）。

---

### 版本引用

| 项 | 值 |
|----|-----|
| 标签 | `v4.0.0` |
| 对比 | `v3.0.5` → `v4.0.0` |
| 仓库 | https://github.com/yellatiamo/CupcakeC2 |

---

## [3.0.5] — 基线

产品仓库历史标签 **`v3.0.5`** 作为 4.0.0 的对比基线。  
4.0.0 在能力与安全边界上属于跨代升级；详细 diff 以本仓库 `v4.0.0` 树与上文条目为准。
