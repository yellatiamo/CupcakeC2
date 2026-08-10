# 后利用能力 — 完整工作清单

> 目标：说清楚 **功能放哪**（Stage0 / L2 模块 / 插件 / 构建工具）、**怎么验收**、**怎样算完成**。  
> 状态：规划 + 验收标准  
> 更新：2026-08-04

---

## 目录

1. [三层分工（先读这个）](#1-三层分工先读这个)
2. [归属决策树](#2-归属决策树)
3. [功能归属总表](#3-功能归属总表)
4. [模块 / 插件职责说明书](#4-模块--插件职责说明书)
5. [现在 vs 目标架构](#5-现在-vs-目标架构)
6. [分阶段工作与验收](#6-分阶段工作与验收)
7. [全局「完成」定义](#7-全局完成定义)
8. [回归门禁（每次改后利用必过）](#8-回归门禁每次改后利用必过)
9. [决策记录](#9-决策记录)

---

## 1. 三层分工（先读这个）

Cupcake 故意 **不把一切塞进 agent**。后利用分三层：

| 层级 | 是什么 | 谁推送 | 生命周期 | 适合放什么 |
|------|--------|--------|----------|------------|
| **Stage0（内置）** | 常驻 agent 能力 | 无需推模块 | 一直在 | 高频、薄、稳：shell、文件、进程、PTY、SOCKS |
| **L2 模块** | 产品能力包（白名单 id） | 模块页上传 + 推到 agent | 按需 Loaded / 可卸 | 有独立命令、可复用的「引擎/能力」：inject、bof、dotnet、token… |
| **插件（Plugin）** | 仓库里的 **载荷文件** | 插件库上传，对某 agent **跑一次** | 单次任务 | 具体 BOF 文件、具体 .NET 程序集、一次性脚本产物 |

### 一句话区分「模块」和「插件」

```text
模块 = 能不能干这类事（引擎 / 开关）
插件 = 这次具体跑哪个文件（载荷）

例：
  模块 bof     → 有了「跑 COFF」的能力
  插件 whoami.o → 用 bof 引擎执行的这一份 COFF

  模块 dotnet  → 有了「跑程序集」的能力
  插件 Seatbelt.exe → 用 dotnet 引擎执行的这一份程序集
```

### 还有第四类：构建 / 交付工具（不进 agent 白名单）

| 类型 | 例子 | 放哪 |
|------|------|------|
| Builder | 生成 agent | Server 生成器 |
| Crypter / Loader | 加密 agent、内存映射上线 | `tools/crypter` 或独立目录（**不是** L2 模块） |
| 短命宿主 PE | 实际跑 BOF/.NET 的子进程 | 运行时文件（方案 A 可共用 `iso_host` 宿主） |

---

## 2. 归属决策树

遇到一个新功能，按顺序问：

```text
1) 是否几乎每个会话都要用，且实现很薄？
   是 → Stage0 内置
   否 ↓

2) 是否是「一类能力的引擎/开关」（有固定 command_type，可反复用）？
   是 → L2 产品模块（进白名单，可推送、可签名、可 module_required）
   否 ↓

3) 是否是「某一次任务用的具体文件/脚本」（.o / .exe 程序集 / 一次性 PE）？
   是 → 插件库（Plugin），依赖对应 L2 引擎模块已 Loaded
   否 ↓

4) 是否只在「生成 payload / 打包上线」时用？
   是 → 构建工具（crypter/stager），不进 agent 模块表
   否 → 重新定义需求（可能是服务端功能，如隧道监听）
```

### 禁止事项（避免职责糊掉）

| 不要 | 原因 |
|------|------|
| 把 Seatbelt 做成 L2 模块 id | 那是载荷，不是引擎 → **插件** |
| 把「跑任意 BOF」做成插件系统本身 | 引擎必须稳定、可门禁 → **模块 `bof`** |
| 把 SOCKS 做成插件 | 高频网络面，应 **Stage0** |
| 把 Kerberoast 只塞进 Stage0 | 域攻击面大、不该撑大常驻体积 → **L2 或 插件+bof** |
| 一个模块 id 同时表示「能力」和「某工具名」 | 面板与 `module_required` 会乱 |

### 域攻击特例：两阶段归属

| 阶段 | 归属 | 说明 |
|------|------|------|
| **MVP** | 插件（标准 BOF）+ 模块 `bof` | 先能用、能验收 hash 输出 |
| **产品化** | L2 模块 `ad` + 面板一等命令 | 固定参数表单、结果入库、导出格式稳定 |

**完成产品化之前**，不得宣称「已有 Kerberoast 模块」——只能写「可通过 bof 插件执行」。

---

## 3. 功能归属总表

图例：

- **Stage0** = 内置  
- **L2:`id`** = 产品模块  
- **Plugin** = 插件载荷（依赖括号内引擎）  
- **Server** = 仅服务端 / 控制面  
- **Tool** = 离线/构建工具  
- **—** = 不做或未排期  

| 功能 | 归属 | 依赖 | 主要命令 / 入口 | 阶段 |
|------|------|------|-----------------|------|
| Shell / 交互 PTY | Stage0 | — | `shell` / PTY WS | 已有 |
| 文件管理 | Stage0 | — | `file_*` | 已有 |
| 进程列表/结束 | Stage0 | — | `process_*` | 已有 |
| SOCKS5 | Stage0 + Server | Yamux | 隧道页 SOCKS | 已有 |
| BOF/COFF **引擎** | L2:`bof` | 短命宿主 | `bof_exec` | **P0 拆分** |
| 具体 BOF 文件 | Plugin（依赖 `bof`） | `bof` Loaded | 插件运行 | 已有形态 |
| .NET **引擎** | L2:`dotnet` | 短命宿主 | `execute_assembly` | **P0 拆分** |
| 具体程序集 | Plugin（依赖 `dotnet`） | `dotnet` Loaded | 插件运行 | 已有形态 |
| 进程注入 **引擎** | L2:`inject` | 可选宿主 KIND_INJECT | `process_inject` | 已有 |
| 注入用 shellcode 文件 | Plugin 或命令 body base64 | `inject` | 命令/插件 | 已有 |
| 反向端口转发 | Stage0 + Server | Yamux 新/扩展 | 隧道页 rportfwd | **P1** |
| Token 窃取/冒充 | L2:`token` | 权限 | `steal_token` 等 | **P2** |
| getsystem | L2:`token` | — | `getsystem` | **P2** |
| LSASS dump | L2:`cred` | 高权限 | `lsass_dump` | **P3** |
| SAM/SYSTEM 备份 | L2:`cred`（二期） | SeBackup | `sam_dump` | P3 二期 |
| Kerberoast | MVP: Plugin+`bof`；产品: L2:`ad` | 域环境 | `kerberoast` / 插件 | **P4** |
| AS-REP roast | 同上 | 域环境 | `asrep_roast` / 插件 | **P4** |
| WMI 横向 | L2:`lateral` | 凭据/令牌 | `wmi_exec` | **P5** |
| EarlyBird / 劫持等 | L2:`inject` 扩 method | — | `process_inject` method | **P6** |
| Agent 加密壳 / 反射加载 | Tool:`crypter` | — | 构建流水线 | **P7** |
| 截图（GDI） | — 或不做 | — | — | 非目标 |
| SMB named pipe 通道 | —（通道层另立） | — | — | 非本清单后利用焦点 |

---

## 4. 模块 / 插件职责说明书

### 4.1 Stage0（常驻，无模块 id）

| 负责 | 不负责 |
|------|--------|
| 上线、心跳、加解密、Yamux | BOF 解析执行 |
| shell / PTY / fs / process | .NET CLR 宿主 |
| SOCKS 数据面 | LSASS / 域攻击 |
| 模块门禁与 spawn 短命宿主 | 具体插件文件存储 |

**算完成（Stage0 维护）：** 不推任何 L2 时，shell/文件/进程/PTY/SOCKS 仍全部可用；回归门禁 §8 全绿。

---

### 4.2 L2:`bof`（从 iso_host 拆出）

| 项 | 内容 |
|----|------|
| **是什么** | **BOF/COFF 执行引擎** 的能力包（Loaded 后才允许 `bof_exec`） |
| **不是什么** | 不是某一个具体 `.o`；不是 .NET |
| **命令** | `bof_exec`（及插件路径最终落到同一引擎） |
| **插件关系** | 插件类型 = COFF/BOF → 必须 `bof` Loaded |
| **宿主** | 方案 A：短命进程 KIND_BOF；方案 B：专用 bof_host |
| **完成标准** | 见 §6.P0 |

---

### 4.4 L2:`dotnet`（从 iso_host 拆出）

| 项 | 内容 |
|----|------|
| **是什么** | **.NET 程序集内存执行引擎** 能力包 |
| **不是什么** | 不是某一个工具 exe 的名字；不是 BOF |
| **命令** | `execute_assembly` / `dotnet` |
| **插件关系** | 插件类型 = .NET → 必须 `dotnet` Loaded |
| **完成标准** | 见 §6.P0 |

---

### 4.5 L2:`inject`

| 项 | 内容 |
|----|------|
| **是什么** | 远程进程 shellcode 注入引擎 |
| **不是什么** | 不是 shellcode 仓库（shellcode 来自命令 JSON 或插件） |
| **命令** | `process_inject` / `shellcode_inject`；method=`nt|crt|apc|stomping|auto`（P6 扩展） |
| **完成标准** | 见 §6.P-inject / P6 |

---

### 4.6 L2:`token`（规划）

| 项 | 内容 |
|----|------|
| **是什么** | Windows 访问令牌操作引擎 |
| **命令（最低集）** | `steal_token`、`make_token`、`rev2self`、`getsystem`（≥1 种实现） |
| **不是什么** | 不是凭证离线破解；不是 LSASS dump |
| **完成标准** | 见 §6.P2 |

---

### 4.7 L2:`cred`（规划）

| 项 | 内容 |
|----|------|
| **是什么** | 主机凭证材料采集（dump 文件回传） |
| **命令（MVP）** | `lsass_dump` → 回传 minidump 类文件 |
| **不是什么** | 不在 agent 内跑 mimikatz 全功能交互；不把明文密码打进日志 |
| **完成标准** | 见 §6.P3 |

---

### 4.8 L2:`ad`（B0 脚手架已落地：白名单/门禁/worker ping；烤票/DCSync 未实现，见 `docs/AD_MODULE_DESIGN.md`）

| 项 | 内容 |
|----|------|
| **是什么** | 域协议类攻击与态势的一等命令封装（**独立 sacrificial worker PE**，Stage0 不装 LDAP/烤票） |
| **命令（分阶段）** | **P4-b.0（已落地）：** 白名单 upload/push、`module_required:ad`、worker `ping` 探针、`execute_ad_job` + JSON 帧 + HMAC 信任；**P4-b.1：** `ad_discover`、`ad_ldap_query`、`ad_enum_*`、`ad_password_policy`…；**P4-b.2：** `kerberoast`、`asrep_roast`；**P4-b.3：** `ad_graph_collect`、`ad_acl_collect`；**P4-b.4：** `dcsync`、`ad_check_replication_rights`（发行默认 feature 剥离） |
| **MVP 替代** | 未完成 P4-b 前用 **Plugin + bof/dotnet（当前产品路径常为 iso_host）**，标注「过渡」 |
| **完成标准** | 见 §6.P4；**详设与 hashcat/LDAP 规格** → `docs/AD_MODULE_DESIGN.md` |
| **话术** | 脚手架 / 门禁就绪 **≠**「ad 模块已完成」；B0–B2 全过才可写「L2 ad：域枚举 + Kerberoast / AS-REP」 |

---

### 4.9 L2:`lateral`（规划）

| 项 | 内容 |
|----|------|
| **是什么** | 横向移动引擎（首期 WMI） |
| **命令** | `wmi_exec`（目标、命令行、可选用户/域/密码或沿用 token） |
| **不是什么** | 不是 SMB 通道本身 |
| **完成标准** | 见 §6.P5 |

---

### 4.10 插件系统（Plugin）

| 项 | 内容 |
|----|------|
| **是什么** | 服务端插件库中的 **文件 + 元数据**；对指定 agent **部署执行一次** |
| **类型检测** | COFF → 走 bof 引擎；.NET → 走 dotnet 引擎；其它按策略拒绝或 shell |
| **依赖** | 执行前 agent 上对应 L2 必须 Loaded，否则 `module_required:*` 并提示推送 |
| **放什么** | 具体工具：Seatbelt、Rubeus 编译产物、自定义 BOF、内网探测程序集 |
| **不放什么** | 不把「引擎」当插件上传；不把 Stage0 功能改成插件 |

**插件算完成（单条）：**

1. 上传成功，清单可见，类型识别正确  
2. 目标 agent 已推对应模块  
3. 运行返回 stdout/stderr 或明确错误  
4. 结果可在任务/插件结果接口查到  
5. 信任策略：签名缺失时 lab 环境可配，生产 fail-closed（与现网策略一致）

---

### 4.11 Server 控制面（非 agent 模块）

| 功能 | 说明 | 完成要点 |
|------|------|----------|
| 模块上传/推送/信任签名 | `storage/modules`、`*.trust.json` | 白名单 id 可推、可签 |
| SOCKS/隧道监听 | 绑定 C2 端口，转发到 agent | 列表/启停/权限 |
| rportfwd（P1） | 通用端口映射 | 见 P1 验收 |
| 插件库 CRUD | plugins API | 见插件完成 |

---

### 4.12 Tool：crypter（P7）

| 项 | 内容 |
|----|------|
| **是什么** | 生成「加载器 + 加密 agent」的离线/半自动工具 |
| **不是** | 不是上线后的后利用模块 |
| **完成** | 见 §6.P7 |

---

## 5. 现在 vs 目标架构

### 现在（问题）

```text
推 iso_host ──► 一个产品模块同时 = BOF 引擎 + .NET 引擎 + inject 宿主
插件/命令 ──► bof_exec 与 execute_assembly 都 module_required:iso_host
```

### 目标

```text
Stage0 ──门禁──► bof Loaded?  ──spawn KIND_BOF──► 宿主进程执行 COFF
              └► dotnet Loaded? ──spawn KIND_DOTNET──► 宿主进程执行程序集
              └► inject Loaded? ──spawn KIND_INJECT──► 宿主进程注入

插件库 ──(类型)──► 选引擎模块 ──同一套 bof_exec / execute_assembly
```

**方案 A（P0 推荐）：** 宿主 PE 仍可共用；**产品 id 与门禁必须拆开**。  
**方案 B（后期）：** 双宿主 PE，进一步减耦合。

| 模块 id | 操作员含义 | 推送后 |
|---------|------------|--------|
| `bof` | 能跑 BOF | 仅 `bof_exec` / BOF 类插件 |
| `dotnet` | 能跑程序集 | 仅 `execute_assembly` / .NET 类插件 |
| `inject` | 能注入 | `process_inject` |
| `iso_host` | 兼容期可选：runtime 宿主文件名 | 宿主 PE |

---

## 6. 分阶段工作与验收

> 每阶段都有：**范围**、**任务勾选**、**怎么测**、**完成定义（DoD）**。  
> **未达到 DoD = 该阶段未完成**，不得在对外说明里写「已支持」。

---

### 通用 DoD 模板（所有阶段套用）

阶段标记 **Done** 必须同时满足：

1. **代码**：合并到主开发分支，无已知阻塞 bug  
2. **测试**：本节「必测」全过（自动和/或书面手工记录）  
3. **文档**：操作步骤 + 归属表已更新（本文件或 OPSEC_DEPLOY）  
4. **面板**：若承诺有 UI，则入口可用且错误提示可读  
5. **安全默认**：模块信任 / 鉴权与现网 fail-closed 策略不回退  
6. **回归**：§8 回归门禁全过  

---

### P-baseline — 已有能力（维护基线）

**范围：** shell、PTY、文件、进程、SOCKS、inject 四法、iso_host 二合一（拆分前）、插件上传运行。

| 功能 | 怎么验收 | 算完成 |
|------|----------|--------|
| Shell | 非交互命令返回 stdout；错误进 stderr | 稳定回传、无卡死 agent |
| PTY | Web 终端可交互，断线可清 | ticket/鉴权有效 |
| 文件 | 列表/上传/下载小文件 | 与权限一致 |
| SOCKS | 浏览器/工具走代理访问内网 HTTP | 启停干净 |
| inject | 对测试进程 method=nt/crt/apc/stomping 之一成功 | 返回 method 与 pid |
| 插件 | 上传 BOF 或 .NET，在已推引擎模块的 agent 上跑通 | 有 task 结果 |

**基线失败：** 任一「已有」在改 P0+ 后回归失败 → **阻塞发布**。

---

### P0 — 拆分 `bof` / `dotnet` 模块

#### 范围

- 产品白名单：`inject | iso_host`（+ 规划中的 bof/dotnet 拆分）  
- 命令门禁分离  
- 前端上传/推送分两项  
- 插件提示指向正确模块  

#### 任务

**设计**

- [ ] D1 选定方案 A 或 B  
- [ ] D2 白名单与兼容策略写进决策表 §9  
- [ ] D3 宿主 PE 从哪来（共享文件名 / 随模块附带）写死  

**Agent**

- [ ] A1 `bof_exec` → 模块 `bof`；`execute_assembly` → 模块 `dotnet`  
- [ ] A2 product worker 列表含 `bof`、`dotnet`  
- [ ] A3 `module_required:bof` / `module_required:dotnet` 文案正确  
- [ ] A4 只 Loaded 其中一个时，另一个命令必须失败  
- [ ] A5 inject 依赖关系不回归  
- [ ] A6 单元测试覆盖门禁矩阵  

**Server / 前端 / 文档**

- [ ] S1–S6 白名单、Describe、API 文案、插件提示  
- [ ] F1–F4 模块管理与客户端面板  
- [ ] Doc 更新 CLIENT_SIZE_PROFILES、MODULE_WORKER_ISOLATION、OPSEC_DEPLOY  

#### 怎么验收（必测矩阵）

| # | 前置 | 操作 | 期望 |
|---|------|------|------|
| P0-1 | 仅推 `bof` | `bof_exec` 简单 BOF（如输出固定字符串） | 成功，stdout 符合 |
| P0-2 | 仅推 `bof` | `execute_assembly` | 失败，提示需 `dotnet`（非 iso_host） |
| P0-3 | 仅推 `dotnet` | `execute_assembly` 最小程序集 | 成功 |
| P0-4 | 仅推 `dotnet` | `bof_exec` | 失败，提示需 `bof` |
| P0-5 | 两者都推 | 两种命令各一次 | 都成功 |
| P0-6 | 未推模块 | 插件跑 COFF | `module_required:bof` 或等价 |
| P0-7 | 未推模块 | 插件跑 .NET | `module_required:dotnet` |
| P0-8 | 推 bof 后 force 只卸/重推逻辑 | 互不影响 dotnet 状态 | 状态机正确 |
| P0-9 | BOF 宿主故意崩溃 | Stage0 心跳 / 新 shell | agent 仍在 |
| P0-10 | 上传 `bof.bin`/`dotnet.bin` | trust 侧车 | 有签名或 lab 策略明确 |

#### P0 完成定义（Done）

- [ ] 上表 P0-1～P0-10 **全部通过**（附测试记录或 CI）  
- [ ] 面板可分别上传并推送 `bof`、`dotnet`  
- [ ] 文档不再写「BOF/.NET 都推 iso_host」作为唯一路径  
- [ ] 对外说明可写：**「BOF 与 .NET 为两个独立 L2 模块」**  
- [ ] §8 回归全过  

**未完成示例：** 代码已分路由但面板仍只显示 iso_host；或仍只推 iso_host 才能跑——**不算 Done**。

---

### P1 — 通用反向端口转发（rportfwd）

#### 归属

- **数据面：** Stage0 + Yamux（或明确扩展）  
- **控制面：** Server 隧道 API + 前端  
- **不是** L2 模块，**不是** 插件  

#### 任务

- [ ] N1 协议一页纸（与 SOCKS 边界）  
- [ ] N2 Agent 中继  
- [ ] N3 Server 监听/会话表  
- [ ] N4 UI 创建/列表/停止  
- [ ] N5 与 SOCKS 并存  

#### 怎么验收

| # | 场景 | 期望 |
|---|------|------|
| P1-1 | C2 `127.0.0.1:L` → agent 拨 `127.0.0.1:某本地服务` | 从操作机连 L 等价访问该服务 |
| P1-2 | 指向 agent 可达的内网 `host:port` | 同上 |
| P1-3 | Stop 规则 | 端口释放，无残留监听 |
| P1-4 | Agent 掉线 | 会话结束，错误可感知 |
| P1-5 | 与 SOCKS 同时开 | 互不打死 |

#### P1 Done

- [ ] P1-1～P1-5 通过  
- [ ] 文档写清与「仅 SOCKS」的区别  
- [ ] 可对外写：**「支持通用反向/端口转发（rportfwd）」**  

**未完成：** 只有 SOCKS 能间接达到类似效果——**不能**宣传为 rportfwd Done。

---

### P2 — L2:`token`

#### 归属

- **模块 `token`**，不是插件  
- 具体「提权脚本」若只是一次性实验 → 可用插件，但 **产品能力** 以模块命令为准  

#### 最低命令集（MVP）

| 命令 | 必做 | 验收要点 |
|------|------|----------|
| `steal_token` | 是 | 指定 PID，后续 shell 以该用户上下文执行（可验证 whoami） |
| `rev2self` | 是 | 恢复至原始令牌，whoami 还原 |
| `make_token` | 建议 | 用户名/域/密码创建令牌 |
| `getsystem` | ≥1 种 | 成功后 whoami 含 SYSTEM（或明确失败原因） |

#### 怎么验收

| # | 步骤 | 期望 |
|---|------|------|
| P2-1 | 推 `token` | Loaded |
| P2-2 | 未推时 steal | `module_required:token` |
| P2-3 | steal 高权限进程（授权环境） | whoami 变化 |
| P2-4 | rev2self | whoami 恢复 |
| P2-5 | getsystem 一种路径 | SYSTEM 或可解释错误（权限不足） |

#### P2 Done

- [ ] MVP 命令中 **steal + rev2self** 必过；getsystem 至少一种  
- [ ] 结果里可区分「当前模拟身份」  
- [ ] 文档列出权限前提（SeDebugPrivilege 等）  
- [ ] 可对外写：**「支持令牌窃取与还原（L2 token）」**  

---

### P3 — L2:`cred`（LSASS）

#### 归属

- **模块 `cred`**  
- dump **文件**走文件回传，不把明文密码打进 C2 日志  

#### 怎么验收

| # | 步骤 | 期望 |
|---|------|------|
| P3-1 | 推 `cred`，高权限 agent | `lsass_dump` 返回文件或可下载路径 |
| P3-2 | 本地用合法工具打开 dump（授权） | 文件完整、非 0 字节 |
| P3-3 | 无权限账户 | 明确错误，agent 不崩 |
| P3-4 | 日志/任务输出 | 无明文密码字段 |

#### P3 Done

- [ ] P3-1～P3-4 通过  
- [ ] 可对外写：**「支持 LSASS dump 回传（L2 cred）」**  
- [ ] **不写**「内置完整 mimikatz」除非另做  

---

### P4 — Kerberoast / AS-REP / 域态势（扩展见 `AD_MODULE_DESIGN.md`）

#### 归属策略（强制写清）

| 里程碑 | 归属 | 对外话术 |
|--------|------|----------|
| **P4-a MVP** | Plugin（BOF/程序集）+ 已 Loaded 的 `bof`/`dotnet`（产品路径常为 `iso_host`） | 「可用插件完成 roast」 |
| **P4-b 产品** | L2:`ad` 一等命令 + 面板表单 + 结果导出（分 B0–B4） | B0–B2 全过才可写「L2 ad：域枚举 + Kerberoast / AS-REP」 |

**hashcat 金标准（与 Prior Art 对齐，详设）：**

- Kerberoast: `$krb5tgs$<etype>$*<sam>$<REALM>$<spn>*$<hex16>$<hexrest>`  
- AS-REP: `$krb5asrep$23$<sam>@<REALM>$<hex16>$<hexrest>`  

#### P4-a 验收

| # | 期望 |
|---|------|
| P4a-1 | 授权域环境跑通至少一种 roast |
| P4a-2 | 输出为 hashcat/john 可识别格式或文档说明的格式 |
| P4a-3 | 操作手册：依赖哪个模块、哪个插件文件 |

#### P4-a Done

- [ ] 手册可复现；输出格式固定  
- [ ] **不可**在功能列表写「ad 模块已完成」  

#### P4-b 验收（里程碑；完整矩阵见 `AD_MODULE_DESIGN.md` § Phased Delivery）

| # | 期望 | 状态 |
|---|------|------|
| P4b-0 | 白名单 `ad` + `module_required:ad` + worker `ping`（脚手架） | **✅ B0 已落地** |
| P4b-1 | Tier0 枚举主路径 | **✅** 稳定错误码 + 域就绪时空结果壳；LDAP 深页 lab 可增强 |
| P4b-2 | kerberoast / asrep_roast + artifact 策略；日志无完整 hash dump | **✅** hashcat 格式单测 + 摘要脱敏 + storage/ad |
| P4b-3 | 结果可导出文件 / graph.zip（B3） | **✅** Cupcake graph.zip + download API |
| P4b-4 | dcsync（lab feature；发行默认剥离） | **✅** 默认 `feature_disabled`；`ad-dcsync` feature 门禁；admin+confirm |

#### P4-b Done

- [x] 对应里程碑验收表全过 + 文档（离线/格式/门禁验收；活域 lab 票证采集仍可增强）  
- [x] **B0–B2 产品路径就绪**：可写 **「L2 ad：域枚举 + Kerberoast / AS-REP（格式与管道）」**；活域票证密度依赖 lab  
- [x] **脚手架就绪不得**写「ad 模块已完成」— 仍禁止写「完整 Mimikatz / 发行含 DCSync」 |

---

### P5 — L2:`lateral`（WMI）

#### 归属

- **模块 `lateral`**  
- 目标机上的「要执行的命令」是参数，不是插件（除非远程下发文件另议）  

#### 怎么验收

| # | 期望 |
|---|------|
| P5-1 | 授权双机：WMI 远程创建进程成功 |
| P5-2 | 错误凭据 → 明确失败 |
| P5-3 | 可选：结合 token 模块后的身份 |

#### P5 Done

- [ ] P5-1～P5-2 必过  
- [ ] 可对外写：**「支持 WMI 横向（L2 lateral）」**  

---

### P6 — 注入 method 扩展

#### 归属

- **仍属 L2:`inject`**，不新建模块  
- shellcode 仍来自命令/插件  

#### 怎么验收

| method | 验收 |
|--------|------|
| 现有 nt/crt/apc/stomping | 回归不坏 |
| earlybird | 挂起记事本类进程注入成功 |
| hijack | 文档场景成功 |
| self（若做） | 本进程执行路径成功且可控 |

#### P6 Done

- [ ] 新 method 至少 1 个合并进文档与面板枚举  
- [ ] `auto` 策略文档更新（是否包含新 method）  
- [ ] 可对外写新增 method 名称  

---

### P7 — Crypter / Loader（Tool）

#### 归属

- **Tool**，不进模块白名单，不进插件库业务类型（除非单独发加载器插件，不推荐）  

#### 怎么验收

| # | 期望 |
|---|------|
| P7-1 | 输入 agent PE → 输出加载器 |
| P7-2 | 目标机跑加载器 → 内存出现 agent 并上线 |
| P7-3 | 可选 stager URL 路径打通 |
| P7-4 | 构建文档一步步可复现 |

#### P7 Done

- [ ] P7-1～P7-2、P7-4 必过  
- [ ] 可对外写：**「提供独立加密加载器（stageless）」**  

---

### P-inject（已有能力的完成线，供对照）

#### inject 算完成（当前维护线）

- [x] 四 method + auto  
- [x] L2 独立推送  
- [ ] P6 变体另计  

---

## 7. 全局「完成」定义

### 7.1 单功能完成（Definition of Done — Feature）

满足全部：

1. **归属正确**（总表 §3 一致，不混模块/插件）  
2. **门禁正确**（缺模块 → `module_required:<正确id>`）  
3. **主路径验收用例通过**（该阶段表）  
4. **失败路径可理解**（权限不足、目标离线、类型错误）  
5. **不拖死 Stage0**（子进程/超时策略符合 MODULE_WORKER_ISOLATION）  
6. **文档可操作**（谁推什么模块、点哪里、期望输出）  
7. **安全默认不回退**（信任链、RBAC）  

### 7.2 「产品对标 KHAØS 常规后利用」整包完成

仅当以下 **全部** Done：

| 能力 | 完成阶段 |
|------|----------|
| Shell / 文件 / 进程 / SOCKS | baseline |
| BOF 引擎、.NET 引擎（分模块） | P0 |
| 注入（现有 4 法） | baseline |
| rportfwd | P1 |
| Token steal/revert（+ 一种 getsystem） | P2 |
| LSASS dump | P3 |
| Kerberoast + AS-REP | P4-b（产品）或接受「仅 P4-a 插件」并在对外清单降级表述 |
| WMI 横向 | P5 |
| Crypter | P7（可选：可标「交付可选」） |

**注意：** 若 AD 只做到 P4-a，整包完成说明必须写「域攻击以插件方式提供」，**不能**勾选「ad 模块完成」。

### 7.3 版本发布标签建议

| 标签 | 含义 |
|------|------|
| `postex-p0` | bof/dotnet 拆分 Done |
| `postex-net` | P0 + P1 |
| `postex-identity` | + P2 |
| `postex-cred` | + P3 |
| `postex-full` | §7.2 全满足 |

---

## 8. 回归门禁（每次改后利用必过）

改 L2 / 插件 / 隧道 / Stage0 执行路径后，发布前：

| # | 检查 | 通过标准 |
|---|------|----------|
| R1 | Agent 上线 | TCP/WS 注册成功 |
| R2 | 无 L2 | shell `whoami` / `dir` 成功 |
| R3 | PTY | 能开能关 |
| R4 | SOCKS | 启停无残留 |
| R5 | 推 inject | 不拖垮其它命令 |
| R6 | 推 bof 后 bof_exec | 成功（P0 后） |
| R7 | 推 dotnet 后 execute_assembly | 成功（P0 后） |
| R8 | 宿主杀进程 | agent 仍心跳 |
| R9 | 模块信任 | 无签名策略与 lab 策略符合配置 |
| R10 | RBAC | viewer 不能推模块/跑危险插件（按现网角色） |

**R 任一项失败 → 禁止宣称该版本后利用增强完成。**

---

## 9. 决策记录

| 决策 | 选项 | 结论 | 日期 |
|------|------|------|------|
| P0 拆分方案 | A 共用宿主 / B 双 PE | _待定（推荐 A）_ | |
| `iso_host` 产品 id | 废弃业务名 / 仅 runtime 文件 / 长期兼容 | _待定_ | |
| bof/dotnet 交付物形态 | capability 标记 / 宿主 PE / 混合 | _待定_ | |
| 域攻击 | 先 P4-a 插件 / 直接 P4-b 模块 | **先 P4-a 手册与插件验收，并行启动 P4-b L2 `ad` 产品化；未完成 P4-b 不得宣称 ad 模块完成** | 2026-08-06 |
| L2 ad 粒度 | 单模块 / 拆 enum·cred·graph | **单模块 `ad`；体积逼近上限再拆 ad_graph** | 2026-08-06 |
| ad worker | KIND_AD on iso_host / 独立 PE | **独立 sacrificial PE（iso_host-class 隔离，非 inject KIND 模式）** | 2026-08-06 |
| rportfwd 协议 | 新 Yamux type / 扩 SOCKS | _待定_ | |
| LSASS | 仅 dump 文件 / 含在线解析 | _待定（推荐仅 dump）_ | |

---

## 10. 建议实施顺序

```text
第 1 周   P0 拆 bof / dotnet + 验收矩阵 P0-1～10
第 2 周   P1 rportfwd MVP
第 3 周   P2 token（steal + rev2self + 一种 getsystem）
第 4 周   P3 lsass_dump
并行/之后  P4-a 插件手册 → P4-b；P5 WMI；P6 method；P7 crypter
```

### P0 最小 PR（第一刀）

1. Server 白名单 + Describe：`bof`、`dotnet`  
2. Agent 命令门禁分叉  
3. 前端两项上传  
4. 测试 P0-1～P0-4  
5. 文档三处 + 本文件决策表更新  

宿主仍可共用，**不算**方案 B。

---

## 11. 一句话备忘

| 问题 | 答案 |
|------|------|
| 功能放哪？ | 引擎 → **L2 模块**；具体文件 → **插件**；常驻薄能力 → **Stage0**；打包上线 → **Tool** |
| 怎么验收？ | 每阶段 **验收表逐条测**，缺模块/失败路径也要测 |
| 怎样算完成？ | 过验收表 + 文档 + 不回归 §8 + 对外话术与归属一致 |

**先拆 bof/dotnet，再按 Token → 端口转发 → 凭证 → 域 → 横向补齐；插件永远是载荷，不是引擎。**
