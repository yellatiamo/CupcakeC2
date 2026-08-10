<template>
  <div class="control-shell" :class="{ 'control-shell--mobile-nav': isMobileNavOpen, 'control-shell--collapsed': isSidebarCollapsed }">
    <button v-if="isCompact" class="mobile-nav-toggle" type="button" @click="isMobileNavOpen = !isMobileNavOpen">
      <el-icon><Operation /></el-icon>
    </button>

    <aside class="control-sidebar" :class="{ collapsed: isSidebarCollapsed }">
      <div class="sidebar-brand">
        <div class="brand-mark" @click="toggleSidebar" style="cursor:pointer" title="收起/展开">
          <el-icon><Grid /></el-icon>
        </div>
        <div class="brand-copy" v-show="!isSidebarCollapsed">
          <span class="brand-kicker">Cupcake Console</span>
          <strong class="brand-title">Unified Control</strong>
          <span class="brand-subtitle">Operations workspace</span>
        </div>
      </div>

      <div class="sidebar-section">
        <div class="sidebar-label" v-show="!isSidebarCollapsed">导航</div>
        <el-menu :default-active="activeMenu" class="sidebar-menu" router>
          <el-menu-item v-for="item in menuItems" :key="item.path" :index="item.path" @click="isMobileNavOpen = false">
            <el-icon><component :is="item.icon" /></el-icon>
            <template #title><span>{{ item.label }}</span></template>
          </el-menu-item>
        </el-menu>
      </div>

      <div class="sidebar-foot" v-show="!isSidebarCollapsed">
        <div class="user-panel">
          <el-avatar :size="42" class="user-avatar">{{ userInitial }}</el-avatar>
          <div class="user-meta">
            <strong>{{ username }}</strong>
            <span>已验证的操作员</span>
          </div>
        </div>

        <div class="foot-actions">
          <button type="button" class="foot-link" @click="openPasswordDialog">
            <el-icon><Lock /></el-icon>
            <span>安全</span>
          </button>
          <button type="button" class="foot-link foot-link--danger" @click="handleLogout">
            <el-icon><SwitchButton /></el-icon>
            <span>注销</span>
          </button>
        </div>
      </div>

      <!-- Collapsed footer: just avatar and logout icon -->
      <div class="sidebar-foot-collapsed" v-show="isSidebarCollapsed">
        <el-avatar :size="36" class="user-avatar">{{ userInitial }}</el-avatar>
        <button type="button" class="foot-link-icon" @click="handleLogout" title="注销">
          <el-icon><SwitchButton /></el-icon>
        </button>
      </div>
    </aside>

    <div v-if="isCompact && isMobileNavOpen" class="mobile-overlay" @click="isMobileNavOpen = false"></div>

    <main class="control-main">
      <header class="control-header">
        <div class="header-copy">
          <h1 class="header-title">{{ currentTitle }}</h1>
          <p class="header-description">{{ currentDescription }}</p>
        </div>

        <div class="header-meta">
          <button
            v-if="isAdmin"
            type="button"
            class="header-chip header-chip--action"
            :class="{ 'header-chip--alert': mcpPendingCount > 0 }"
            @click="openMcpDrawer"
            title="MCP 待确认"
          >
            <el-badge :value="mcpPendingCount" :hidden="mcpPendingCount === 0" :max="99">
              <span>MCP 确认</span>
            </el-badge>
          </button>
          <div class="header-chip">
            <span class="chip-dot"></span>
            <span>控制平面在线</span>
          </div>
          <div class="header-chip">
            <el-icon><Clock /></el-icon>
            <span>{{ currentDate }}</span>
          </div>
          <div class="header-clock">{{ currentTime }}</div>
        </div>
      </header>

      <section class="control-content">
        <router-view v-slot="{ Component }">
          <transition name="layout-fade" mode="out-in">
            <keep-alive>
              <component :is="Component" />
            </keep-alive>
          </transition>
        </router-view>
      </section>
    </main>

    <el-dialog v-model="pwdDialog.visible" title="修改密码" width="420px" class="premium-dialog" append-to-body>
      <el-form :model="pwdDialog.form" label-position="top">
        <el-form-item label="当前密码">
          <el-input v-model="pwdDialog.form.oldPassword" type="password" show-password />
        </el-form-item>
        <el-form-item label="新密码">
          <el-input v-model="pwdDialog.form.newPassword" type="password" show-password />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="pwdDialog.visible = false">取消</el-button>
        <el-button type="primary" @click="submitChangePassword" :loading="pwdDialog.loading">保存</el-button>
      </template>
    </el-dialog>

    <!-- MCP 确认：待批准 + 历史留存（批准/拒绝/失败均不删除） -->
    <el-drawer
      v-model="mcpDrawer.visible"
      title="MCP 操作确认与记录"
      size="520px"
      append-to-body
      class="mcp-confirm-drawer"
    >
      <p class="mcp-drawer-tip">
        任意 MCP 写操作都会先入库。待确认需批准后才下发；批准/拒绝/失败/超时的记录会永久留存在历史中（含 API 自动批准）。
      </p>
      <el-tabs v-model="mcpDrawer.tab" @tab-change="onMcpTabChange">
        <el-tab-pane :label="`待确认 (${mcpPendingCount})`" name="pending" />
        <el-tab-pane :label="`历史记录 (${mcpHistoryCount})`" name="history" />
      </el-tabs>

      <div v-if="mcpDrawer.loading" class="mcp-empty">加载中…</div>
      <template v-else>
        <div v-if="!mcpVisibleItems.length" class="mcp-empty">
          {{ mcpDrawer.tab === 'pending' ? '暂无待确认请求' : '暂无历史记录' }}
        </div>
        <div
          v-for="item in mcpVisibleItems"
          :key="item.id"
          class="mcp-card"
          :data-risk="item.risk_level"
          :data-status="item.status"
          @click="openMcpDetail(item)"
        >
          <div class="mcp-card-head">
            <el-tag size="small" :type="statusTagType(item.status)">{{ statusLabel(item.status) }}</el-tag>
            <el-tag size="small" :type="riskTagType(item.risk_level)" effect="plain">{{ item.risk_level || 'high' }}</el-tag>
            <span class="mcp-op">{{ item.op || item.path }}</span>
            <span class="mcp-time">{{ formatMcpTime(item.created_at) }}</span>
          </div>
          <pre class="mcp-summary">{{ item.summary }}</pre>
          <div class="mcp-meta">
            <span>Agent: {{ item.agent_uuid || '—' }}</span>
            <span>{{ item.method }} {{ item.path }}</span>
            <span v-if="item.decided_by">处理人: {{ item.decided_by }} · {{ formatMcpTime(item.decided_at) }}</span>
            <span v-if="resultPreview(item)" class="mcp-result">{{ resultPreview(item) }}</span>
            <span v-if="item.error_code && item.status !== 'executed'" class="mcp-err">错误: {{ item.error_code }}</span>
          </div>
          <div class="mcp-actions" @click.stop>
            <el-button size="small" link type="primary" @click="openMcpDetail(item)">详情</el-button>
            <template v-if="item.status === 'pending'">
              <el-button size="small" type="danger" plain :loading="mcpDrawer.busyId === item.id" @click="denyMcp(item)">拒绝</el-button>
              <el-button size="small" type="primary" :loading="mcpDrawer.busyId === item.id" @click="approveMcp(item)">批准执行</el-button>
            </template>
          </div>
        </div>
      </template>
    </el-drawer>

    <!-- MCP 执行详情：命令 + Agent 回显 -->
    <el-dialog
      v-model="mcpDetail.visible"
      title="MCP 执行详情"
      width="640px"
      append-to-body
      class="mcp-detail-dialog"
      destroy-on-close
    >
      <template v-if="mcpDetail.item">
        <div class="mcp-detail-row">
          <span class="mcp-detail-label">状态</span>
          <el-tag size="small" :type="statusTagType(mcpDetail.item.status)">{{ statusLabel(mcpDetail.item.status) }}</el-tag>
          <el-tag size="small" effect="plain">{{ mcpDetail.item.risk_level }}</el-tag>
        </div>
        <div class="mcp-detail-row">
          <span class="mcp-detail-label">操作</span>
          <code>{{ mcpDetail.item.op || mcpDetail.item.path }}</code>
        </div>
        <div class="mcp-detail-row">
          <span class="mcp-detail-label">Agent</span>
          <code>{{ mcpDetail.item.agent_uuid || '—' }}</code>
        </div>
        <div class="mcp-detail-row">
          <span class="mcp-detail-label">时间</span>
          <span>{{ formatMcpTime(mcpDetail.item.created_at) }}
            <template v-if="mcpDetail.item.decided_by"> → {{ mcpDetail.item.decided_by }} @ {{ formatMcpTime(mcpDetail.item.decided_at) }}</template>
          </span>
        </div>
        <div class="mcp-detail-block">
          <div class="mcp-detail-label">用途说明</div>
          <pre class="mcp-detail-pre">{{ mcpDetail.item.summary }}</pre>
        </div>
        <div v-if="mcpDetail.parsed?.purpose || mcpDetail.purpose" class="mcp-detail-block">
          <div class="mcp-detail-label">模型填写的用途</div>
          <pre class="mcp-detail-pre">{{ mcpDetail.parsed?.purpose || mcpDetail.purpose }}</pre>
        </div>
        <div v-if="mcpDetail.parsed?.command || mcpDetail.parsed?.input" class="mcp-detail-block">
          <div class="mcp-detail-label">执行的命令</div>
          <pre class="mcp-detail-pre mcp-detail-cmd">{{ mcpDetail.parsed.command || mcpDetail.parsed.input }}</pre>
        </div>
        <div v-if="mcpDetail.parsed?.op" class="mcp-detail-block">
          <div class="mcp-detail-label">AD 操作 / 参数</div>
          <pre class="mcp-detail-pre">op={{ mcpDetail.parsed.op }}
params={{ formatJson(mcpDetail.parsed.params) }}</pre>
        </div>
        <div class="mcp-detail-block">
          <div class="mcp-detail-label">Agent 回显 / 结果</div>
          <pre class="mcp-detail-pre mcp-detail-out">{{ detailOutputText }}</pre>
        </div>
        <div v-if="mcpDetail.item.body_json" class="mcp-detail-block">
          <div class="mcp-detail-label">原始请求 Body</div>
          <pre class="mcp-detail-pre mcp-detail-muted">{{ prettyJson(mcpDetail.item.body_json) }}</pre>
        </div>
        <div v-if="mcpDetail.item.result_body" class="mcp-detail-block">
          <div class="mcp-detail-label">原始结果 JSON</div>
          <pre class="mcp-detail-pre mcp-detail-muted">{{ prettyJson(mcpDetail.item.result_body) }}</pre>
        </div>
      </template>
      <template #footer>
        <el-button @click="mcpDetail.visible = false">关闭</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { computed, onBeforeUnmount, onMounted, reactive, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import {
  Box,
  Clock,
  Connection,
  Grid,
  Headset,
  Lightning,
  Lock,
  Monitor,
  Odometer,
  Operation,
  Setting,
  Share,
  SwitchButton
} from '@element-plus/icons-vue'
import { ElMessage, ElMessageBox, ElNotification } from 'element-plus'
import api from '../api/index'

const route = useRoute()
const router = useRouter()

const isAdmin = computed(() => {
  try {
    const role = (JSON.parse(localStorage.getItem('cupcake_user') || '{}').role || '').toLowerCase()
    return role === 'admin' || role === 'administrator' || role === 'break-glass-admin'
  } catch {
    return false
  }
})

const mcpPendingCount = ref(0)
const mcpHistoryCount = ref(0)
const mcpDrawer = reactive({
  visible: false,
  tab: 'pending',
  loading: false,
  pendingItems: [],
  historyItems: [],
  busyId: '',
  knownIds: new Set()
})
const mcpDetail = reactive({ visible: false, item: null, parsed: null })
let mcpPollTimer = null

const mcpVisibleItems = computed(() =>
  mcpDrawer.tab === 'pending' ? mcpDrawer.pendingItems : mcpDrawer.historyItems
)

const detailOutputText = computed(() => {
  const p = mcpDetail.parsed || {}
  if (p.output != null && String(p.output).trim() !== '') return String(p.output)
  if (p.summary_json) {
    try {
      return typeof p.summary_json === 'string'
        ? JSON.stringify(JSON.parse(p.summary_json), null, 2)
        : JSON.stringify(p.summary_json, null, 2)
    } catch {
      return String(p.summary_json)
    }
  }
  if (p.note) return String(p.note)
  if (p.error_code) return `error_code: ${p.error_code}`
  if (mcpDetail.item?.result_body) {
    try {
      const j = JSON.parse(mcpDetail.item.result_body)
      if (j.output) return j.output
      return JSON.stringify(j, null, 2)
    } catch {
      return mcpDetail.item.result_body
    }
  }
  return '（无回显数据 — 可能仍在执行中，或仅记录了下发状态）'
})

const riskTagType = (r) => {
  if (r === 'critical') return 'danger'
  if (r === 'high') return 'warning'
  if (r === 'medium') return 'info'
  return 'success'
}

const statusTagType = (s) => {
  if (s === 'pending') return 'warning'
  if (s === 'executed') return 'success'
  if (s === 'denied') return 'info'
  if (s === 'failed' || s === 'expired') return 'danger'
  return ''
}

const statusLabel = (s) => {
  const map = {
    pending: '待确认',
    approved: '已批准',
    executed: '已执行',
    denied: '已拒绝',
    failed: '执行失败',
    expired: '已超时'
  }
  return map[s] || s || '—'
}

const formatMcpTime = (t) => {
  if (!t) return ''
  try {
    return new Date(t).toLocaleString()
  } catch {
    return String(t)
  }
}

const truncateText = (s, n) => {
  if (!s) return ''
  const t = String(s)
  return t.length > n ? t.slice(0, n) + '…' : t
}

const parseResultBody = (raw) => {
  if (!raw) return {}
  try {
    return typeof raw === 'string' ? JSON.parse(raw) : raw
  } catch {
    return { output: String(raw) }
  }
}

const resultPreview = (item) => {
  const p = parseResultBody(item?.result_body)
  if (p.command || p.input) {
    const out = (p.output || '').trim()
    if (out) return `回显: ${truncateText(out.replace(/\s+/g, ' '), 100)}`
    if (p.completed === false) return '已下发，等待回显…'
    return `命令: ${truncateText(p.command || p.input, 60)}`
  }
  if (p.summary_json) {
    const s = typeof p.summary_json === 'string' ? p.summary_json : JSON.stringify(p.summary_json)
    return `结果: ${truncateText(s, 100)}`
  }
  if (p.dispatched && !p.output) return '结果: 已下发 (无回显字段)'
  if (item?.result_body) return `结果: ${truncateText(item.result_body, 100)}`
  return ''
}

const prettyJson = (raw) => {
  if (!raw) return ''
  try {
    const o = typeof raw === 'string' ? JSON.parse(raw) : raw
    return JSON.stringify(o, null, 2)
  } catch {
    return String(raw)
  }
}

const formatJson = (v) => {
  if (v == null) return '{}'
  if (typeof v === 'string') {
    try {
      return JSON.stringify(JSON.parse(v), null, 2)
    } catch {
      return v
    }
  }
  try {
    return JSON.stringify(v, null, 2)
  } catch {
    return String(v)
  }
}

const openMcpDetail = (item) => {
  mcpDetail.item = item
  mcpDetail.parsed = parseResultBody(item?.result_body)
  mcpDetail.purpose = ''
  // Enrich command / purpose from request body snapshot
  try {
    const body = parseResultBody(item?.body_json)
    if (!mcpDetail.parsed.command && !mcpDetail.parsed.input) {
      if (body.cmd) mcpDetail.parsed.command = body.cmd
      if (body.command) mcpDetail.parsed.command = body.command
    }
    if (!mcpDetail.parsed.purpose) {
      mcpDetail.parsed.purpose = body.purpose || body.reason || body.usage || ''
    }
    mcpDetail.purpose = mcpDetail.parsed.purpose || ''
    if (body.op) mcpDetail.parsed.op = body.op
    if (body.params) mcpDetail.parsed.params = body.params
  } catch { /* ignore */ }
  // Fallback: parse "用途:" line from summary
  if (!mcpDetail.parsed.purpose && item?.summary) {
    const m = String(item.summary).match(/用途[：:]\s*(.+?)(?:\n命令|\n|$)/s)
    if (m) mcpDetail.parsed.purpose = m[1].trim()
  }
  mcpDetail.visible = true
}

const loadMcpHistory = async () => {
  try {
    // no status filter → all records (API keeps executed/denied/failed permanently)
    const { data } = await api.get('/api/mcp/pending', { params: {} })
    const all = data.items || []
    mcpDrawer.historyItems = all.filter((x) => x.status !== 'pending')
    mcpHistoryCount.value = mcpDrawer.historyItems.length
    // also refresh pending count if present
    if (typeof data.pending_count === 'number') {
      mcpPendingCount.value = data.pending_count
    }
  } catch {
    /* ignore */
  }
}

const pollMcpPending = async () => {
  if (!isAdmin.value) return
  try {
    const { data } = await api.get('/api/mcp/pending', { params: { status: 'pending' } })
    const items = data.items || []
    mcpPendingCount.value = data.pending_count ?? items.length
    mcpDrawer.pendingItems = items
    for (const it of items) {
      if (!mcpDrawer.knownIds.has(it.id)) {
        mcpDrawer.knownIds.add(it.id)
        ElNotification({
          title: 'MCP 待确认',
          message: (it.summary || it.op || it.path || '新的写操作').slice(0, 160),
          type: 'warning',
          duration: 12000,
          onClick: () => {
            mcpDrawer.tab = 'pending'
            openMcpDrawer()
          }
        })
      }
    }
  } catch {
    /* ignore for non-admin / offline */
  }
}

const onMcpTabChange = async (name) => {
  if (name === 'history') {
    mcpDrawer.loading = true
    await loadMcpHistory()
    mcpDrawer.loading = false
  } else {
    await pollMcpPending()
  }
}

const openMcpDrawer = async () => {
  mcpDrawer.visible = true
  mcpDrawer.loading = true
  try {
    await Promise.all([pollMcpPending(), loadMcpHistory()])
    // 有待确认优先展示待确认，否则展示历史（避免“自动批准后以为没记录”）
    if (mcpPendingCount.value === 0 && mcpHistoryCount.value > 0) {
      mcpDrawer.tab = 'history'
    } else {
      mcpDrawer.tab = 'pending'
    }
  } finally {
    mcpDrawer.loading = false
  }
}

const approveMcp = async (item) => {
  try {
    await ElMessageBox.confirm(
      `确认批准并执行此 MCP 操作？\n\n${item.summary || item.path}`,
      '批准 MCP 命令',
      { type: 'warning', confirmButtonText: '批准执行', cancelButtonText: '取消' }
    )
  } catch {
    return
  }
  mcpDrawer.busyId = item.id
  try {
    const body = {}
    if (item.op === 'dcsync' || (item.path || '').includes('dcsync')) {
      // Panel can fill confirm contract on approve if needed later
      body.confirm = true
    }
    const { data } = await api.post(`/api/mcp/pending/${item.id}/approve`, body)
    if (data.status === 'executed' || data.item?.status === 'executed') {
      ElMessage.success('已批准并执行')
    } else {
      ElMessage.warning(data.error || data.item?.error_code || '执行完成（请检查结果）')
    }
    await Promise.all([pollMcpPending(), loadMcpHistory()])
    mcpDrawer.tab = 'history'
  } catch (e) {
    ElMessage.error(e?.response?.data?.error || e.message || '批准失败')
  } finally {
    mcpDrawer.busyId = ''
  }
}

const denyMcp = async (item) => {
  mcpDrawer.busyId = item.id
  try {
    await api.post(`/api/mcp/pending/${item.id}/deny`)
    ElMessage.info('已拒绝（记录已写入历史）')
    await Promise.all([pollMcpPending(), loadMcpHistory()])
    mcpDrawer.tab = 'history'
  } catch (e) {
    ElMessage.error(e?.response?.data?.error || e.message || '拒绝失败')
  } finally {
    mcpDrawer.busyId = ''
  }
}

const allMenuItems = [
  { path: '/dashboard', label: '仪表盘', icon: Odometer },
  { path: '/clients', label: '受控端', icon: Monitor },
  { path: '/listeners', label: '监听器', icon: Headset, adminOnly: true },
  { path: '/tunnels', label: '隧道', icon: Share },
  { path: '/generator', label: '生成器', icon: Lightning, adminOnly: true },
  { path: '/modules', label: '模块', icon: Box },
  { path: '/ad', label: '域渗透模块', icon: Share },
  { path: '/plugins', label: '插件', icon: Connection },
  { path: '/history', label: '历史记录', icon: Clock },
  { path: '/settings', label: '设置', icon: Setting, adminOnly: true }
]

const titleDisplayNames = {
  Dashboard: '仪表盘',
  Clients: '受控端',
  Listeners: '监听器',
  Tunnels: '隧道',
  Generator: '生成器',
  Modules: '模块',
  AD: '域渗透模块',
  AdCenter: '域渗透模块',
  Plugins: '插件',
  History: '历史记录',
  Settings: '设置',
  'Client Detail': '主机详情'
}

const titleDescriptions = {
  Dashboard: '实时全盘拓扑节点视场、各平台端点数量分布与核心资源指标汇聚。',
  '仪表盘': '实时全盘拓扑节点视场、各平台端点数量分布与核心资源指标汇聚。',
  Clients: '已接入主机的生命周期管理、正向/反向交互会话与实时状态监控。',
  '受控端': '已接入主机的生命周期管理、正向/反向交互会话与实时状态监控。',
  Listeners: '多协议传输通道监听、端口分配与通信数据接入服务管理。',
  '监听器': '多协议传输通道监听、端口分配与通信数据接入服务管理。',
  Tunnels: '内置 SOCKS5 及端口转发通道的建立、状态与数据桥接。',
  '隧道': '内置 SOCKS5 及端口转发通道的建立、状态与数据桥接。',
  Generator: '跨平台 Shell & Stager 载荷构建、定制模板与能力参数配置。',
  '生成器': '跨平台 Shell & Stager 载荷构建、定制模板与能力参数配置。',
  Modules: 'L2 模块仓库：bof / inject / ad，分模块推送。',
  '模块': 'L2 模块仓库：bof / inject / ad，分模块推送。',
  AD: '域渗透工具模块 ad 的上传、登记、推送与加载状态管理。',
  AdCenter: '域渗透工具模块 ad 的上传、登记、推送与加载状态管理。',
  '域渗透': '域渗透工具模块 ad 的上传、登记、推送与加载状态管理。',
  '域渗透模块': '域渗透工具模块 ad 的上传、登记、推送与加载状态管理。',
  Plugins: '扩展功能模块集中注入、内存载荷加载与平台兼容插件管理。',
  '插件': '扩展功能模块集中注入、内存载荷加载与平台兼容插件管理。',
  History: '插件 / 模块 / Shell / AD 执行审计：来源、操作者、输入输出与 req_id 全量可追溯。',
  '历史记录': '插件 / 模块 / Shell / AD 执行审计：来源、操作者、输入输出与 req_id 全量可追溯。',
  Settings: '多角色操作员鉴权配置、系统审计日志与控制平面安全设置。',
  '设置': '多角色操作员鉴权配置、系统审计日志与控制平面安全设置。',
  'Client Detail': '特定受控端点的详细信息、命令行终端交互、文件管理与高级交互。',
  '主机详情': '特定受控端点的详细信息、命令行终端交互、文件管理与高级交互。'
}

const userData = JSON.parse(localStorage.getItem('cupcake_user') || '{}')
const username = ref(userData.username || 'Operator')
const userRole = (userData.role || 'operator').toLowerCase()
const menuItems = computed(() =>
  allMenuItems.filter((m) => !m.adminOnly || isAdmin.value)
)
const userInitial = computed(() => username.value.charAt(0).toUpperCase())
const activeMenu = computed(() => route.path.startsWith('/client/') ? '/clients' : route.path)

const rawTitle = computed(() => route.meta.title || 'Dashboard')
const currentTitle = computed(() => titleDisplayNames[rawTitle.value] || rawTitle.value)
const currentDescription = computed(() => titleDescriptions[rawTitle.value] || titleDescriptions[currentTitle.value] || '具有统一布局和共享视觉系统的控制舱操作工作流。')

const currentTime = ref('')
const currentDate = ref('')
const viewportWidth = ref(typeof window === 'undefined' ? 1440 : window.innerWidth)
const isMobileNavOpen = ref(false)
const isCompact = computed(() => viewportWidth.value < 1080)
const isSidebarCollapsed = ref(false)

const toggleSidebar = () => {
  isSidebarCollapsed.value = !isSidebarCollapsed.value
}

const pwdDialog = reactive({
  visible: false,
  loading: false,
  form: { oldPassword: '', newPassword: '' }
})

let clockTimer = null

const syncClock = () => {
  const now = new Date()
  currentTime.value = now.toLocaleTimeString('en-GB', { hour12: false })
  currentDate.value = now.toLocaleDateString('en-GB', {
    weekday: 'short',
    year: 'numeric',
    month: 'short',
    day: 'numeric'
  })
}

const handleResize = () => {
  viewportWidth.value = window.innerWidth
  if (!isCompact.value) {
    isMobileNavOpen.value = false
  }
}

const openPasswordDialog = () => {
  pwdDialog.form.oldPassword = ''
  pwdDialog.form.newPassword = ''
  pwdDialog.visible = true
}

const submitChangePassword = async () => {
  if (!pwdDialog.form.oldPassword || !pwdDialog.form.newPassword) {
    ElMessage.warning('请填写所有密码字段。')
    return
  }

  pwdDialog.loading = true
  try {
    // Self-service password change (not admin user-management API)
    await api.put('/api/auth/password', {
      old_password: pwdDialog.form.oldPassword,
      new_password: pwdDialog.form.newPassword
    })
    ElMessage.success('密码已更新。')
    pwdDialog.visible = false
  } catch (e) {
    ElMessage.error(e?.response?.data?.error || '密码更新失败。')
  } finally {
    pwdDialog.loading = false
  }
}

const handleLogout = () => {
  ElMessageBox.confirm('结束当前会话并返回登录页面？', '确认注销', {
    type: 'warning',
    confirmButtonText: '注销',
    cancelButtonText: '取消'
  }).then(() => {
    localStorage.removeItem('cupcake_token')
    localStorage.removeItem('cupcake_user')
    router.push('/login')
  }).catch(() => {})
}

onMounted(() => {
  syncClock()
  clockTimer = window.setInterval(syncClock, 1000)
  window.addEventListener('resize', handleResize)
  if (isAdmin.value) {
    pollMcpPending()
    mcpPollTimer = window.setInterval(pollMcpPending, 5000)
  }
})

onBeforeUnmount(() => {
  if (clockTimer) {
    window.clearInterval(clockTimer)
  }
  if (mcpPollTimer) {
    window.clearInterval(mcpPollTimer)
  }
  window.removeEventListener('resize', handleResize)
})
</script>

<style scoped>
.control-shell {
  display: grid;
  grid-template-columns: 296px minmax(0, 1fr);
  height: 100vh;
  min-height: 100vh;
  overflow: hidden;
  position: relative;
  transition: grid-template-columns 0.25s ease;
}

.control-shell--collapsed {
  grid-template-columns: 72px minmax(0, 1fr);
}

.control-sidebar {
  position: relative;
  z-index: 4;
  display: flex;
  flex-direction: column;
  gap: 24px;
  padding: 28px 22px 22px;
  color: var(--text-strong);
  background: var(--bg-sidebar);
  border-right: 1px solid var(--line-soft);
  transition: padding 0.25s ease, width 0.25s ease;
  overflow: hidden;
}

.control-sidebar.collapsed {
  padding: 28px 0 22px;
  width: 72px;
  align-items: center;
}

.control-sidebar.collapsed .sidebar-brand {
  justify-content: center;
  padding: 0;
}

.control-sidebar.collapsed .sidebar-section {
  width: 100%;
  padding: 0;
}

.control-sidebar.collapsed .sidebar-menu {
  width: 100% !important;
}

.control-sidebar.collapsed :deep(.el-menu) {
  width: 100% !important;
  border-right: none !important;
  background: transparent !important;
}

.control-sidebar.collapsed :deep(.el-menu-item) {
  height: 44px !important;
  line-height: 44px !important;
  padding: 0 !important;
  padding-left: 0 !important;
  margin: 4px 0 !important;
  display: flex !important;
  justify-content: center !important;
  align-items: center !important;
}

.control-sidebar.collapsed :deep(.el-menu-item .el-icon) {
  margin: 0 !important;
  font-size: 20px;
}

.control-sidebar.collapsed :deep(.el-menu-item span),
.control-sidebar.collapsed :deep(.el-menu-item .el-menu-tooltip__trigger) {
  display: none !important;
}

.sidebar-brand {
  display: flex;
  align-items: center;
  gap: 14px;
  padding: 8px 6px;
}

.brand-mark {
  width: 52px;
  height: 52px;
  display: grid;
  place-items: center;
  border-radius: 18px;
  color: #111111;
  background: #f2f2f2;
  box-shadow: none;
}

.brand-copy {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.brand-kicker,
.sidebar-label {
  font-size: 11px;
  letter-spacing: 0.14em;
  text-transform: uppercase;
  color: var(--text-muted);
}

.brand-title {
  font-size: 18px;
  letter-spacing: -0.03em;
}

.brand-subtitle {
  font-size: 13px;
  color: var(--text-muted);
}

.sidebar-section {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.sidebar-menu :deep(.el-menu-item) {
  height: 48px;
  margin: 4px 0;
  border-radius: 16px;
  color: var(--text-body) !important;
  font-weight: 700;
}

.sidebar-menu :deep(.el-menu-item:hover) {
  background: var(--bg-sidebar-soft) !important;
  color: var(--text-strong) !important;
}

.sidebar-menu :deep(.el-menu-item.is-active) {
  background: #f4f4f4 !important;
  color: var(--text-strong) !important;
  box-shadow: inset 0 0 0 1px #dddddd;
}

.sidebar-menu :deep(.el-menu-item .el-icon) {
  margin-right: 10px;
  font-size: 18px;
}

.sidebar-foot {
  margin-top: auto;
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.user-panel {
  display: flex;
  align-items: center;
  gap: 14px;
  padding: 16px;
  border-radius: 20px;
  background: #fafafa;
  border: 1px solid #ececec;
}

.user-avatar {
  background: #111111;
  color: #fff;
  font-weight: 700;
}

.user-meta {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.user-meta strong {
  font-size: 14px;
}

.user-meta span {
  font-size: 12px;
  color: var(--text-muted);
}

.foot-actions {
  display: grid;
  gap: 10px;
}

.foot-link {
  display: inline-flex;
  align-items: center;
  gap: 10px;
  width: 100%;
  padding: 12px 14px;
  border: 0;
  border-radius: 16px;
  color: var(--text-body);
  background: #fafafa;
  cursor: pointer;
  transition: background 0.16s ease, transform 0.16s ease;
}

.foot-link:hover {
  background: #f2f2f2;
  transform: translateY(-1px);
}

.foot-link--danger:hover {
  color: #111111;
  background: #f2f2f2;
}

.sidebar-foot-collapsed {
  margin-top: auto;
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 12px;
}

.foot-link-icon {
  width: 36px;
  height: 36px;
  border: 0;
  border-radius: 10px;
  background: #fafafa;
  color: var(--text-body);
  cursor: pointer;
  display: grid;
  place-items: center;
  transition: background 0.15s;
}

.foot-link-icon:hover {
  background: #f0f0f0;
}

/* Collapsed: el-menu tooltip hide */
:deep(.el-menu--collapse .el-sub-menu__icon-arrow) {
  display: none;
}

.control-main {
  min-width: 0;
  min-height: 0;
  height: 100vh;
  display: flex;
  flex-direction: column;
  overflow: hidden;
  padding: 22px;
}

.control-header {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 20px;
  padding: 10px 8px 24px;
}

.header-copy {
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.header-kicker {
  font-size: 11px;
  letter-spacing: 0.16em;
  text-transform: uppercase;
  color: var(--accent-strong);
  font-weight: 700;
}

.header-title {
  margin: 0;
  font-size: 24px;
  line-height: 1.2;
  letter-spacing: -0.02em;
}

.header-description {
  max-width: 760px;
  margin: 0;
  color: var(--text-body);
  line-height: 1.6;
  font-size: 13px;
}

.header-meta {
  display: flex;
  align-items: center;
  gap: 10px;
  flex-wrap: wrap;
  justify-content: flex-end;
}

.header-chip {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  min-height: 40px;
  padding: 0 14px;
  border-radius: 999px;
  background: #ffffff;
  border: 1px solid var(--line-soft);
  color: var(--text-body);
  font-size: 12px;
  font-weight: 700;
}

.chip-dot {
  width: 8px;
  height: 8px;
  border-radius: 999px;
  background: #111111;
  box-shadow: none;
}

.header-clock {
  display: inline-flex;
  align-items: center;
  min-height: 40px;
  padding: 0 16px;
  border-radius: 999px;
  background: #f5f5f5;
  color: var(--text-strong);
  font-weight: 800;
  letter-spacing: 0.08em;
}

.control-content {
  min-height: 0;
  flex: 1;
  overflow-x: hidden;
  overflow-y: auto;
  padding-bottom: 24px;
}

.layout-fade-enter-active,
.layout-fade-leave-active {
  transition: opacity 0.12s ease;
}

.layout-fade-enter-from,
.layout-fade-leave-to {
  opacity: 0;
}

.mobile-nav-toggle {
  position: fixed;
  top: 20px;
  left: 20px;
  z-index: 6;
  width: 44px;
  height: 44px;
  border: 0;
  border-radius: 14px;
  background: #111111;
  color: #fff;
  cursor: pointer;
  box-shadow: var(--shadow-panel);
}

.mobile-overlay {
  position: fixed;
  inset: 0;
  z-index: 3;
  background: rgba(17, 17, 17, 0.14);
  backdrop-filter: blur(4px);
}

@media (max-width: 1079px) {
  .control-shell {
    grid-template-columns: 1fr;
  }

  .control-sidebar {
    position: fixed;
    inset: 0 auto 0 0;
    width: min(320px, 84vw);
    transform: translateX(-105%);
    transition: transform 0.2s ease;
  }

  .control-shell--mobile-nav .control-sidebar {
    transform: translateX(0);
  }

  .control-main {
    padding-top: 84px;
  }

  .control-header {
    flex-direction: column;
  }

  .header-meta {
    justify-content: flex-start;
  }
}

@media (max-width: 720px) {
  .control-main {
    padding-left: 14px;
    padding-right: 14px;
  }

  .header-title {
    font-size: 34px;
  }
}

.header-chip--action {
  cursor: pointer;
  border: none;
  font: inherit;
  background: var(--bg-elevated, rgba(0, 0, 0, 0.04));
}
.header-chip--alert {
  color: #b45309;
  box-shadow: 0 0 0 1px rgba(180, 83, 9, 0.35);
}
.mcp-drawer-tip {
  font-size: 13px;
  color: var(--text-muted, #666);
  margin: 0 0 16px;
  line-height: 1.5;
}
.mcp-empty {
  text-align: center;
  color: #999;
  padding: 40px 0;
}
.mcp-card {
  border: 1px solid var(--line-soft, #e5e5e5);
  border-radius: 10px;
  padding: 12px 14px;
  margin-bottom: 12px;
  background: var(--bg-card, #fff);
  cursor: pointer;
  transition: box-shadow 0.15s ease;
}
.mcp-card:hover {
  box-shadow: 0 2px 12px rgba(0, 0, 0, 0.06);
}
.mcp-detail-row {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: 10px;
  font-size: 13px;
}
.mcp-detail-label {
  font-size: 12px;
  font-weight: 600;
  color: #64748b;
  min-width: 72px;
}
.mcp-detail-block {
  margin: 14px 0;
}
.mcp-detail-pre {
  margin: 6px 0 0;
  padding: 10px 12px;
  background: #0f172a0a;
  border-radius: 8px;
  font-size: 12px;
  line-height: 1.45;
  white-space: pre-wrap;
  word-break: break-word;
  max-height: 240px;
  overflow: auto;
}
.mcp-detail-cmd {
  background: #1e293b;
  color: #e2e8f0;
  font-family: ui-monospace, 'JetBrains Mono', Consolas, monospace;
}
.mcp-detail-out {
  background: #052e16;
  color: #bbf7d0;
  font-family: ui-monospace, 'JetBrains Mono', Consolas, monospace;
  max-height: 320px;
}
.mcp-detail-muted {
  max-height: 160px;
  opacity: 0.85;
  font-size: 11px;
}
.mcp-card[data-risk='critical'] {
  border-color: #fca5a5;
  background: #fff7f7;
}
.mcp-card[data-risk='high'] {
  border-color: #fcd34d;
  background: #fffbeb;
}
.mcp-card[data-status='executed'] {
  border-color: #86efac;
  background: #f0fdf4;
}
.mcp-card[data-status='denied'] {
  border-color: #cbd5e1;
  background: #f8fafc;
}
.mcp-card[data-status='failed'],
.mcp-card[data-status='expired'] {
  border-color: #fca5a5;
  background: #fef2f2;
}
.mcp-result {
  color: #166534;
  word-break: break-all;
}
.mcp-err {
  color: #b91c1c;
}
.mcp-card-head {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 8px;
}
.mcp-op {
  font-weight: 600;
  flex: 1;
  font-size: 13px;
}
.mcp-time {
  font-size: 11px;
  color: #999;
}
.mcp-summary {
  white-space: pre-wrap;
  word-break: break-word;
  font-size: 12px;
  line-height: 1.45;
  margin: 0 0 8px;
  max-height: 200px;
  overflow: auto;
  background: rgba(0, 0, 0, 0.03);
  padding: 8px;
  border-radius: 6px;
}
.mcp-meta {
  display: flex;
  flex-direction: column;
  gap: 2px;
  font-size: 11px;
  color: #888;
  margin-bottom: 10px;
}
.mcp-actions {
  display: flex;
  justify-content: flex-end;
  gap: 8px;
}
</style>
