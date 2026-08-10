<template>
  <div class="view-shell history-shell">
    <section class="surface-card history-card">
      <div class="panel-head">
        <div>
          <span class="panel-kicker">Audit</span>
          <h3>执行历史记录</h3>
          <p class="hint">插件 / 模块 / Shell / AD 全量审计。来源：MCP · 手动(面板) · 内部。</p>
        </div>
        <el-button type="primary" :loading="loading" @click="fetchHistory">
          <el-icon><Refresh /></el-icon>
          刷新
        </el-button>
      </div>

      <div class="filter-bar">
        <div class="filter-group">
          <span class="filter-label">来源</span>
          <el-radio-group v-model="filters.source" size="small" @change="onFilterChange">
            <el-radio-button label="all">全部</el-radio-button>
            <el-radio-button label="mcp">MCP</el-radio-button>
            <el-radio-button label="panel">手动</el-radio-button>
            <el-radio-button label="internal">内部</el-radio-button>
          </el-radio-group>
        </div>

        <div class="filter-group">
          <span class="filter-label">范围</span>
          <el-radio-group v-model="filters.scope" size="small" @change="onScopeChange">
            <el-radio-button label="all">全部主机</el-radio-button>
            <el-radio-button label="agent" :disabled="!filters.uuid">当前主机</el-radio-button>
          </el-radio-group>
          <el-select
            v-model="filters.uuid"
            clearable
            filterable
            placeholder="筛选主机 UUID"
            style="width: 260px"
            @change="onUuidSelect"
          >
            <el-option
              v-for="c in clients"
              :key="c.uuid"
              :label="`${c.hostname || c.uuid?.slice(0, 8)} (${c.uuid?.slice(0, 8) || '-'})`"
              :value="c.uuid"
            />
          </el-select>
        </div>

        <div class="filter-group">
          <span class="filter-label">类型</span>
          <el-radio-group v-model="filters.type" size="small" @change="onFilterChange">
            <el-radio-button label="all">全部</el-radio-button>
            <el-radio-button label="plugin">插件</el-radio-button>
            <el-radio-button label="module">模块</el-radio-button>
            <el-radio-button label="shell">Shell</el-radio-button>
            <el-radio-button label="ad">AD</el-radio-button>
          </el-radio-group>
        </div>

        <div class="filter-group">
          <span class="filter-label">条数</span>
          <el-select v-model="filters.limit" style="width: 100px" size="small" @change="onFilterChange">
            <el-option :value="50" label="50" />
            <el-option :value="100" label="100" />
            <el-option :value="200" label="200" />
            <el-option :value="500" label="500" />
          </el-select>
        </div>
      </div>

      <el-table
        :data="rows"
        v-loading="loading"
        class="premium-table"
        empty-text="暂无历史记录"
        row-key="req_id"
      >
        <el-table-column label="时间" width="168">
          <template #default="{ row }">
            <span class="mono">{{ formatDate(row.created_at) }}</span>
          </template>
        </el-table-column>

        <el-table-column label="主机" min-width="140">
          <template #default="{ row }">
            <div class="agent-cell">
              <span class="hostname-text">{{ agentLabel(row.agent_uuid) }}</span>
              <span class="mono uuid-label">{{ shortUuid(row.agent_uuid) }}</span>
            </div>
          </template>
        </el-table-column>

        <el-table-column label="来源" width="100" align="center">
          <template #default="{ row }">
            <el-tag size="small" :type="sourceTagType(row.source)" effect="light">
              {{ sourceLabel(row.source) }}
            </el-tag>
          </template>
        </el-table-column>

        <el-table-column label="操作者" width="110" show-overflow-tooltip>
          <template #default="{ row }">
            <span class="mono">{{ row.created_by || '—' }}</span>
          </template>
        </el-table-column>

        <el-table-column label="类型" width="130" show-overflow-tooltip>
          <template #default="{ row }">
            <el-tag size="small" :type="typeTagType(row.type)" effect="plain">{{ row.type || '—' }}</el-tag>
          </template>
        </el-table-column>

        <el-table-column label="输入" min-width="180" show-overflow-tooltip>
          <template #default="{ row }">
            <span class="mono input-text">{{ row.input || '—' }}</span>
          </template>
        </el-table-column>

        <el-table-column label="状态" width="100" align="center">
          <template #default="{ row }">
            <el-tag size="small" :type="statusTagType(row.status)">{{ statusLabel(row.status) }}</el-tag>
          </template>
        </el-table-column>

        <el-table-column label="输出预览" min-width="200">
          <template #default="{ row }">
            <span class="mono output-preview" :title="row.output || ''">{{ previewOutput(row.output) }}</span>
          </template>
        </el-table-column>

        <el-table-column label="req_id" width="120" show-overflow-tooltip>
          <template #default="{ row }">
            <span class="mono">{{ shortUuid(row.req_id) }}</span>
          </template>
        </el-table-column>

        <el-table-column label="操作" width="100" fixed="right" align="center">
          <template #default="{ row }">
            <el-button link type="primary" @click="openDetail(row)">详情</el-button>
          </template>
        </el-table-column>
      </el-table>
    </section>

    <el-dialog
      v-model="detail.visible"
      :title="`审计详情 · ${detail.row?.req_id || ''}`"
      width="780px"
      top="6vh"
      destroy-on-close
    >
      <div v-if="detail.row" class="detail-grid">
        <div class="detail-row"><span>时间</span><strong class="mono">{{ formatDate(detail.row.created_at) }}</strong></div>
        <div class="detail-row"><span>主机</span><strong class="mono">{{ detail.row.agent_uuid }}</strong></div>
        <div class="detail-row">
          <span>来源</span>
          <el-tag size="small" :type="sourceTagType(detail.row.source)">{{ sourceLabel(detail.row.source) }}</el-tag>
        </div>
        <div class="detail-row"><span>操作者</span><strong>{{ detail.row.created_by || '—' }}</strong></div>
        <div class="detail-row"><span>类型</span><strong>{{ detail.row.type || '—' }}</strong></div>
        <div class="detail-row"><span>状态</span><strong>{{ statusLabel(detail.row.status) }}</strong></div>
        <div class="detail-row"><span>req_id</span><strong class="mono">{{ detail.row.req_id }}</strong></div>
        <div class="detail-block">
          <span>输入</span>
          <pre class="detail-pre">{{ detail.row.input || '(空)' }}</pre>
        </div>
        <div class="detail-block">
          <span>输出</span>
          <pre class="detail-pre output">{{ detail.row.output || '(无输出)' }}</pre>
        </div>
      </div>
      <template #footer>
        <el-button @click="detail.visible = false">关闭</el-button>
        <el-button type="primary" :disabled="!detail.row?.output" @click="copyOutput">复制输出</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { onMounted, reactive, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { Refresh } from '@element-plus/icons-vue'
import { ElMessage } from 'element-plus'
import api from '../api/index'

const route = useRoute()
const router = useRouter()

const loading = ref(false)
const rows = ref([])
const clients = ref([])
const clientMap = ref({})

const filters = reactive({
  source: 'all', // all | mcp | panel | internal  (UI 手动 → panel)
  scope: 'all',  // all | agent
  uuid: '',
  type: 'all',   // all | plugin | module | shell | ad
  limit: 100
})

const detail = reactive({
  visible: false,
  row: null
})

const shortUuid = (v) => {
  if (!v) return '—'
  return v.length > 8 ? v.slice(0, 8) : v
}

const agentLabel = (uuid) => {
  const c = clientMap.value[uuid]
  return c?.hostname || shortUuid(uuid)
}

const sourceLabel = (src) => {
  const s = (src || 'panel').toLowerCase()
  if (s === 'mcp') return 'MCP'
  if (s === 'internal') return '内部'
  return '手动'
}

const sourceTagType = (src) => {
  const s = (src || 'panel').toLowerCase()
  if (s === 'mcp') return 'warning'
  if (s === 'internal') return 'info'
  return 'success' // panel / 手动
}

const statusLabel = (st) => {
  if (st === 'completed') return '完成'
  if (st === 'pending') return '进行中'
  if (st === 'failed') return '失败'
  return st || '—'
}

const statusTagType = (st) => {
  if (st === 'completed') return 'success'
  if (st === 'pending') return 'info'
  if (st === 'failed') return 'danger'
  return ''
}

const typeTagType = (t) => {
  const s = (t || '').toLowerCase()
  if (s.startsWith('ad_') || s === 'ad') return 'danger'
  if (s.startsWith('module_')) return 'warning'
  if (s === 'shell' || s.startsWith('shell_')) return ''
  return 'primary'
}

const previewOutput = (out) => {
  if (!out) return '—'
  const one = String(out).replace(/\s+/g, ' ').trim()
  return one.length > 80 ? one.slice(0, 80) + '…' : one
}

const formatDate = (ts) => {
  if (!ts) return '—'
  const d = new Date(ts)
  if (Number.isNaN(d.getTime())) return String(ts)
  return d.toLocaleString('zh-CN', { hour12: false })
}

const syncQueryToFilters = () => {
  const q = route.query || {}
  if (q.source && ['all', 'mcp', 'panel', 'internal'].includes(String(q.source))) {
    filters.source = String(q.source)
  }
  if (q.type && ['all', 'plugin', 'module', 'shell', 'ad'].includes(String(q.type))) {
    filters.type = String(q.type)
  }
  if (q.limit) {
    const n = parseInt(String(q.limit), 10)
    if ([50, 100, 200, 500].includes(n)) filters.limit = n
  }
  if (q.uuid) {
    filters.uuid = String(q.uuid)
    filters.scope = 'agent'
  }
}

const pushQuery = () => {
  const query = {}
  if (filters.source && filters.source !== 'all') query.source = filters.source
  if (filters.type && filters.type !== 'all') query.type = filters.type
  if (filters.limit && filters.limit !== 100) query.limit = String(filters.limit)
  if (filters.scope === 'agent' && filters.uuid) query.uuid = filters.uuid
  router.replace({ name: 'History', query })
}

const fetchClients = async () => {
  try {
    const res = await api.get('/api/clients')
    const list = res.data || []
    clients.value = list
    const map = {}
    for (const c of list) {
      if (c?.uuid) map[c.uuid] = c
    }
    clientMap.value = map
  } catch (e) {
    console.error('clients fetch failed', e)
  }
}

const fetchHistory = async () => {
  loading.value = true
  try {
    const params = {
      source: filters.source || 'all',
      type: filters.type || 'all',
      limit: filters.limit || 100
    }
    if (filters.scope === 'agent' && filters.uuid) {
      params.uuid = filters.uuid
    }
    const res = await api.get('/api/history', { params })
    rows.value = Array.isArray(res.data) ? res.data : []
  } catch (e) {
    ElMessage.error(e.response?.data?.error || '加载历史失败')
    rows.value = []
  } finally {
    loading.value = false
  }
}

const onFilterChange = () => {
  pushQuery()
  fetchHistory()
}

const onScopeChange = () => {
  if (filters.scope === 'all') {
    // keep uuid for re-select but query omits it
  } else if (!filters.uuid) {
    ElMessage.info('请先选择主机')
    filters.scope = 'all'
    return
  }
  pushQuery()
  fetchHistory()
}

const onUuidSelect = (val) => {
  if (val) {
    filters.scope = 'agent'
  } else {
    filters.scope = 'all'
  }
  pushQuery()
  fetchHistory()
}

const openDetail = (row) => {
  detail.row = row
  detail.visible = true
}

const copyOutput = async () => {
  try {
    await navigator.clipboard.writeText(detail.row?.output || '')
    ElMessage.success('已复制输出')
  } catch {
    ElMessage.warning('复制失败')
  }
}

watch(
  () => route.query,
  () => {
    syncQueryToFilters()
  }
)

onMounted(async () => {
  syncQueryToFilters()
  await fetchClients()
  await fetchHistory()
})
</script>

<style scoped>
.history-shell {
  display: flex;
  flex-direction: column;
  gap: 16px;
  min-height: 0;
}

.history-card {
  padding: 16px 18px 20px;
  background: var(--bg-panel-strong);
  border: 1px solid var(--line-muted);
  border-radius: var(--radius-sm);
}

.panel-head {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 12px;
  margin-bottom: 14px;
}

.panel-kicker {
  font-size: 11px;
  font-weight: 700;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: var(--text-muted);
}

.panel-head h3 {
  margin: 4px 0 6px;
  font-size: 18px;
  color: var(--text-strong);
}

.hint {
  margin: 0;
  font-size: 12px;
  color: var(--text-muted);
}

.filter-bar {
  display: flex;
  flex-wrap: wrap;
  gap: 14px 20px;
  align-items: center;
  margin-bottom: 14px;
  padding: 12px 14px;
  border-radius: 8px;
  background: var(--surface-soft);
  border: 1px solid var(--line-muted);
}

.filter-group {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}

.filter-label {
  font-size: 12px;
  font-weight: 700;
  color: var(--text-muted);
  min-width: 28px;
}

.agent-cell {
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.hostname-text {
  font-weight: 600;
  color: var(--text-strong);
}

.uuid-label {
  font-size: 11px;
  color: var(--text-muted);
}

.mono {
  font-family: 'JetBrains Mono', ui-monospace, monospace;
  font-size: 12px;
}

.input-text,
.output-preview {
  color: var(--text-muted);
  font-size: 12px;
}

.detail-grid {
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.detail-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 12px;
  padding: 6px 0;
  border-bottom: 1px solid var(--line-muted);
  font-size: 13px;
}

.detail-row span {
  color: var(--text-muted);
  min-width: 64px;
}

.detail-block {
  display: flex;
  flex-direction: column;
  gap: 6px;
  margin-top: 6px;
}

.detail-block > span {
  font-size: 12px;
  font-weight: 700;
  color: var(--text-muted);
}

.detail-pre {
  margin: 0;
  padding: 12px;
  border-radius: 8px;
  background: var(--surface-soft);
  border: 1px solid var(--line-muted);
  white-space: pre-wrap;
  word-break: break-all;
  max-height: 160px;
  overflow: auto;
  font-family: 'JetBrains Mono', ui-monospace, monospace;
  font-size: 12px;
}

.detail-pre.output {
  background: #111111;
  color: #f2f2f2;
  max-height: 320px;
  border-color: #222;
}

@media (max-width: 960px) {
  .filter-bar {
    flex-direction: column;
    align-items: flex-start;
  }
}
</style>
