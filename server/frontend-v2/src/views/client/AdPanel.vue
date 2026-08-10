<template>
  <div class="ad-panel">
    <div class="panel-head">
      <div>
        <h3>域渗透 (AD) · 模块能力</h3>
        <p class="hint">
          依赖<strong>模块能力</strong> <code>ad</code>（非插件）。身份 = agent 进程 token。
        </p>
      </div>
      <div class="head-actions">
        <el-button :loading="loading" @click="refresh">刷新</el-button>
      </div>
    </div>

    <el-alert
      v-if="!adModuleLoaded"
      type="error"
      show-icon
      :closable="false"
      class="mb gate-alert"
    >
      <template #title>
        <strong>模块能力未就绪</strong>：本机尚未加载 <code>ad</code> 模块，AD 操作已锁定。
      </template>
      <div class="gate-body">
        <p>请先推送产品模块 ad（域渗透 sacrificial worker），再执行发现 / 枚举 / Kerberoast 等。</p>
        <el-button type="primary" size="small" :loading="pushingAd" @click="pushAdModule">
          立即推送 ad 模块
        </el-button>
        <el-button size="small" :loading="checkingMod" @click="checkAdModule">重新检测</el-button>
      </div>
    </el-alert>
    <el-alert
      v-else
      type="success"
      show-icon
      :closable="false"
      class="mb"
      title="模块能力就绪：ad 已在本机加载，可使用 AD 功能。"
    />

    <el-alert
      type="warning"
      show-icon
      :closable="false"
      class="mb"
      title="DCSync 需管理员确认；图采集完成后：详情 → 预览图。"
    />

    <el-form inline class="mb" @submit.prevent>
      <el-form-item label="操作">
        <el-select
          v-model="op"
          filterable
          style="width: 240px"
          placeholder="选择操作"
          :disabled="!adModuleLoaded"
        >
          <el-option
            v-for="c in capabilities"
            :key="c.op"
            :label="formatOpName(c.op, capabilities)"
            :value="c.op"
          />
        </el-select>
      </el-form-item>
      <el-form-item label="域名">
        <el-input v-model="domain" placeholder="可选" style="width: 160px" :disabled="!adModuleLoaded" />
      </el-form-item>
      <el-form-item>
        <el-button type="primary" :loading="dispatching" :disabled="!adModuleLoaded" @click="dispatch">
          执行
        </el-button>
        <el-button :disabled="!adModuleLoaded" @click="ping">探测 Worker</el-button>
      </el-form-item>
    </el-form>

    <el-table :data="tasks" v-loading="loading" empty-text="无本机 AD 任务" class="task-table">
      <el-table-column label="操作" min-width="130">
        <template #default="{ row }">
          <span class="op-name" :title="row.op">{{ formatOpName(row.op, capabilities) }}</span>
        </template>
      </el-table-column>
      <el-table-column label="状态" width="100">
        <template #default="{ row }">
          <el-tag size="small" :type="statusTagType(row.status)" effect="plain" round>
            {{ formatStatusName(row.status) }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column label="错误码" min-width="120">
        <template #default="{ row }">
          <span
            class="cell-clip"
            :class="{ muted: !row.error_code }"
            :title="formatErrorName(row.error_code) || ''"
          >
            {{ errorSnippet(row.error_code, 24) }}
          </span>
        </template>
      </el-table-column>
      <el-table-column label="摘要" min-width="160">
        <template #default="{ row }">
          <span class="cell-clip" :title="summarySnippet(row.summary_json, 200)">
            {{ summarySnippet(row.summary_json, 48) }}
          </span>
        </template>
      </el-table-column>
      <el-table-column label="详情" width="88" fixed="right" align="center">
        <template #default="{ row }">
          <el-button size="small" link type="primary" @click="openDetail(row)">详情</el-button>
        </template>
      </el-table-column>
    </el-table>

    <!-- 任务详情 -->
    <el-drawer
      v-model="detailVisible"
      :title="detailTitle"
      size="480px"
      direction="rtl"
      class="ad-detail-drawer"
      destroy-on-close
    >
      <template v-if="detailTask">
        <div class="detail-grid">
          <div class="detail-row">
            <span class="k">操作</span>
            <span class="v">{{ formatOpName(detailTask.op, capabilities) }}
              <code class="raw-op">{{ detailTask.op }}</code>
            </span>
          </div>
          <div class="detail-row">
            <span class="k">状态</span>
            <span class="v">
              <el-tag size="small" :type="statusTagType(detailTask.status)" effect="plain">
                {{ formatStatusName(detailTask.status) }}
              </el-tag>
              <span class="raw-muted">{{ detailTask.status }}</span>
            </span>
          </div>
          <div class="detail-row">
            <span class="k">风险</span>
            <span class="v">{{ riskLabel(detailTask.risk_level) }}</span>
          </div>
          <div class="detail-row">
            <span class="k">错误码</span>
            <span class="v">
              <template v-if="detailTask.error_code">
                {{ formatErrorName(detailTask.error_code) }}
                <code v-if="formatErrorName(detailTask.error_code) !== detailTask.error_code" class="raw-op">
                  {{ detailTask.error_code }}
                </code>
              </template>
              <span v-else class="muted">无</span>
            </span>
          </div>
          <div class="detail-row">
            <span class="k">任务 ID</span>
            <span class="v">#{{ detailTask.id }} · {{ detailTask.req_id || '—' }}</span>
          </div>
          <div class="detail-row">
            <span class="k">时间</span>
            <span class="v">{{ formatTime(detailTask.created_at) }} → {{ formatTime(detailTask.updated_at) }}</span>
          </div>
        </div>

        <h4 class="block-title">参数</h4>
        <pre class="code-block">{{ prettyJson(detailTask.params_json) || '（无）' }}</pre>

        <h4 class="block-title">摘要全文</h4>
        <pre class="code-block">{{ prettyJson(detailTask.summary_json) || '（无）' }}</pre>

        <div v-if="detailTask.artifact_path" class="artifact-actions">
          <h4 class="block-title">产物</h4>
          <p class="artifact-path">{{ detailTask.artifact_path }}</p>
          <div class="action-row">
            <el-button size="small" type="primary" @click="downloadTask(detailTask)">下载产物</el-button>
            <el-button
              v-if="canPreviewGraph(detailTask)"
              size="small"
              type="success"
              :loading="previewingId === detailTask.id"
              @click="previewGraph(detailTask)"
            >
              预览图
            </el-button>
          </div>
        </div>
      </template>
    </el-drawer>

    <div v-if="graphPreview" class="graph-section">
      <div class="graph-head">
        <span>
          图预览 · 任务 #{{ graphTaskId }} · {{ graphPreview.domain || '—' }} ·
          {{ graphPreview.node_count }}/{{ graphPreview.edge_count }}
        </span>
        <el-button size="small" link @click="clearPreview">关闭</el-button>
      </div>
      <div class="graph-box">
        <v-chart class="graph-chart" :option="graphOption" autoresize />
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { use } from 'echarts/core'
import { CanvasRenderer } from 'echarts/renderers'
import { GraphChart } from 'echarts/charts'
import { TooltipComponent } from 'echarts/components'
import VChart from 'vue-echarts'
import api from '../../api/index'
import {
  errorSnippet,
  formatErrorName,
  formatOpName,
  formatStatusName,
  prettyJson,
  statusTagType,
  summarySnippet
} from '../../utils/ad_display'

use([CanvasRenderer, GraphChart, TooltipComponent])

const props = defineProps({
  clientId: { type: String, required: true },
  clientInfo: { type: Object, default: null },
  socket: { type: Object, default: null }
})

const KIND_COLORS = {
  Domain: '#111111',
  Computer: '#3a5a40',
  User: '#1d3557',
  Group: '#9a3412',
  Unknown: '#8c8c8c'
}

const loading = ref(false)
const dispatching = ref(false)
const capabilities = ref([])
const tasks = ref([])
const op = ref('ad_discover')
const domain = ref('')
const previewingId = ref(null)
const graphPreview = ref(null)
const graphTaskId = ref(null)
const adModuleLoaded = ref(false)
const pushingAd = ref(false)
const checkingMod = ref(false)

const detailVisible = ref(false)
const detailTask = ref(null)

const detailTitle = computed(() => {
  if (!detailTask.value) return '任务详情'
  return `详情 · ${formatOpName(detailTask.value.op, capabilities.value)}`
})

const graphOption = computed(() => {
  const g = graphPreview.value
  if (!g) return {}
  const nodes = (g.nodes || []).map((n) => {
    const kind = n.kind || 'Unknown'
    const color = KIND_COLORS[kind] || KIND_COLORS.Unknown
    return {
      id: n.id,
      name: n.name || n.id,
      symbolSize: kind === 'Domain' ? 30 : 18,
      itemStyle: { color, borderColor: '#fff', borderWidth: 1 },
      label: {
        show: true,
        position: 'bottom',
        fontSize: 10,
        formatter: n.name || n.id
      },
      kind
    }
  })
  const links = (g.edges || []).map((e) => ({
    source: e.source,
    target: e.target,
    kind: e.kind,
    lineStyle: { color: '#111', opacity: 0.5, curveness: 0.1 }
  }))
  return {
    backgroundColor: 'transparent',
    tooltip: {
      trigger: 'item',
      formatter: (p) => {
        if (p.data?.source != null) return `${p.data.kind || ''}: ${p.data.source} → ${p.data.target}`
        return `<b>${p.data?.name || ''}</b><br/>${p.data?.kind || ''}`
      }
    },
    series: [
      {
        type: 'graph',
        layout: 'force',
        data: nodes,
        links,
        roam: true,
        draggable: true,
        force: { repulsion: 360, edgeLength: 120, gravity: 0.08 },
        emphasis: { focus: 'adjacency' }
      }
    ]
  }
})

const riskLabel = (r) => {
  const m = { low: '低', medium: '中', high: '高', critical: '严重' }
  return m[String(r || '').toLowerCase()] || r || '—'
}

const formatTime = (t) => {
  if (!t) return '—'
  try {
    return new Date(t).toLocaleString('zh-CN', { hour12: false })
  } catch {
    return String(t)
  }
}

const openDetail = (row) => {
  detailTask.value = row
  detailVisible.value = true
}

const canPreviewGraph = (row) => {
  if (!row?.artifact_path) return false
  const opName = (row.op || '').toLowerCase()
  if (opName === 'ad_graph_collect' || opName === 'ad_acl_collect') return true
  const p = (row.artifact_path || '').toLowerCase()
  return p.includes('graph')
}

const checkAdModule = async () => {
  checkingMod.value = true
  try {
    const res = await api.get('/api/modules', { params: { uuid: props.clientId } })
    const list = res.data?.modules || []
    adModuleLoaded.value = list.some(
      (m) => (m.id === 'ad' || m === 'ad') && (m.loaded_on_agent || m.alive)
    )
    // Also try capabilities unlocked list when available
    try {
      const capRes = await api.get('/api/capabilities', { params: { uuid: props.clientId } })
      const mods = capRes.data?.module_capabilities || []
      const ad = mods.find((m) => m.id === 'ad')
      if (ad) adModuleLoaded.value = !!ad.loaded_on_agent || !!ad.loaded
    } catch (_) {
      /* optional */
    }
  } catch (_) {
    adModuleLoaded.value = false
  } finally {
    checkingMod.value = false
  }
}

const pushAdModule = async () => {
  pushingAd.value = true
  try {
    const res = await api.post('/api/modules/push', { uuid: props.clientId, id: 'ad' })
    adModuleLoaded.value = true
    ElMessage.success(res.data?.msg || 'ad 模块已推送')
    await checkAdModule()
  } catch (e) {
    const d = e?.response?.data || {}
    ElMessage.error(d.hint || d.error || '推送 ad 失败（请先在模块仓库登记）')
  } finally {
    pushingAd.value = false
  }
}

const refresh = async () => {
  loading.value = true
  try {
    const [caps, taskRes] = await Promise.all([
      api.get('/api/ad/capabilities'),
      api.get('/api/ad/tasks', { params: { uuid: props.clientId } })
    ])
    capabilities.value = caps.data.capabilities || []
    tasks.value = taskRes.data.tasks || []
    await checkAdModule()
  } catch (e) {
    ElMessage.error(e?.response?.data?.error || e.message)
  } finally {
    loading.value = false
  }
}

const gateErrorMessage = (e) => {
  const d = e?.response?.data || {}
  if (d.code === 'module_required' || d.error_code === 'module_required') {
    adModuleLoaded.value = false
    return d.hint || d.error || '需要先推送 ad 模块'
  }
  return d.error || e.message
}

const dispatch = async () => {
  if (!adModuleLoaded.value) {
    ElMessage.warning('请先推送 ad 模块')
    return
  }
  dispatching.value = true
  try {
    const params = {}
    if (domain.value) params.domain = domain.value
    await api.post('/api/ad/exec', { uuid: props.clientId, op: op.value, params })
    ElMessage.success('已下发')
    await refresh()
  } catch (e) {
    ElMessage.error(gateErrorMessage(e))
  } finally {
    dispatching.value = false
  }
}

const ping = async () => {
  if (!adModuleLoaded.value) {
    ElMessage.warning('请先推送 ad 模块')
    return
  }
  try {
    await api.post('/api/ad/ping', { uuid: props.clientId })
    ElMessage.success('探测已发送')
    await refresh()
  } catch (e) {
    ElMessage.error(gateErrorMessage(e))
  }
}

const downloadTask = async (row) => {
  try {
    const res = await api.get(`/api/ad/tasks/${row.id}/download`, { responseType: 'blob' })
    const url = URL.createObjectURL(res.data)
    const a = document.createElement('a')
    a.href = url
    a.download = `ad-task-${row.id}.bin`
    a.click()
    URL.revokeObjectURL(url)
  } catch (e) {
    ElMessage.error(e?.response?.data?.error || '下载失败')
  }
}

const previewGraph = async (row) => {
  previewingId.value = row.id
  try {
    const { data } = await api.get(`/api/ad/tasks/${row.id}/graph`)
    graphPreview.value = data.graph || null
    graphTaskId.value = row.id
    if (!graphPreview.value?.nodes?.length) {
      ElMessage.warning('图数据为空')
    }
  } catch (e) {
    const msg = e?.response?.data?.error || e?.response?.data?.hint || '预览失败'
    ElMessage.error(msg)
  } finally {
    previewingId.value = null
  }
}

const clearPreview = () => {
  graphPreview.value = null
  graphTaskId.value = null
}

onMounted(refresh)
</script>

<style scoped>
.ad-panel { padding: 8px 4px; }
.panel-head { display: flex; justify-content: space-between; margin-bottom: 12px; }
.hint { font-size: 13px; opacity: 0.8; margin: 4px 0 0; }
.mb { margin-bottom: 12px; }
code { font-size: 12px; }
.head-actions { display: flex; gap: 8px; }
.gate-alert :deep(.el-alert__description) { margin-top: 6px; }
.gate-body p { margin: 0 0 10px; font-size: 13px; }
.gate-body .el-button { margin-right: 8px; }
.op-name { font-weight: 500; }
.cell-clip {
  display: inline-block;
  max-width: 100%;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  vertical-align: bottom;
  font-size: 13px;
}
.muted { opacity: 0.45; }
.detail-grid {
  display: flex;
  flex-direction: column;
  gap: 10px;
  margin-bottom: 8px;
}
.detail-row {
  display: grid;
  grid-template-columns: 72px 1fr;
  gap: 8px;
  font-size: 13px;
  align-items: start;
}
.detail-row .k { opacity: 0.55; }
.detail-row .v { word-break: break-all; }
.raw-op {
  margin-left: 6px;
  font-size: 11px;
  opacity: 0.55;
  background: rgba(0, 0, 0, 0.04);
  padding: 1px 5px;
  border-radius: 4px;
}
.raw-muted {
  margin-left: 8px;
  font-size: 11px;
  opacity: 0.45;
}
.block-title {
  margin: 16px 0 8px;
  font-size: 13px;
  font-weight: 600;
}
.code-block {
  margin: 0;
  padding: 10px 12px;
  border-radius: 8px;
  background: rgba(17, 17, 17, 0.04);
  border: 1px solid rgba(17, 17, 17, 0.06);
  font-size: 12px;
  line-height: 1.45;
  max-height: 220px;
  overflow: auto;
  white-space: pre-wrap;
  word-break: break-word;
}
.artifact-path {
  font-size: 12px;
  opacity: 0.7;
  word-break: break-all;
  margin: 0 0 10px;
}
.action-row { display: flex; flex-wrap: wrap; gap: 8px; }
.graph-section {
  margin-top: 16px;
  border: 1px solid rgba(17, 17, 17, 0.08);
  border-radius: 10px;
  padding: 10px 12px;
  background: rgba(255, 250, 242, 0.45);
}
.graph-head {
  display: flex;
  justify-content: space-between;
  align-items: center;
  font-size: 13px;
  margin-bottom: 8px;
  opacity: 0.85;
}
.graph-box { width: 100%; height: 360px; }
.graph-chart { width: 100%; height: 100%; }
</style>
