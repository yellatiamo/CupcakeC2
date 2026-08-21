<template>
  <div class="module-panel">
    <div class="panel-head">
      <div>
        <h3>模块</h3>
        <p class="hint">
          本页推送<strong>模块能力</strong>：
          <code>bof</code>（进程内经典 BOF 执行器，Manual-Map 无文件加载）、
          <code>inject</code>（shellcode 注入 worker）、
          <code>ad</code>（域渗透 worker）。
          「已就绪」= 模块已在 Agent 侧可执行；inject / ad 为独立 worker，而非常驻进程。
        </p>
      </div>
      <div class="head-actions">
        <el-button :loading="listing" @click="listOnAgent">刷新就绪状态</el-button>
        <el-button :loading="loading" @click="refresh">刷新仓库</el-button>
      </div>
    </div>

    <el-alert
      v-if="!modules.length"
      type="warning"
      show-icon
      :closable="false"
      title="仓库为空：请在「模块」页上传 bof / inject / ad"
      class="mb"
    />

    <el-alert
      v-if="aliveSummary"
      type="success"
      show-icon
      :closable="false"
      :title="aliveSummary"
      class="mb"
    />
    <el-alert
      v-else-if="listedOnce"
      type="info"
      show-icon
      :closable="false"
      title="当前主机未检测到已就绪模块（可推送 bof / inject / ad）"
      class="mb"
    />

    <el-table :data="displayModules" class="mt" v-loading="loading" empty-text="无已登记模块">
      <el-table-column prop="id" label="ID" width="100" />
      <el-table-column prop="name" label="名称" width="130" />
      <el-table-column prop="description" label="描述" min-width="180" show-overflow-tooltip />
      <el-table-column label="模块能力" min-width="150">
        <template #default="{ row }">
          <div class="cap-row">
            <el-tag
              v-for="cap in (row.capabilities || capFallback(row.id))"
              :key="cap"
              size="small"
              type="warning"
              effect="plain"
            >{{ cap }}</el-tag>
          </div>
        </template>
      </el-table-column>
      <el-table-column label="签名" width="90">
        <template #default="{ row }">
          <el-tag size="small" :type="row.signed ? 'success' : 'info'" effect="plain">
            {{ row.signed ? '已签' : '—' }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column label="大小" width="90">
        <template #default="{ row }">{{ formatSize(row.size) }}</template>
      </el-table-column>
      <el-table-column label="本机状态" width="150">
        <template #default="{ row }">
          <el-tag v-if="isAlive(row)" type="success" size="small" effect="dark">
            {{ statusLabel(row) }}
          </el-tag>
          <el-tag v-else type="info" size="small">未推送</el-tag>
        </template>
      </el-table-column>
      <el-table-column label="操作" width="160" fixed="right">
        <template #default="{ row }">
          <el-button
            size="small"
            type="primary"
            :loading="pushing === row.id"
            :disabled="isAlive(row)"
            @click="pushModule(row)"
          >
            {{ isAlive(row) ? '已就绪' : '推送到本机' }}
          </el-button>
        </template>
      </el-table-column>
    </el-table>

    <p class="foot-note">
      bof：进程内 Manual-Map（无落盘）。inject / ad：独立 worker。
    </p>
  </div>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { ElMessage, ElNotification } from 'element-plus'
import api from '../../api/index'

const props = defineProps({
  clientId: { type: String, required: true },
  clientInfo: { type: Object, default: null },
  socket: { type: Object, default: null }
})

const loading = ref(false)
const pushing = ref('')
const listing = ref(false)
const modules = ref([])
const listedOnce = ref(false)
// Keep in sync with server productModuleIDs (bof | inject | ad)
const PRODUCT_IDS = new Set(['bof', 'inject', 'ad'])

const displayModules = computed(() => {
  const clientOS = (props.clientInfo?.os || '').toLowerCase()
  // Product three modules only (+ any already alive for edge cases), filtered by platform support.
  return modules.value.filter((m) => {
    if (!PRODUCT_IDS.has(m.id) && !isAlive(m)) return false
    // Server already filters ListCatalog by OS; this is a second line of defense in the UI.
    // Known windows-only: ad, inject, bof. Hide if client is linux and not alive.
    const winOnly = new Set(['ad', 'inject', 'bof'])
    if (winOnly.has(m.id) && clientOS && !clientOS.includes('win') && !isAlive(m)) {
      return false
    }
    return true
  })
})

const aliveSummary = computed(() => {
  const alive = modules.value.filter((m) => isAlive(m)).map((m) => m.name || m.id)
  if (!alive.length) return ''
  return `本机已就绪（缓存/可执行）：${alive.join('、')}`
})

const formatSize = (n) => {
  if (!n) return '—'
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / 1024 / 1024).toFixed(2)} MB`
}

const isAlive = (row) => !!(row && (row.loaded_on_agent || row.alive))

/** bof is mapped into the agent process; inject/ad are sacrificial workers */
const statusLabel = (row) => {
  if (!isAlive(row)) return '未推送'
  if (row.id === 'bof') return '已映射·就绪'
  if (row.id === 'ad') return '已推送·worker'
  return '已推送·就绪'
}

/** Agent module_list returns "id:mode" (e.g. bof:mem) */
const parseAgentModuleIds = (raw) => {
  return String(raw || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)
    .map((s) => s.split(':')[0].trim())
    .filter(Boolean)
}

const CAP_FALLBACK = {
  bof: ['bof'],
  inject: ['inject'],
  ad: ['ad_ops']
}
const capFallback = (id) => CAP_FALLBACK[id] || []

const normalizeList = (list) =>
  (list || []).map((m) =>
    typeof m === 'string'
      ? { id: m, name: m, description: '', size: 0, kind: 'custom', loaded_on_agent: false, capabilities: capFallback(m) }
      : { ...m, loaded_on_agent: !!m.loaded_on_agent, capabilities: m.capabilities || capFallback(m.id) }
  )

const refresh = async () => {
  loading.value = true
  try {
    const res = await api.get('/api/modules', { params: { uuid: props.clientId } })
    modules.value = normalizeList(res.data?.modules)
  } catch (e) {
    ElMessage.error(e?.response?.data?.error || '加载失败')
  } finally {
    loading.value = false
  }
}

const pushModule = async (row) => {
  const id = row.id
  if (isAlive(row)) {
    ElMessage.info(
      id === 'bof'
        ? 'bof 模块已在本机映射就绪（进程内加载），无需重复推送'
        : `模块「${row.name || id}」已在本机就绪，无需重复推送`
    )
    return
  }
  pushing.value = id
  try {
    const res = await api.post('/api/modules/push', { uuid: props.clientId, id })
    const data = res.data || {}
    row.loaded_on_agent = true
    row.alive = true
    const detail = data.detail ? String(data.detail) : ''
    ElNotification({
      title: '推送成功',
      message:
        data.msg ||
        (id === 'bof'
          ? `bof 模块已映射（进程内执行 BOF，无文件落地）${detail ? ' · ' + detail : ''}`
          : `模块 ${data.name || id} 已在目标主机就绪`),
      type: 'success',
      duration: 5000
    })
    if (data.warning) ElMessage.warning(data.warning)
    await refresh()
    try {
      await listOnAgent()
    } catch (_) {
      /* optional */
    }
  } catch (e) {
    ElNotification({
      title: '推送失败',
      message: e?.response?.data?.error || '推送失败',
      type: 'error',
      duration: 5000
    })
  } finally {
    pushing.value = ''
  }
}

const listOnAgent = async () => {
  listing.value = true
  try {
    const res = await api.post('/api/modules/query', { uuid: props.clientId })
    listedOnce.value = true
    // Prefer catalog with loaded flags; do NOT dump raw JSON to the page
    if (Array.isArray(res.data?.modules)) {
      modules.value = normalizeList(res.data.modules)
    } else {
      await refresh()
    }
    // Agent returns "id:mode" e.g. "bof:mem,inject:worker"
    const raw = (res.data?.result || '').trim()
    if (raw) {
      const ids = parseAgentModuleIds(raw)
      for (const m of modules.value) {
        if (ids.includes(m.id)) {
          m.loaded_on_agent = true
          m.alive = true
        }
      }
      ElMessage.success(`已同步：Agent 报告就绪 ${ids.join(', ')}（原始: ${raw}）`)
    } else {
      ElMessage.success('已同步：Agent 当前无已就绪模块')
    }
  } catch (e) {
    ElMessage.error(e?.response?.data?.error || '查询失败')
  } finally {
    listing.value = false
  }
}

onMounted(async () => {
  await refresh()
  try {
    await listOnAgent()
  } catch (_) {
    /* optional */
  }
})
</script>

<style scoped>
.module-panel { padding: 16px 20px; }
.panel-head {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 16px;
  gap: 12px;
}
.head-actions { display: flex; gap: 8px; flex-shrink: 0; }
.hint { margin: 8px 0 0; opacity: 0.75; line-height: 1.5; max-width: 640px; }
.mt { margin-top: 16px; }
.mb { margin-bottom: 12px; }
.foot-note {
  margin-top: 14px;
  font-size: 12px;
  opacity: 0.65;
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 4px;
}
.cap-row { display: flex; flex-wrap: wrap; gap: 4px; }
</style>
