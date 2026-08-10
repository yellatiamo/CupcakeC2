<template>
  <div class="plugin-manager">
    <!-- Top compact status indicators -->
    <section class="stat-grid">
      <article class="surface-card stat-card">
        <div class="stat-card__icon">
          <el-icon><Tools /></el-icon>
        </div>
        <div>
          <span class="stat-card__label">可用插件</span>
          <div class="stat-card__value">{{ plugins.length }}</div>
        </div>
      </article>

      <article class="surface-card stat-card">
        <div class="stat-card__icon">
          <el-icon><Monitor /></el-icon>
        </div>
        <div>
          <span class="stat-card__label">正在执行</span>
          <div class="stat-card__value">{{ runningTasks.length }}</div>
        </div>
      </article>
    </section>

    <!-- Unified Workspace Layout -->
    <div class="workspace-layout">
      <!-- Left: Plugin List -->
      <div class="panel-column left-panel">
        <div class="surface-card card-container">
          <div class="card-header">
            <span class="header-title"><el-icon><Collection /></el-icon> 插件库</span>
            <el-input 
              v-model="search" 
              placeholder="搜索插件..." 
              clearable 
              class="search-input"
              :prefix-icon="Search"
            />
          </div>

          <div class="card-body">
            <el-table :data="filteredPlugins" style="width: 100%; height: 100%;" height="100%">
              <el-table-column label="插件名称" width="220">
                <template #default="scope">
                  <div class="plugin-name-cell">
                    <span class="name">{{ scope.row.name }}</span>
                    <el-tag size="small" :type="getTypeTag(scope.row.type)" effect="light">{{ scope.row.type }}</el-tag>
                  </div>
                </template>
              </el-table-column>
              <el-table-column prop="description" label="描述" show-overflow-tooltip />
              <el-table-column label="操作" width="100" align="center">
                <template #default="scope">
                  <el-button 
                    type="primary" 
                    circle 
                    :icon="CaretRight" 
                    @click="prepRun(scope.row)" 
                  />
                </template>
              </el-table-column>
            </el-table>
          </div>
        </div>
      </div>

      <!-- Right: Task History -->
      <div class="panel-column right-panel">
        <div class="surface-card card-container">
          <div class="card-header">
            <span class="header-title"><el-icon><Clock /></el-icon> 执行历史 (最近 10 条)</span>
            <div class="header-actions">
              <el-button link type="primary" @click="goFullHistory">全部历史</el-button>
              <el-button link type="primary" @click="fetchLogs">刷新</el-button>
            </div>
          </div>

          <div class="card-body task-list-body" v-loading="loadingLogs">
            <div class="task-list">
              <el-empty v-if="history.length === 0" description="暂无执行记录" />
              <div v-for="log in history" :key="log.req_id" class="task-item" :class="log.status">
                <div class="task-info">
                  <div class="task-type-row">
                    <span class="task-type">{{ log.type }}</span>
                    <el-tag size="small" :type="sourceTagType(log.source)" effect="light">{{ sourceLabel(log.source) }}</el-tag>
                  </div>
                  <span class="task-id">ID: {{ log.req_id }}</span>
                  <span class="task-meta" v-if="log.created_by">by {{ log.created_by }}</span>
                  <span class="task-time">{{ formatDate(log.created_at) }}</span>
                </div>
                <div class="task-actions">
                  <el-tag size="small" :type="getStatusType(log.status)">{{ log.status }}</el-tag>
                  <el-button 
                    v-if="log.status === 'completed'" 
                    link 
                    type="primary" 
                    @click="viewResult(log)"
                  >查看回显</el-button>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Run Options Dialog -->
    <el-dialog v-model="runDialog.visible" title="运行插件配置" width="500px">
      <el-form label-position="top">
        <el-form-item label="命令行参数">
          <el-input 
            v-model="runDialog.args" 
            type="textarea" 
            :rows="3" 
            placeholder="例如: -h 192.168.1.1 --port 445 (如果是注入，请输入 PID)"
          />
        </el-form-item>
        <div class="opsec-tip">
          <el-icon><Warning /></el-icon>
          插件库 = BOF / shellcode <strong>载荷</strong>。BOF 走 <code>bof</code> 模块在
          <strong>Agent 进程内</strong>无文件执行；注入类载荷走 <code>inject</code> 牺牲进程。
          载荷不在 Agent 长期缓存。
        </div>
      </el-form>
      <template #footer>
        <el-button @click="runDialog.visible = false">取消</el-button>
        <el-button type="primary" :loading="runDialog.loading" @click="executePlugin">立即执行</el-button>
      </template>
    </el-dialog>

    <!-- Result Viewer Dialog -->
    <el-dialog v-model="resultDialog.visible" :title="'任务回显: ' + resultDialog.taskId" width="80%" top="5vh">
      <div class="result-viewer" v-loading="resultDialog.loading">
        <pre v-if="resultDialog.content">{{ resultDialog.content }}</pre>
        <el-empty v-else description="暂无输出或正在加载..." />
      </div>
      <template #footer>
        <el-button @click="resultDialog.visible = false">关闭</el-button>
        <el-button type="primary" :icon="Download" @click="downloadLog">下载 TXT</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, reactive, computed, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { 
  Tools, Monitor, Collection, Search, CaretRight, 
  Clock, Warning, Download 
} from '@element-plus/icons-vue'
import api from '../../api/index'
import { ElMessage } from 'element-plus'

const props = defineProps({
  clientId: String,
  clientInfo: Object
})

const router = useRouter()

const search = ref('')
const plugins = ref([])
const history = ref([])
const loadingLogs = ref(false)

const filteredPlugins = computed(() => {
  return plugins.value.filter(p => {
    // 1. Filter by search query
    const matchesSearch = p.name.toLowerCase().includes(search.value.toLowerCase()) || 
                          p.type.toLowerCase().includes(search.value.toLowerCase())
    if (!matchesSearch) return false

    // 2. Filter by Client OS
    if (!props.clientInfo?.os) return true // Fallback if os info missing
    
    const clientOS = props.clientInfo.os.toLowerCase()
    const requiredOS = (p.required_os || '').toLowerCase()
    
    // If plugin specifies an OS, it must match or be 'multi'
    if (requiredOS && requiredOS !== 'multi' && requiredOS !== 'any') {
        return clientOS.includes(requiredOS) || requiredOS.includes(clientOS)
    }
    
    return true
  })
})

const runningTasks = computed(() => history.value.filter(h => h.status === 'pending'))

// Dialogs State
const runDialog = reactive({
  visible: false,
  loading: false,
  args: '',
  selectedPlugin: null
})

const resultDialog = reactive({
  visible: false,
  loading: false,
  taskId: '',
  content: ''
})

const fetchPlugins = async () => {
  try {
    const res = await api.get('/api/plugins')
    plugins.value = res.data
  } catch (e) {
    ElMessage.error('无法获取插件列表')
  }
}

const fetchLogs = async () => {
    loadingLogs.value = true
    try {
        // Prefer source-aware agent history; keep existing endpoint shape.
        const histRes = await api.get(`/api/clients/history/${props.clientId}`, {
          params: { source: 'all', limit: 50 }
        })
        // 只显示插件执行记录，过滤掉系统命令（migrate、shell、heartbeat等）
        const systemCommands = ['migrate', 'shell', 'shell_interactive', 'shell_exit', 'heartbeat', 'file_upload', 'file_download', 'file_upload_chunk', 'file_download_chunk', 'file_delete', 'file_list', 'module_stage', 'module_unload']
        const pluginOnly = (histRes.data || []).filter(log => {
          const t = (log.type || '').toLowerCase()
          if (systemCommands.includes(t)) return false
          if (t.startsWith('file_') || t.startsWith('process_') || t.startsWith('ad_') || t.startsWith('module_')) return false
          return true
        })
        history.value = pluginOnly.slice(0, 10)
    } catch (e) {
        console.error('Logs fetch failed', e)
    } finally {
        loadingLogs.value = false
    }
}

const goFullHistory = () => {
  router.push({
    name: 'History',
    query: {
      uuid: props.clientId || undefined,
      type: 'plugin',
      source: 'all'
    }
  })
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
  return 'success'
}

const prepRun = (plugin) => {
  runDialog.selectedPlugin = plugin
  runDialog.args = ''
  runDialog.visible = true
}

/** Poll history/result until completed|failed or timeout; surface STDERR to user. */
const waitPluginResult = async (taskId, maxMs = 45000) => {
  const started = Date.now()
  let lastOutput = ''
  while (Date.now() - started < maxMs) {
    await new Promise((r) => setTimeout(r, 1200))
    try {
      const histRes = await api.get(`/api/clients/history/${props.clientId}`, {
        params: { source: 'all', limit: 30 }
      })
      const row = (histRes.data || []).find((x) => x.req_id === taskId)
      if (row && (row.status === 'completed' || row.status === 'failed')) {
        lastOutput = row.output || ''
        // Prefer task file if present
        try {
          const res = await api.get(`/api/plugins/result/${taskId}`)
          if (res.data) lastOutput = typeof res.data === 'string' ? res.data : String(res.data)
        } catch (_) {
          /* use history output */
        }
        return { status: row.status, output: lastOutput }
      }
    } catch (_) {
      /* keep polling */
    }
  }
  // Timeout: try one more result file
  try {
    const res = await api.get(`/api/plugins/result/${taskId}`)
    lastOutput = typeof res.data === 'string' ? res.data : String(res.data || '')
  } catch (_) {
    /* empty */
  }
  return { status: 'timeout', output: lastOutput }
}

const executePlugin = async () => {
  if (!runDialog.selectedPlugin) return
  runDialog.loading = true
  try {
    const res = await api.post('/api/plugins/run', {
      agent_id: props.clientId,
      plugin_id: runDialog.selectedPlugin.id,
      args: runDialog.args
    })
    const taskId = res.data?.task_id
    if (!taskId) {
      ElMessage.warning('已提交但未返回 task_id')
      runDialog.visible = false
      return
    }
    ElMessage.info(`已下发，等待回显… (${taskId.slice(0, 8)})`)
    runDialog.visible = false

    const { status, output } = await waitPluginResult(taskId)
    await fetchLogs()

    const errText = output || ''
    const hasStderr =
      /\[STDERR\]/i.test(errText) ||
      /isolated bof:/i.test(errText) ||
      /WriteFile failed/i.test(errText) ||
      /host runtime missing/i.test(errText) ||
      /module_required/i.test(errText)

    if (status === 'failed' || hasStderr) {
      ElMessage.error({
        message: (errText || '插件执行失败').slice(0, 280),
        duration: 8000,
        showClose: true
      })
      resultDialog.taskId = taskId
      resultDialog.content = errText || '（无输出，仅失败状态）'
      resultDialog.visible = true
    } else if (status === 'timeout') {
      ElMessage.warning('等待回显超时：任务可能仍在跑，或 agent 已被杀/未回包。请到历史记录查看。')
    } else {
      ElMessage.success('插件执行完成')
      if (errText) {
        resultDialog.taskId = taskId
        resultDialog.content = errText
        resultDialog.visible = true
      }
    }
  } catch (e) {
    const d = e?.response?.data || {}
    const msg = d.hint || d.error || e.message || '执行失败'
    ElMessage.error(msg)
  } finally {
    runDialog.loading = false
  }
}

const viewResult = async (log) => {
  resultDialog.taskId = log.req_id
  resultDialog.content = ''
  resultDialog.visible = true
  resultDialog.loading = true

  try {
    const res = await api.get(`/api/plugins/result/${log.req_id}`)
    resultDialog.content = typeof res.data === 'string' ? res.data : String(res.data)
  } catch (e) {
    // Fallback: history row output (DB), then explain
    if (log.output) {
      resultDialog.content = log.output
    } else {
      try {
        const histRes = await api.get(`/api/clients/history/${props.clientId}`, {
          params: { source: 'all', limit: 50 }
        })
        const row = (histRes.data || []).find((x) => x.req_id === log.req_id)
        if (row?.output) {
          resultDialog.content = row.output
        } else if (log.status === 'pending') {
          resultDialog.content =
            '任务仍为 pending：agent 尚未回包。常见原因：bof 模块未就绪、注入的牺牲进程被 AV 杀掉、或仍在执行。可强制刷新历史记录。'
        } else {
          resultDialog.content = '无法加载日志，可能文件已被清理或尚未生成。'
        }
      } catch (_) {
        resultDialog.content = '无法加载日志，可能文件已被清理或尚未生成。'
      }
    }
  } finally {
    resultDialog.loading = false
  }
}

const downloadLog = () => {
    const blob = new Blob([resultDialog.content], { type: 'text/plain' })
    const url = window.URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `task_${resultDialog.taskId}.txt`
    a.click()
}

// Helpers
const getTypeTag = (type) => {
  if (type === 'execute-assembly') return 'warning'
  if (type === 'memfd-exec' || type === 'linux-script') return 'success'
  if (type === 'shellcode-inject' || type === 'native-pe') return 'danger'
  if (type === 'bof-exec') return 'info'
  return ''
}

const getStatusType = (status) => {
  if (status === 'completed') return 'success'
  if (status === 'pending') return 'info'
  if (status === 'failed') return 'danger'
  return ''
}

const formatDate = (ts) => {
    if (!ts) return '-'
    const d = new Date(ts)
    return d.toLocaleTimeString()
}

onMounted(() => {
  fetchPlugins()
  fetchLogs()
})
</script>

<style scoped>
.plugin-manager {
  display: flex;
  flex-direction: column;
  height: 100%;
  gap: 16px;
  background: var(--surface-soft);
}

.stat-grid {
  display: flex;
  gap: 16px;
  flex-shrink: 0;
}

.stat-card {
  flex: 1;
  display: flex;
  align-items: center;
  gap: 14px;
  min-height: 80px;
  padding: 16px 20px;
  background: var(--bg-panel-strong);
  border: 1px solid var(--line-muted);
  border-radius: var(--radius-sm);
}

.stat-card__icon {
  flex: 0 0 40px;
  width: 40px;
  height: 40px;
  display: grid;
  place-items: center;
  border-radius: 12px;
  background: var(--accent-soft);
  color: var(--accent-strong);
  font-size: 18px;
}

.stat-card__label {
  font-size: 12px;
  font-weight: 600;
  color: var(--text-muted);
}

.stat-card__value {
  margin-top: 4px;
  font-size: 24px;
  font-weight: 800;
  color: var(--text-strong);
}

/* Workspace layout using flex instead of fixed viewport heights */
.workspace-layout {
  display: flex;
  gap: 16px;
  flex: 1;
  min-height: 0;
}

.panel-column {
  display: flex;
  flex-direction: column;
  min-height: 0;
}

.left-panel {
  flex: 14;
}

.right-panel {
  flex: 10;
}

.card-container {
  height: 100%;
  display: flex;
  flex-direction: column;
  min-height: 0;
  border-radius: var(--radius-sm);
  background: var(--bg-panel-strong);
  border: 1px solid var(--line-muted);
  overflow: hidden;
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 12px 16px;
  border-bottom: 1px solid var(--line-muted);
  background: var(--bg-panel-strong);
  flex-shrink: 0;
}

.header-title {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font-size: 14px;
  font-weight: 700;
  color: var(--text-strong);
}

.header-actions {
  display: inline-flex;
  align-items: center;
  gap: 4px;
}

.task-type-row {
  display: inline-flex;
  align-items: center;
  gap: 6px;
}

.task-meta {
  font-size: 11px;
  color: var(--text-muted);
}

.search-input {
  width: 220px;
}

.card-body {
  flex: 1;
  min-height: 0;
  overflow: hidden;
}

.plugin-name-cell {
  display: flex;
  flex-direction: column;
  gap: 4px;
  align-items: flex-start;
}

.plugin-name-cell .name {
  font-weight: 700;
  color: var(--text-strong);
}

.task-list-body {
  display: flex;
  flex-direction: column;
  overflow: hidden;
}

.task-list {
  flex: 1;
  display: flex;
  flex-direction: column;
  gap: 10px;
  padding: 16px;
  overflow-y: auto;
}

.task-item {
  padding: 12px;
  border-radius: 8px;
  border: 1px solid var(--line-muted);
  background: var(--bg-panel-strong);
  display: flex;
  justify-content: space-between;
  align-items: center;
  transition: all 0.2s ease;
}

.task-item:hover {
  background: var(--surface-soft);
}

.task-item.completed {
  border-left: 4px solid var(--el-color-success);
}

.task-item.pending {
  border-left: 4px solid var(--el-color-primary);
}

.task-item.failed {
  border-left: 4px solid var(--el-color-danger);
}

.task-info {
  display: flex;
  flex-direction: column;
  gap: 3px;
}

.task-type {
  font-weight: 700;
  font-size: 13px;
  color: var(--text-strong);
}

.task-id {
  font-size: 11px;
  color: var(--text-muted);
  font-family: 'JetBrains Mono', monospace;
}

.task-time {
  font-size: 11px;
  color: var(--text-muted);
}

.task-actions {
  display: flex;
  flex-direction: column;
  align-items: flex-end;
  gap: 6px;
}

.opsec-tip {
  margin-top: 15px;
  padding: 10px;
  background: rgba(230, 162, 60, 0.08);
  border: 1px solid rgba(230, 162, 60, 0.2);
  border-radius: 8px;
  font-size: 12px;
  color: var(--el-color-warning);
  display: flex;
  align-items: center;
  gap: 8px;
}

.result-viewer {
  background: #111111;
  color: #f2f2f2;
  padding: 20px;
  border-radius: 8px;
  max-height: 60vh;
  overflow: auto;
}

.result-viewer pre {
  margin: 0;
  font-family: 'JetBrains Mono', monospace;
  white-space: pre-wrap;
  word-break: break-all;
}

@media (max-width: 960px) {
  .workspace-layout {
    flex-direction: column;
    overflow-y: auto;
  }

  .left-panel,
  .right-panel {
    flex: none;
    height: 400px;
  }

  .card-header {
    flex-direction: row;
    align-items: center;
  }

  .search-input {
    width: 150px;
  }
}
</style>
