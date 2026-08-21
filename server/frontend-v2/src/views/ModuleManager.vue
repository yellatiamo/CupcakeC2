<template>
  <div class="view-shell module-shell">
    <section class="surface-card module-card">
      <div class="panel-head">
        <div>
          <span class="panel-kicker">模块能力 · L2 Modules</span>
          <h3>模块仓库</h3>
          <p class="hint">
            L2 产品模块仓库：
            <code>bof</code>（进程内经典 BOF 执行器，Manual-Map 无文件）、
            <code>inject</code>（shellcode 注入 worker）、
            <code>ad</code>（域渗透 worker）。
            插件是载荷，依赖对应模块。
          </p>
        </div>
        <el-button type="primary" :loading="loading" @click="refresh">
          刷新列表
        </el-button>
      </div>

      <div class="workflow">
        <div class="step">
          <strong>bof</strong>
          <span>模块能力：bof（Agent 进程内经典 BOF，Manual-Map 无文件）</span>
        </div>
        <div class="step">
          <strong>inject</strong>
          <span>模块能力：inject</span>
        </div>
        <div class="step">
          <strong>ad</strong>
          <span>模块能力：ad_ops</span>
        </div>
      </div>

      <el-divider />

      <el-form label-position="top" class="upload-form" @submit.prevent>
        <div class="form-row">
          <el-form-item label="模块 ID" required>
            <el-select v-model="uploadForm.id" style="width: 240px">
              <el-option label="bof — 进程内 BOF 执行器" value="bof" />
              <el-option label="inject — 进程注入" value="inject" />
              <el-option label="ad — 域渗透 worker" value="ad" />
            </el-select>
          </el-form-item>
          <el-form-item label="模块文件 (.exe / .dll / .bin)" required>
            <input type="file" ref="fileInput" @change="onFileChange" />
          </el-form-item>
          <el-form-item label=" ">
            <el-button type="primary" :loading="uploading" :disabled="!uploadForm.file" @click="doUpload">
              上传并登记
            </el-button>
          </el-form-item>
        </div>
      </el-form>

      <el-table :data="modules" v-loading="loading" empty-text="仓库为空 — 请先上传 bof / inject / ad">
        <el-table-column prop="id" label="ID" width="100" />
        <el-table-column prop="name" label="名称" width="120" />
        <el-table-column prop="description" label="描述" min-width="200" show-overflow-tooltip />
        <el-table-column prop="kind" label="类型" width="90">
          <template #default="{ row }">
            <el-tag size="small" :type="kindTag(row.kind)">{{ kindLabel(row.kind) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="模块能力" min-width="160">
          <template #default="{ row }">
            <div class="cap-row">
              <el-tag
                v-for="cap in (row.capabilities || [])"
                :key="cap"
                size="small"
                type="warning"
                effect="plain"
                class="cap-tag"
              >{{ cap }}</el-tag>
              <span v-if="!(row.capabilities || []).length" class="muted">—</span>
            </div>
          </template>
        </el-table-column>
        <el-table-column label="签名/版本" width="140">
          <template #default="{ row }">
            <el-tag size="small" :type="row.signed ? 'success' : 'info'" effect="plain">
              {{ row.signed ? '已签名' : '未签名' }}
            </el-tag>
            <div class="ver-line">{{ row.version || '—' }}</div>
          </template>
        </el-table-column>
        <el-table-column label="大小" width="90">
          <template #default="{ row }">{{ formatSize(row.size) }}</template>
        </el-table-column>
        <el-table-column label="目标状态" width="110">
          <template #default="{ row }">
            <el-tag v-if="isPushedAlive(row.id)" size="small" type="success" effect="dark">
              {{ row.id === 'bof' ? '已映射就绪' : '已就绪' }}
            </el-tag>
            <el-tag v-else-if="pushTarget[row.id]" size="small" type="info">未就绪</el-tag>
            <span v-else class="muted">选主机</span>
          </template>
        </el-table-column>
        <el-table-column label="操作" min-width="420" fixed="right">
          <template #default="{ row }">
            <el-button size="small" @click="packPreview(row)">打包预览</el-button>
            <el-select
              v-model="pushTarget[row.id]"
              placeholder="选择在线主机"
              clearable
              filterable
              style="width: 180px; margin: 0 8px"
              @change="() => onTargetChange(row.id)"
            >
              <el-option
                v-for="c in onlineClients"
                :key="c.uuid"
                :label="`${c.hostname || c.uuid.slice(0, 8)} (${c.ip || '-'})`"
                :value="c.uuid"
                :disabled="!targetIsCompatible(c.uuid, row.id)"
              />
            </el-select>
            <el-button
              size="small"
              type="primary"
              :loading="pushing === row.id"
              :disabled="!pushTarget[row.id] || isPushedAlive(row.id) || !targetIsCompatible(pushTarget[row.id], row.id)"
              @click="pushToAgent(row)"
            >
              {{ isPushedAlive(row.id)
                ? (row.id === 'bof' ? '已映射就绪' : '已在目标就绪')
                : (targetIsCompatible(pushTarget[row.id], row.id) ? '推送' : '平台不匹配') }}
            </el-button>
            <el-button
              v-if="isAdmin"
              size="small"
              type="danger"
              :loading="deleting === row.id"
              :disabled="isPushedAlive(row.id)"
              :title="isPushedAlive(row.id) ? '目标仍标记已加载，建议先换主机或确认后再删仓库' : '从仓库删除'"
              @click="deleteModule(row)"
            >
              删除
            </el-button>
          </template>
        </el-table-column>
      </el-table>

      <el-alert
        v-if="packInfo"
        class="pack-alert"
        type="info"
        :closable="true"
        @close="packInfo = ''"
        :title="packInfo"
      />
    </section>
  </div>
</template>

<script setup>
import { onMounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox, ElNotification } from 'element-plus'
import api from '../api/index'

const loading = ref(false)
const uploading = ref(false)
const pushing = ref('')
const deleting = ref('')
const modules = ref([])
const onlineClients = ref([])
const pushTarget = reactive({})
/** moduleId -> { [uuid]: true } when staged/alive on that agent */
const aliveMap = reactive({})
const packInfo = ref('')
const fileInput = ref(null)

const userRole = (() => {
  try {
    return (JSON.parse(localStorage.getItem('cupcake_user') || '{}').role || 'operator').toLowerCase()
  } catch {
    return 'operator'
  }
})()
const isAdmin = userRole === 'admin' || userRole === 'administrator'

const uploadForm = reactive({
  id: 'bof',
  file: null
})

const formatSize = (n) => {
  if (!n) return '—'
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / 1024 / 1024).toFixed(2)} MB`
}

const kindLabel = (k) => {
  const m = { host: '宿主', runtime: '运行时', legacy: '遗留', custom: '自定义' }
  return m[k] || k || '—'
}
const kindTag = (k) => {
  if (k === 'host') return 'warning'
  if (k === 'legacy') return 'info'
  return 'success'
}

const isPushedAlive = (moduleId) => {
  const uuid = pushTarget[moduleId]
  if (!uuid) return false
  return !!(aliveMap[moduleId] && aliveMap[moduleId][uuid])
}

const markAlive = (moduleId, uuid) => {
  if (!aliveMap[moduleId]) aliveMap[moduleId] = {}
  aliveMap[moduleId][uuid] = true
}

const refresh = async () => {
  loading.value = true
  try {
    const [modRes, cliRes] = await Promise.all([
      api.get('/api/modules'),
      api.get('/api/clients')
    ])
    const list = modRes.data?.modules || []
    modules.value = list.map((m) =>
      typeof m === 'string'
        ? { id: m, name: m, description: '', size: 0, kind: 'custom' }
        : m
    )
    const clients = Array.isArray(cliRes.data) ? cliRes.data : (cliRes.data?.clients || [])
    onlineClients.value = clients.filter((c) => (c.status || '').toLowerCase() !== 'offline')
  } catch (e) {
    ElMessage.error(e?.response?.data?.error || '加载模块列表失败')
  } finally {
    loading.value = false
  }
}

const onTargetChange = async (moduleId) => {
  const uuid = pushTarget[moduleId]
  if (!uuid) return
  // Refresh loaded flags for this agent
  try {
    const res = await api.get('/api/modules', { params: { uuid } })
    const list = res.data?.modules || []
    for (const m of list) {
      if (typeof m === 'object' && m.loaded_on_agent) {
        markAlive(m.id, uuid)
      }
    }
  } catch (_) {
    /* ignore */
  }
}

// Simple client-side platform hint for UX (server still enforces).
const moduleIsWindowsOnly = (id) => ['ad', 'inject', 'bof'].includes(id)
const targetIsCompatible = (uuid, moduleId) => {
  if (!moduleIsWindowsOnly(moduleId)) return true
  const c = onlineClients.value.find((x) => x.uuid === uuid)
  if (!c) return true
  const os = (c.os || '').toLowerCase()
  return os.includes('win')
}

const onFileChange = (e) => {
  uploadForm.file = e.target.files?.[0] || null
}

const doUpload = async () => {
  if (!uploadForm.id || !uploadForm.file) {
    ElMessage.warning('请填写模块 ID 并选择文件')
    return
  }
  uploading.value = true
  try {
    const fd = new FormData()
    fd.append('id', uploadForm.id.trim())
    fd.append('file', uploadForm.file)
    const res = await api.post('/api/modules/upload', fd, {
      headers: { 'Content-Type': 'multipart/form-data' }
    })
    ElNotification({
      title: '登记成功',
      message: res.data?.name
        ? `${res.data.name}（${res.data.id}）已登记：${res.data.description || ''}`
        : `模块 ${uploadForm.id} 已登记`,
      type: 'success',
      duration: 4000
    })
    uploadForm.file = null
    if (fileInput.value) fileInput.value.value = ''
    await refresh()
  } catch (e) {
    ElNotification({
      title: '上传失败',
      message: e?.response?.data?.error || '上传失败',
      type: 'error'
    })
  } finally {
    uploading.value = false
  }
}

const deleteModule = async (row) => {
  const aliveHint = isPushedAlive(row.id)
    ? `\n注意：当前选中主机仍标记为已加载「${row.id}」，删除仅移除服务端仓库，不影响已推送内存态。`
    : ''
  try {
    await ElMessageBox.confirm(
      `确定从仓库删除模块「${row.name || row.id}」？\n将移除磁盘 .bin 与 trust 签名侧车。${aliveHint}`,
      '删除模块（不可恢复）',
      { type: 'warning', confirmButtonText: '确认删除', cancelButtonText: '取消', distinguishCancelAndClose: true }
    )
  } catch {
    return
  }
  deleting.value = row.id
  try {
    await api.delete(`/api/modules/${encodeURIComponent(row.id)}`)
    ElMessage.success(`已删除 ${row.id}`)
    await refresh()
  } catch (e) {
    ElMessage.error(e?.response?.data?.error || '删除失败')
  } finally {
    deleting.value = ''
  }
}

const pushToAgent = async (row) => {
  const id = row.id
  const uuid = pushTarget[id]
  if (!uuid) return
  if (isPushedAlive(id)) {
    ElMessage.info(
      id === 'bof'
        ? 'bof 模块已在该主机映射就绪（进程内加载），无需重复推送'
        : `「${row.name || id}」已在该主机就绪，无需重复推送`
    )
    return
  }
  pushing.value = id
  try {
    const res = await api.post('/api/modules/push', { uuid, id })
    const data = res.data || {}
    markAlive(id, uuid)
    ElNotification({
      title: '推送成功',
      message: data.msg || `模块 ${data.name || id} 已在目标主机就绪`,
      type: 'success',
      duration: 5000
    })
    if (data.warning) {
      ElMessage.warning(data.warning)
    }
  } catch (e) {
    ElNotification({
      title: '推送失败',
      message: e?.response?.data?.error || '推送失败（模块未登记或主机离线）',
      type: 'error',
      duration: 5000
    })
  } finally {
    pushing.value = ''
  }
}

const packPreview = async (row) => {
  try {
    const res = await api.get(`/api/modules/pack/${row.id}`)
    const len = (res.data?.data || '').length
    packInfo.value = `${res.data?.name || row.id}：CKMS 打包成功，base64 长度 ${len}。${res.data?.description || ''}`
  } catch (e) {
    ElMessage.error(e?.response?.data?.error || '打包失败')
  }
}

onMounted(refresh)
</script>

<style scoped>
.module-shell { padding: 0; }
.module-card { padding: 20px 24px; }
.panel-head {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 16px;
  margin-bottom: 16px;
}
.panel-kicker {
  display: block;
  font-size: 12px;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  opacity: 0.55;
  margin-bottom: 4px;
}
.hint { margin: 8px 0 0; opacity: 0.75; line-height: 1.5; max-width: 720px; }
.hint code { font-size: 12px; }
.workflow {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 12px;
  margin-bottom: 8px;
}
.step {
  padding: 12px 14px;
  border-radius: 10px;
  background: rgba(255, 255, 255, 0.03);
  border: 1px solid rgba(255, 255, 255, 0.06);
  display: flex;
  flex-direction: column;
  gap: 6px;
  font-size: 13px;
}
.step code {
  font-size: 11px;
  word-break: break-all;
  opacity: 0.85;
}
.form-row {
  display: flex;
  flex-wrap: wrap;
  gap: 16px;
  align-items: flex-end;
}
.pack-alert { margin-top: 16px; }
.cap-row { display: flex; flex-wrap: wrap; gap: 4px; }
.cap-tag { margin: 0; }
.ver-line { font-size: 11px; opacity: 0.65; margin-top: 4px; }
.muted { opacity: 0.45; font-size: 12px; }
</style>
