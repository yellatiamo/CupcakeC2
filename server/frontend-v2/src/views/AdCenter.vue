<template>
  <div class="view-shell ad-shell">
    <section class="surface-card ad-card">
      <div class="panel-head">
        <div>
          <span class="panel-kicker">模块能力 · AD Tool Module</span>
          <h3>域渗透工具模块</h3>
          <p class="hint">
            管理产品模块 <code>ad</code>（域渗透 sacrificial worker）。
            上传 / 推送 / 查看加载状态。实际 AD 操作在<strong>主机详情 → 域渗透</strong>；
            执行审计请到「历史记录」筛选类型 AD。
          </p>
        </div>
        <div class="head-actions">
          <el-button @click="goHistory">AD 执行历史</el-button>
          <el-button type="primary" :loading="loading" @click="refresh">刷新</el-button>
        </div>
      </div>

      <div class="cap-strip">
        <div class="cap-item" v-for="c in capabilityHints" :key="c.id">
          <strong>{{ c.id }}</strong>
          <span>{{ c.desc }}</span>
        </div>
      </div>

      <el-divider />

      <!-- 模块仓库：仅 ad -->
      <div class="section-title-line">
        <h4 class="section-h4">模块仓库 · ad</h4>
        <el-tag v-if="adModule" size="small" :type="adModule.signed ? 'success' : 'info'" effect="plain">
          {{ adModule.signed ? '已签名' : '未签名' }}
        </el-tag>
      </div>

      <el-form label-position="top" class="upload-form" @submit.prevent>
        <div class="form-row">
          <el-form-item label="模块文件 (cupcake-ad-worker .exe / .dll / .bin)" required>
            <input type="file" ref="fileInput" @change="onFileChange" />
          </el-form-item>
          <el-form-item label="版本（可选）">
            <el-input v-model="uploadForm.version" placeholder="如 1.0.0" style="width: 140px" />
          </el-form-item>
          <el-form-item label=" ">
            <el-button
              type="primary"
              :loading="uploading"
              :disabled="!uploadForm.file || !isAdmin"
              @click="doUpload"
            >
              {{ isAdmin ? '上传并登记 ad' : '仅管理员可上传' }}
            </el-button>
            <el-button
              v-if="adModule && isAdmin"
              type="danger"
              plain
              :loading="deleting"
              @click="deleteAdModule"
            >
              从仓库删除
            </el-button>
          </el-form-item>
        </div>
      </el-form>

      <el-table
        :data="adModuleRows"
        v-loading="loading"
        empty-text="仓库中尚无 ad 模块 — 请上传 cupcake-ad-worker"
        class="mb"
      >
        <el-table-column prop="id" label="ID" width="90" />
        <el-table-column prop="name" label="名称" width="140" />
        <el-table-column prop="description" label="描述" min-width="200" show-overflow-tooltip />
        <el-table-column label="模块能力" min-width="160">
          <template #default="{ row }">
            <div class="cap-row">
              <el-tag
                v-for="cap in (row.capabilities || ['ad_ops'])"
                :key="cap"
                size="small"
                type="warning"
                effect="plain"
              >{{ cap }}</el-tag>
            </div>
          </template>
        </el-table-column>
        <el-table-column label="版本" width="100">
          <template #default="{ row }">{{ row.version || '—' }}</template>
        </el-table-column>
        <el-table-column label="大小" width="100">
          <template #default="{ row }">{{ formatSize(row.size) }}</template>
        </el-table-column>
        <el-table-column label="操作" width="140" fixed="right">
          <template #default="{ row }">
            <el-button size="small" @click="packPreview(row)">打包预览</el-button>
          </template>
        </el-table-column>
      </el-table>

      <el-alert
        v-if="packInfo"
        class="mb"
        type="info"
        :closable="true"
        @close="packInfo = ''"
        :title="packInfo"
      />

      <!-- 推送到主机 -->
      <div class="section-title-line">
        <h4 class="section-h4">推送到在线主机</h4>
        <span class="section-meta">仅 Windows · 需仓库已登记 ad</span>
      </div>

      <el-alert
        v-if="!adModule"
        type="warning"
        show-icon
        :closable="false"
        class="mb"
        title="请先上传 ad 模块到仓库，再推送到主机"
      />

      <el-table
        :data="onlineClients"
        v-loading="loadingClients"
        empty-text="暂无在线主机"
        class="agent-table"
      >
        <el-table-column label="主机" min-width="160">
          <template #default="{ row }">
            <div class="agent-cell">
              <strong>{{ row.hostname || row.uuid?.slice(0, 8) }}</strong>
              <span class="mono">{{ shortUuid(row.uuid) }}</span>
            </div>
          </template>
        </el-table-column>
        <el-table-column label="IP" width="130" prop="ip" />
        <el-table-column label="系统" width="120">
          <template #default="{ row }">
            <el-tag size="small" effect="plain">{{ row.os || '—' }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="ad 模块状态" width="140" align="center">
          <template #default="{ row }">
            <el-tag v-if="isAdLoaded(row.uuid)" type="success" size="small" effect="dark">已加载</el-tag>
            <el-tag v-else-if="!isWindows(row)" type="info" size="small">平台不支持</el-tag>
            <el-tag v-else type="info" size="small">未加载</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="操作" min-width="220" fixed="right">
          <template #default="{ row }">
            <el-button
              size="small"
              type="primary"
              :loading="pushing === row.uuid"
              :disabled="!adModule || isAdLoaded(row.uuid) || !isWindows(row) || !isAdmin"
              @click="pushToAgent(row)"
            >
              {{ isAdLoaded(row.uuid) ? '已在本机' : '推送 ad' }}
            </el-button>
            <el-button size="small" link type="primary" @click="goClientAd(row.uuid)">
              打开主机 AD
            </el-button>
          </template>
        </el-table-column>
      </el-table>

      <p class="foot-note">
        模块能力与插件能力分离：本页只管理 <code>ad</code> 工具模块。
        执行域发现 / Kerberoast / 图采集等请进入对应主机详情页；全量审计在「历史记录」。
      </p>
    </section>
  </div>
</template>

<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage, ElMessageBox, ElNotification } from 'element-plus'
import api from '../api/index'

const router = useRouter()

const loading = ref(false)
const loadingClients = ref(false)
const uploading = ref(false)
const deleting = ref(false)
const pushing = ref('')
const adModule = ref(null)
const onlineClients = ref([])
/** uuid -> true when ad loaded */
const loadedMap = reactive({})
const packInfo = ref('')
const fileInput = ref(null)

const uploadForm = reactive({
  file: null,
  version: ''
})

const userRole = (() => {
  try {
    return (JSON.parse(localStorage.getItem('cupcake_user') || '{}').role || 'operator').toLowerCase()
  } catch {
    return 'operator'
  }
})()
const isAdmin = userRole === 'admin' || userRole === 'administrator'

const capabilityHints = [
  { id: 'ad_ops', desc: '域态势 / 枚举 / 发现' },
  { id: 'kerberos', desc: 'Kerberoast / AS-REP' },
  { id: 'graph', desc: '关系图采集预览' },
  { id: 'dcsync', desc: '高危 · 需确认' }
]

const adModuleRows = computed(() => (adModule.value ? [adModule.value] : []))

const formatSize = (n) => {
  if (!n) return '—'
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / 1024 / 1024).toFixed(2)} MB`
}

const shortUuid = (u) => (u ? String(u).slice(0, 8) : '—')

const isWindows = (row) => {
  const os = (row?.os || '').toLowerCase()
  return !os || os.includes('win')
}

const isAdLoaded = (uuid) => !!loadedMap[uuid]

const goHistory = () => {
  router.push({ name: 'History', query: { type: 'ad', source: 'all' } })
}

const goClientAd = (uuid) => {
  if (!uuid) return
  router.push({ name: 'ClientAd', params: { id: uuid } })
}

const onFileChange = (e) => {
  uploadForm.file = e.target.files?.[0] || null
}

const refresh = async () => {
  loading.value = true
  loadingClients.value = true
  try {
    const [modRes, cliRes] = await Promise.all([
      api.get('/api/modules'),
      api.get('/api/clients')
    ])
    const list = modRes.data?.modules || []
    const found = list.find((m) => (typeof m === 'string' ? m : m.id) === 'ad')
    adModule.value = found
      ? typeof found === 'string'
        ? { id: 'ad', name: 'ad', description: '域渗透 worker', capabilities: ['ad_ops'] }
        : found
      : null

    const clients = Array.isArray(cliRes.data) ? cliRes.data : cliRes.data?.clients || []
    onlineClients.value = clients.filter((c) => (c.status || '').toLowerCase() !== 'offline')

    // Probe loaded flags per online windows agent (best-effort, sequential capped)
    const targets = onlineClients.value.filter(isWindows).slice(0, 30)
    await Promise.all(
      targets.map(async (c) => {
        try {
          const res = await api.get('/api/modules', { params: { uuid: c.uuid } })
          const mods = res.data?.modules || []
          const ad = mods.find((m) => (m.id || m) === 'ad')
          loadedMap[c.uuid] = !!(ad && (ad.loaded_on_agent || ad.alive || ad.loaded))
        } catch {
          /* keep previous */
        }
      })
    )
  } catch (e) {
    ElMessage.error(e?.response?.data?.error || '加载失败')
  } finally {
    loading.value = false
    loadingClients.value = false
  }
}

const doUpload = async () => {
  if (!uploadForm.file) {
    ElMessage.warning('请选择 ad 模块文件')
    return
  }
  uploading.value = true
  try {
    const fd = new FormData()
    fd.append('id', 'ad')
    fd.append('file', uploadForm.file)
    if (uploadForm.version) fd.append('version', uploadForm.version.trim())
    const res = await api.post('/api/modules/upload', fd, {
      headers: { 'Content-Type': 'multipart/form-data' }
    })
    ElNotification({
      title: 'ad 模块已登记',
      message: res.data?.msg || `sha256 ${res.data?.sha256 || ''}`.trim(),
      type: 'success'
    })
    uploadForm.file = null
    uploadForm.version = ''
    if (fileInput.value) fileInput.value.value = ''
    await refresh()
  } catch (e) {
    ElMessage.error(e?.response?.data?.error || '上传失败')
  } finally {
    uploading.value = false
  }
}

const deleteAdModule = async () => {
  try {
    await ElMessageBox.confirm(
      '确定从仓库删除 ad 模块？仅移除服务端登记与磁盘文件，已推送到主机的内存态不受影响。',
      '删除 ad 模块',
      { type: 'warning', confirmButtonText: '确认删除', cancelButtonText: '取消' }
    )
  } catch {
    return
  }
  deleting.value = true
  try {
    await api.delete('/api/modules/ad')
    ElMessage.success('已删除 ad')
    adModule.value = null
    await refresh()
  } catch (e) {
    ElMessage.error(e?.response?.data?.error || '删除失败')
  } finally {
    deleting.value = false
  }
}

const pushToAgent = async (row) => {
  if (!row?.uuid || !adModule.value) return
  pushing.value = row.uuid
  try {
    const res = await api.post('/api/modules/push', { uuid: row.uuid, id: 'ad' })
    loadedMap[row.uuid] = true
    ElNotification({
      title: '推送成功',
      message: res.data?.msg || `ad 已在 ${row.hostname || row.uuid.slice(0, 8)} 就绪`,
      type: 'success'
    })
  } catch (e) {
    const d = e?.response?.data || {}
    ElMessage.error(d.hint || d.error || '推送失败')
  } finally {
    pushing.value = ''
  }
}

const packPreview = async () => {
  try {
    const res = await api.get('/api/modules/pack/ad')
    const len = (res.data?.data || '').length
    packInfo.value = `ad 打包成功，base64 长度 ${len}。${res.data?.description || ''}`
  } catch (e) {
    ElMessage.error(e?.response?.data?.error || '打包失败')
  }
}

onMounted(refresh)
</script>

<style scoped>
.ad-shell { padding: 0; }
.ad-card { padding: 20px 24px; }
.panel-head {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 16px;
  margin-bottom: 14px;
}
.panel-kicker {
  font-size: 12px;
  opacity: 0.7;
  text-transform: uppercase;
  letter-spacing: 0.06em;
}
.hint { margin: 6px 0 0; opacity: 0.8; font-size: 13px; line-height: 1.55; }
.head-actions { display: flex; gap: 8px; flex-wrap: wrap; }
.cap-strip {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 10px;
  margin-bottom: 8px;
}
.cap-item {
  padding: 12px 14px;
  border-radius: 14px;
  border: 1px solid rgba(17, 17, 17, 0.08);
  background: linear-gradient(180deg, #fff, #f7f7f7);
  display: flex;
  flex-direction: column;
  gap: 4px;
}
.cap-item strong { font-size: 13px; }
.cap-item span { font-size: 12px; color: var(--text-muted, #666); }
.section-title-line {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  margin: 8px 0 12px;
}
.section-h4 { margin: 0; font-size: 15px; }
.section-meta { font-size: 12px; color: var(--text-muted, #888); }
.form-row {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  align-items: flex-end;
}
.mb { margin-bottom: 14px; }
.cap-row { display: flex; flex-wrap: wrap; gap: 4px; }
.agent-cell { display: flex; flex-direction: column; gap: 2px; }
.mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; opacity: 0.7; }
.foot-note {
  margin-top: 16px;
  font-size: 12px;
  line-height: 1.6;
  color: var(--text-muted, #777);
}
code { font-size: 12px; }
@media (max-width: 960px) {
  .cap-strip { grid-template-columns: repeat(2, minmax(0, 1fr)); }
}
</style>
