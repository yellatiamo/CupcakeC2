<template>
  <div class="view-shell plugin-shell">
    <section class="view-actions view-actions--between">
      <div class="view-actions__copy">
        <span class="panel-kicker">插件能力 · Plugin Center</span>
        <h3>插件管理</h3>
        <p class="hint-line">
          武器库载荷（BOF / shellcode / 原生 PE）。与<strong>模块能力</strong>（bof / inject / ad）分离：
          BOF 执行需目标已加载 <code>bof</code> 模块（Agent 进程内无文件运行）。
        </p>
      </div>

      <el-button type="primary" class="upload-btn" @click="showUploadDialog = true">
        <el-icon><Plus /></el-icon>
        添加插件
      </el-button>
    </section>

    <el-alert
      type="info"
      show-icon
      :closable="false"
      class="cap-banner"
      title="插件能力 ≠ 模块能力：本页管理武器插件；L2 模块请在「模块」页维护与推送。"
    />

    <section class="stat-grid">
      <article class="surface-card stat-card">
        <div class="stat-card__icon">
          <el-icon><Collection /></el-icon>
        </div>
        <div>
          <span class="stat-card__label">已注册插件</span>
          <div class="stat-card__value">{{ plugins.length }}</div>
        </div>
      </article>

      <article class="surface-card stat-card">
        <div class="stat-card__icon">
          <el-icon><Platform /></el-icon>
        </div>
        <div>
          <span class="stat-card__label">跨平台支持</span>
          <div class="stat-card__value">{{ platformCount }}</div>
        </div>
      </article>

      <article class="surface-card stat-card">
        <div class="stat-card__icon">
          <el-icon><Cpu /></el-icon>
        </div>
        <div>
          <span class="stat-card__label">内存载荷占比</span>
          <div class="stat-card__value">{{ memoryPayloadCount }}</div>
        </div>
      </article>
    </section>

    <section class="surface-card table-shell">
      <el-table :data="plugins" v-loading="loading" class="premium-table">
        <el-table-column width="64" align="center">
          <template #default="{ row }">
            <div class="category-orb" :class="row.category || 'general'">
              <el-icon v-if="row.category === 'credentials'"><Lock /></el-icon>
              <el-icon v-else-if="row.category === 'lateral'"><Share /></el-icon>
              <el-icon v-else><Box /></el-icon>
            </div>
          </template>
        </el-table-column>

        <el-table-column label="插件名称与分类" min-width="220">
          <template #default="{ row }">
            <div class="name-cell">
              <span class="p-name">{{ row.name }}</span>
              <span class="p-category">{{ translateCategory(row.category) }}</span>
            </div>
          </template>
        </el-table-column>

        <el-table-column prop="description" label="核心功能描述" min-width="260" show-overflow-tooltip>
          <template #default="{ row }">
            <span class="desc-text">{{ row.description || '暂无详细功能描述' }}</span>
          </template>
        </el-table-column>

        <el-table-column label="运行环境" width="150" align="center">
          <template #default="{ row }">
            <el-tag :type="getOsTag(row.required_os)" class="premium-tag" effect="plain" round>
              {{ formatOS(row.required_os) }}
            </el-tag>
          </template>
        </el-table-column>

        <el-table-column label="交互机制" width="180" align="center">
          <template #default="{ row }">
            <div class="type-capsule" :class="getTypeTag(row.type)">
              {{ translateType(row.type) }}
            </div>
          </template>
        </el-table-column>

        <el-table-column label="依赖模块" width="120" align="center">
          <template #default="{ row }">
            <el-tag v-if="pluginNeedsModule(row)" size="small" type="warning" effect="plain">
              bof
            </el-tag>
            <span v-else class="desc-text">无（原生 PE）</span>
          </template>
        </el-table-column>

        <el-table-column label="移除" width="88" align="center" fixed="right">
          <template #default="{ row }">
            <el-button type="danger" link class="delete-action-btn" @click="confirmDelete(row.id)">
              <el-icon><Delete /></el-icon>
            </el-button>
          </template>
        </el-table-column>
      </el-table>
    </section>

    <el-dialog v-model="showUploadDialog" title="添加插件" width="620px" class="premium-dialog">
      <el-form label-position="top" class="upload-form">
        <el-form-item label="插件名称" required>
          <el-input v-model="uploadForm.name" placeholder="例如：fscan、SharpKatz、PortScanner" />
        </el-form-item>

        <el-form-item label="功能描述">
          <el-input v-model="uploadForm.description" type="textarea" :rows="3" placeholder="填写插件用途与说明" />
        </el-form-item>

        <div class="upload-grid">
          <el-form-item label="目标系统">
            <el-select v-model="uploadForm.required_os">
              <el-option label="Windows（默认）" value="windows" />
              <el-option label="Linux" value="linux" />
              <el-option label="全平台" value="multi" />
            </el-select>
          </el-form-item>

          <el-form-item label="执行方式">
            <el-input model-value="自动识别（按文件内容）" disabled />
            <div class="field-hint">
              原生 PE（fscan 等）→ native-exec；COFF/BOF → bof-exec；.NET 已退役（转 shellcode 走 inject）
            </div>
          </el-form-item>
        </div>

        <el-form-item label="插件分类">
          <el-select v-model="uploadForm.category">
            <el-option label="通用插件" value="general" />
            <el-option label="凭据获取" value="credentials" />
            <el-option label="横向移动" value="lateral" />
            <el-option label="权限提升" value="privesc" />
          </el-select>
        </el-form-item>

        <el-form-item label="上传文件" required>
          <el-upload
            drag
            action="#"
            :auto-upload="false"
            :limit="1"
            :show-file-list="true"
            :on-change="handleFileChange"
            :on-remove="handleFileRemove"
            class="premium-uploader"
          >
            <el-icon class="up-icon"><UploadFilled /></el-icon>
            <div class="up-text">点击或拖拽插件文件到这里</div>
            <div class="up-hint">支持 .exe / .dll（原生）/ .o（BOF），类型自动识别；.NET 已退役：请转 shellcode 走 inject</div>
          </el-upload>
        </el-form-item>
      </el-form>

      <template #footer>
        <div class="dialog-footer">
          <el-button @click="showUploadDialog = false">取消</el-button>
          <el-button type="primary" :loading="uploading" @click="submitUpload">确认添加</el-button>
        </div>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import {
  Box,
  Collection,
  Cpu,
  Delete,
  Lock,
  Platform,
  Plus,
  Share,
  UploadFilled
} from '@element-plus/icons-vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import api from '@/api'

const loading = ref(false)
const uploading = ref(false)
const showUploadDialog = ref(false)
const plugins = ref([])

const uploadForm = ref({
  name: '',
  description: '',
  required_os: 'windows',
  type: 'auto',
  category: 'general',
  file: null
})

const platformCount = computed(() => {
  return Array.from(new Set(plugins.value.map((plugin) => plugin.required_os || 'multi'))).length
})

const memoryPayloadCount = computed(() => {
  return plugins.value.filter((plugin) => {
    const type = String(plugin.type || '').toLowerCase()
    return (
      type.includes('mem') ||
      type.includes('shellcode') ||
      type.includes('bof') ||
      type.includes('assembly') ||
      type.includes('dotnet')
    )
  }).length
})

const pluginNeedsModule = (row) => {
  if (!row) return false
  if (row.required_module === 'bof') return true
  const t = String(row.type || '').toLowerCase()
  return t.includes('bof')
}

const resetUploadForm = () => {
  uploadForm.value = {
    name: '',
    description: '',
    required_os: 'windows',
    type: 'auto',
    category: 'general',
    file: null
  }
}

const fetchPlugins = async () => {
  loading.value = true
  try {
    const res = await api.get('/api/plugins')
    plugins.value = Array.isArray(res.data) ? res.data : []
  } catch (error) {
    ElMessage.error('无法同步插件数据')
  } finally {
    loading.value = false
  }
}

const handleFileChange = (file) => {
  uploadForm.value.file = file.raw
  // Suggest name from filename if empty
  if (!uploadForm.value.name && file?.name) {
    uploadForm.value.name = file.name.replace(/\.[^.]+$/, '')
  }
}

const handleFileRemove = () => {
  uploadForm.value.file = null
}

const submitUpload = async () => {
  if (!uploadForm.value.file) {
    ElMessage.warning('请选择插件文件')
    return
  }
  if (!uploadForm.value.name) {
    uploadForm.value.name = uploadForm.value.file.name || 'plugin'
  }

  uploading.value = true
  const formData = new FormData()
  formData.append('file', uploadForm.value.file)
  formData.append('name', uploadForm.value.name)
  formData.append('description', uploadForm.value.description)
  formData.append('required_os', uploadForm.value.required_os || 'windows')
  formData.append('type', 'auto')
  formData.append('category', uploadForm.value.category)

  try {
    const res = await api.post('/api/plugins/upload', formData, {
      headers: { 'Content-Type': 'multipart/form-data' }
    })
    const note = res.data?.detection_note || res.data?.detected_type || ''
    ElMessage.success(note ? `插件添加成功：${note}` : '插件添加成功（已自动识别类型）')
    showUploadDialog.value = false
    resetUploadForm()
    fetchPlugins()
  } catch (error) {
    ElMessage.error(error?.response?.data?.error || '插件上传失败')
  } finally {
    uploading.value = false
  }
}

const confirmDelete = (id) => {
  ElMessageBox.confirm('确定将该插件从受控端武器库中移除吗？', '删除插件', {
    type: 'warning',
    confirmButtonText: '移除',
    cancelButtonText: '取消'
  })
    .then(async () => {
      await api.delete(`/api/plugins/${id}`)
      ElMessage.success('插件已移除')
      fetchPlugins()
    })
    .catch(() => {})
}

const getOsTag = (os) => {
  if (os === 'windows') return 'primary'
  if (os === 'linux') return 'success'
  return 'info'
}

const getTypeTag = (type) => {
  const map = {
    'execute-assembly': 'type-orange',
    'memfd-exec': 'type-green',
    'shellcode-inject': 'type-red',
    'native-exec': 'type-green',
    'bof-exec': 'type-orange'
  }
  return map[type] || 'type-grey'
}

const translateType = (type) => {
  const map = {
    'execute-assembly': '.NET 内存执行（已退役）',
    'memfd-exec': 'Linux memfd 执行',
    'shellcode-inject': 'Shellcode 注入',
    'native-exec': '原生 PE（隔离进程）',
    'bof-exec': 'BOF / COFF'
  }
  return map[type] || type || '自动识别'
}

const translateCategory = (category) => {
  const map = {
    credentials: '凭据获取',
    lateral: '横向移动',
    privesc: '权限提升',
    general: '扩展插件'
  }
  return map[category] || '扩展插件'
}

const formatOS = (os) => {
  if (!os || os === 'multi') return 'ALL PLATFORMS'
  return String(os).toUpperCase()
}

onMounted(fetchPlugins)
</script>

<style scoped>
.hint-line {
  margin: 6px 0 0;
  font-size: 13px;
  opacity: 0.72;
  line-height: 1.45;
  max-width: 640px;
}
.hint-line code { font-size: 12px; }
.cap-banner { margin-bottom: 14px; }
.plugin-management-container {
  padding: 0;
}

.mb-24 {
  margin-bottom: 20px;
}

.glass-panel {
  background: rgba(255, 255, 255, 0.75);
  backdrop-filter: blur(20px);
  -webkit-backdrop-filter: blur(20px);
  border: 1px solid var(--accent-soft);
  border-radius: 24px;
  box-shadow: 0 10px 30px var(--line-soft);
}

.stats-row {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 16px;
}

.stat-module {
  display: flex;
  align-items: center;
  gap: 14px;
  min-height: 84px;
  padding: 16px 20px;
  border-radius: 22px;
}

.stat-icon-box {
  flex: 0 0 42px;
  width: 42px;
  height: 42px;
  border-radius: 14px;
  display: flex;
  align-items: center;
  justify-content: center;
  background: var(--surface-subtle) !important;
  color: var(--text-strong) !important;
  font-size: 18px;
}

.stat-icon-box.purple {
  background: rgba(17, 24, 39, 0.06) !important;
}

.stat-icon-box.blue {
  background: rgba(15, 23, 42, 0.07) !important;
}

.stat-icon-box.orange {
  background: rgba(51, 65, 85, 0.08) !important;
}

.stat-info {
  min-width: 0;
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.stat-label,
.desc-text,
.p-category,
.up-hint {
  color: var(--text-muted) !important;
}

.stat-label {
  font-size: 12px;
  font-weight: 600;
  line-height: 1.25;
}

.stat-value {
  font-size: 26px;
  line-height: 1;
  font-weight: 800;
  color: var(--text-strong);
}

.table-module {
  overflow: hidden;
}

.premium-table {
  background: transparent;
}

.name-cell {
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.p-name {
  font-weight: 700;
  color: var(--text-strong);
}

.category-orb {
  width: 34px;
  height: 34px;
  border-radius: 10px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 16px;
  background: var(--surface-subtle) !important;
  color: var(--text-strong) !important;
}

.category-orb.credentials {
  background: #fee2e2 !important;
  color: #ef4444 !important;
}

.category-orb.lateral {
  background: #ecfeff !important;
  color: #0891b2 !important;
}

.category-orb.general {
  background: #f1f5f9 !important;
  color: var(--text-muted) !important;
}

.premium-tag,
.type-capsule {
  background: var(--surface-muted) !important;
  border-color: var(--line-control) !important;
}

.type-capsule {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-width: 124px;
  padding: 8px 14px;
  border: 1px solid var(--line-control);
  border-radius: 999px;
  color: var(--text-strong);
  font-weight: 600;
  font-size: 13px;
}

.delete-action-btn {
  font-size: 16px;
}

.upload-form :deep(.el-select),
.upload-form :deep(.el-input) {
  width: 100%;
}

.upload-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 16px;
}

.premium-uploader {
  width: 100%;
}

.up-icon {
  font-size: 28px;
  margin-bottom: 10px;
}

.up-text {
  font-size: 14px;
  font-weight: 600;
  color: var(--text-strong);
}

.up-hint {
  font-size: 12px;
  margin-top: 4px;
}

.field-hint {
  font-size: 12px;
  margin-top: 6px;
  opacity: 0.65;
  line-height: 1.4;
}

.dialog-footer {
  display: flex;
  justify-content: flex-end;
  gap: 12px;
}

@media (max-width: 1100px) {
  .stats-row {
    grid-template-columns: 1fr;
  }
}

@media (max-width: 720px) {
  .view-actions {
    flex-direction: column;
    align-items: stretch;
  }

  .table-module {
    padding: 14px;
  }

  .upload-grid {
    grid-template-columns: 1fr;
  }
}
</style>
