<template>
  <div class="client-detail">
    <div class="top-header">
      <div class="header-left">
        <h1>{{ getPageTitle() }}</h1>
        <span class="subtitle">{{ clientInfo?.hostname || clientId }} | {{ clientInfo?.ip || 'N/A' }} | {{ clientInfo?.username || 'N/A' }}</span>
      </div>
      <div class="header-right">
        <el-button @click="handleReturnToList">返回列表</el-button>
      </div>
    </div>

    <div class="main-layout">
      <div class="left-sidebar">
        <el-menu
          :default-active="activeMenu"
          @select="handleMenuSelect"
          class="sidebar-menu"
        >
          <el-menu-item index="terminals">
            <el-icon><Monitor /></el-icon>
            <span>终端</span>
          </el-menu-item>
          <el-menu-item index="files">
            <el-icon><Folder /></el-icon>
            <span>文件管理</span>
          </el-menu-item>
          <el-menu-item index="tunnels">
            <el-icon><Connection /></el-icon>
            <span>隧道管理</span>
          </el-menu-item>
          <el-menu-item index="processes">
            <el-icon><Fold /></el-icon>
            <span>进程管理</span>
          </el-menu-item>
          <el-menu-item index="plugins">
            <el-icon><Tools /></el-icon>
            <span>插件/工具</span>
          </el-menu-item>
          <el-menu-item index="modules">
            <el-icon><Box /></el-icon>
            <span>模块</span>
          </el-menu-item>
          <el-menu-item index="ad">
            <el-icon><Connection /></el-icon>
            <span>域渗透</span>
          </el-menu-item>
        </el-menu>
      </div>

      <div class="right-content">
        <router-view v-slot="{ Component }">
          <transition name="fade" mode="out-in">
            <component
              :is="Component"
              :client-id="clientId"
              :client-info="clientInfo"
              :socket="socket"
              ref="childRef"
            />
          </transition>
        </router-view>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, onUnmounted, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { Monitor, Folder, Connection, Fold, Tools, Box } from '@element-plus/icons-vue'
import api from '../api/index'
import { ElMessage } from 'element-plus'

const route = useRoute()
const router = useRouter()

const clientId = computed(() => route.params.id)
const clientInfo = ref(null)

const activeMenu = computed(() => {
  const name = route.name
  if (name === 'ClientTerminals') return 'terminals'
  if (name === 'ClientFiles') return 'files'
  if (name === 'ClientTunnels') return 'tunnels'
  if (name === 'ClientProcesses') return 'processes'
  if (name === 'ClientPlugins') return 'plugins'
  if (name === 'ClientModules') return 'modules'
  if (name === 'ClientAd') return 'ad'
  return 'terminals'
})

const handleMenuSelect = (index) => {
  const routeMap = {
    terminals: 'ClientTerminals',
    files: 'ClientFiles',
    tunnels: 'ClientTunnels',
    processes: 'ClientProcesses',
    plugins: 'ClientPlugins',
    modules: 'ClientModules',
    ad: 'ClientAd',
  }
  router.push({ name: routeMap[index], params: { id: clientId.value } })
}

const getPageTitle = () => {
  const titleMap = {
    ClientTerminals: '终端',
    ClientFiles: '文件管理',
    ClientTunnels: '隧道管理',
    ClientProcesses: '进程管理',
    ClientPlugins: '插件与工具',
    ClientModules: 'Stage0 模块',
    ClientAd: '域渗透',
  }
  return titleMap[route.name] || '终端'
}

const fetchClientInfo = async () => {
  try {
    const res = await api.get('/api/clients')
    const client = res.data.find(c => c.uuid === clientId.value)
    if (client) {
      clientInfo.value = client
    } else {
      ElMessage.error('Client not found')
      router.push('/clients')
    }
  } catch (e) {
    ElMessage.error('Failed to load client information')
  }
}

const socket = ref(null)
const childRef = ref(null)
let pingInterval = null

const handleReturnToList = () => {
  router.push('/clients')
}

const initSocket = async () => {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  const host = window.location.host
  let ticket = ''
  try {
    const res = await api.post('/api/auth/ws-ticket', { purpose: 'shell' })
    ticket = res?.data?.ticket || ''
  } catch (_) {
    ticket = ''
  }
  if (!ticket) {
    ElMessage.error('无法获取 shell WebSocket 升级票据，请重新登录')
    return
  }
  const wsUrl = `${protocol}//${host}/api/shell/${clientId.value}?ticket=${encodeURIComponent(ticket)}`

  socket.value = new WebSocket(wsUrl)

  socket.value.onopen = () => {
    pingInterval = setInterval(() => {
      if (socket.value?.readyState === WebSocket.OPEN) {
        socket.value.send(JSON.stringify({ type: 'ping' }))
      }
    }, 30000)
  }

  socket.value.onmessage = (event) => {
    if (childRef.value?.handleSocketMessage) {
      childRef.value.handleSocketMessage(event)
    }
  }
}

onMounted(() => {
  fetchClientInfo()
  initSocket()
})

onUnmounted(() => {
  if (pingInterval) clearInterval(pingInterval)
  if (socket.value) socket.value.close()
})

watch(clientId, () => {
  fetchClientInfo()
})
</script>

<style scoped>
.client-detail {
  height: 100%;
  display: flex;
  flex-direction: column;
  background-color: var(--bg-panel-strong);
}

.top-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 16px 24px;
  background-color: var(--bg-panel-strong);
  border-bottom: 1px solid var(--line-muted);
  flex-shrink: 0;
}

.header-left h1 {
  margin: 0;
  font-size: 20px;
  font-weight: 600;
  color: #303133;
  line-height: 1.4;
}

.header-left .subtitle {
  font-size: 13px;
  color: var(--text-muted);
  font-family: 'JetBrains Mono', monospace;
  margin-left: 16px;
}

.header-right {
  display: flex;
  gap: 10px;
}

.main-layout {
  flex: 1;
  display: flex;
  overflow: hidden;
  min-height: 0;
}

.left-sidebar {
  width: 220px;
  background-color: var(--bg-panel-strong);
  display: flex;
  flex-direction: column;
  border-right: 1px solid var(--line-muted);
  flex-shrink: 0;
}

.sidebar-menu {
  background-color: transparent !important;
  border: none;
  flex-shrink: 0;
  padding: 10px 0;
}

:deep(.el-menu-item) {
  height: 50px;
  line-height: 50px;
  margin: 4px 16px;
  border-radius: 12px;
  font-size: 13px;
  font-weight: 700;
  color: var(--text-muted);
  transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
}

:deep(.el-menu-item:hover) {
  background-color: var(--surface-muted) !important;
  color: var(--text-strong) !important;
}

:deep(.el-menu-item.is-active) {
  background-color: var(--surface-muted) !important;
  color: var(--text-strong) !important;
  box-shadow: none;
}

.right-content {
  flex: 1;
  padding: 16px;
  overflow: hidden;
  display: flex;
  flex-direction: column;
  min-height: 0;
  background-color: var(--surface-soft);
}

:deep(.right-content > div) {
  flex: 1;
  display: flex;
  flex-direction: column;
  min-height: 0;
}

.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.2s ease;
}

.fade-enter-from,
.fade-leave-to {
  opacity: 0;
}
</style>
