<template>
  <div class="terminal-tabs-container">
    <div class="tabs-header">
      <div class="tabs-list">
        <div
          v-for="tab in tabs"
          :key="tab.name"
          :class="['tab-item', { active: activeTabName === tab.name }]"
          @click="activeTabName = tab.name"
        >
          <span class="tab-dot"></span>
          <span class="tab-title">{{ tab.title }}</span>
          <span class="tab-close" @click.stop="handleTabRemove(tab.name)">×</span>
        </div>
      </div>
      <div class="tabs-actions">
        <button class="btn-add-tab" @click="addNewTab" title="新建终端">+</button>
      </div>
    </div>

    <div class="terminal-status-bar" v-if="clientInfo">
      <div class="status-left">
        <span class="status-indicator online"></span>
        <span class="status-host">{{ clientInfo?.hostname }}</span>
        <span class="status-sep">|</span>
        <span class="status-ip">{{ clientInfo?.ip }}</span>
      </div>
      <div class="status-right">
        <button class="btn-load-mod" :disabled="pushingShell" @click="pushShellModule" title="推送 bof 重模块（终端本身已内置）">
          {{ pushingShell ? '推送中…' : '加载 bof 模块' }}
        </button>
        <span class="status-badge">PTY ACTIVE</span>
        <span class="status-meta">{{ clientInfo?.username || 'N/A' }}</span>
        <span class="status-sep">·</span>
        <span class="status-meta">{{ clientInfo?.os || 'windows' }}</span>
      </div>
    </div>

    <div class="terminal-content">
      <div v-if="tabs.length === 0" class="terminal-empty-state">
        正在初始化终端...
      </div>

      <div
        v-for="tab in tabs"
        :key="tab.name"
        v-show="activeTabName === tab.name"
        class="terminal-instance"
      >
        <WebTerminal
          :ref="el => setTerminalRef(tab.name, el)"
          :socket="socket"
          :client-id="clientId"
          :session-id="tab.sessionId"
          :allow-p-t-y="tab.isPTY"
        />
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, reactive, onMounted, defineProps, defineExpose } from 'vue'
import { ElMessage } from 'element-plus'
import api from '../api/index'
import WebTerminal from './WebTerminal.vue'

const props = defineProps({
  clientId: {
    type: String,
    required: true
  },
  clientInfo: {
    type: Object,
    default: null
  },
  socket: {
    type: Object,
    default: null
  }
})

const tabs = ref([])
const activeTabName = ref('')
let tabCounter = 0
const pushingShell = ref(false)

const terminalRefs = reactive({})

const pushShellModule = async () => {
  pushingShell.value = true
  try {
    await api.post('/api/modules/push', { uuid: props.clientId, id: 'bof' })
    ElMessage.success('已推送 bof 模块（终端/文件/进程无需模块，已内置）')
  } catch (e) {
    ElMessage.error(e?.response?.data?.error || '推送失败：请先在「模块」页登记 bof；日常终端不需要加载模块')
  } finally {
    pushingShell.value = false
  }
}

const setTerminalRef = (name, el) => {
  if (el) {
    terminalRefs[name] = el
  }
}

const handleSocketMessage = (event) => {
  Object.values(terminalRefs).forEach(termComp => {
    if (termComp && termComp.handleSocketMessage) {
      termComp.handleSocketMessage(event)
    }
  })
}

const createTab = (isPTY = false) => {
  tabCounter++
  const sessionId = `session-${Date.now()}-${tabCounter}`
  return {
    name: sessionId,
    title: isPTY ? `Interactive Shell` : `Shell ${tabCounter}`,
    sessionId: sessionId,
    isPTY: isPTY,
    input: '',
    submitting: false
  }
}

const addNewTab = () => {
  const newTab = createTab(true)
  newTab.title = `Shell ${tabCounter}`
  tabs.value.push(newTab)
  activeTabName.value = newTab.name
}

const handleTabRemove = (targetName) => {
  if (tabs.value.length === 1) {
    ElMessage.warning('至少保留一个终端')
    return
  }

  const index = tabs.value.findIndex(tab => tab.name === targetName)
  if (index !== -1) {
    tabs.value.splice(index, 1)
    delete terminalRefs[targetName]
    if (activeTabName.value === targetName) {
      activeTabName.value = tabs.value[Math.max(0, index - 1)].name
    }
  }
}

onMounted(() => {
  const ptyTab = createTab(true)
  ptyTab.title = 'Interactive Shell'
  tabs.value.push(ptyTab)
  activeTabName.value = ptyTab.name
})

defineExpose({ handleSocketMessage })
</script>

<style scoped>
.terminal-tabs-container {
  height: 100%;
  display: flex;
  flex-direction: column;
  background: #1a1a1a;
  border-radius: 12px;
  overflow: hidden;
  border: 1px solid #2a2a2a;
}

.tabs-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 6px 12px;
  background: #111111;
  border-bottom: 1px solid #2a2a2a;
  min-height: 38px;
}

.tabs-list {
  display: flex;
  align-items: center;
  gap: 4px;
  overflow-x: auto;
}

.tab-item {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 5px 12px;
  border-radius: 6px;
  cursor: pointer;
  font-size: 12px;
  color: #888;
  transition: all 0.15s ease;
  white-space: nowrap;
  user-select: none;
}

.tab-item:hover {
  background: #2a2a2a;
  color: #ccc;
}

.tab-item.active {
  background: #2a2a2a;
  color: #fff;
}

.tab-dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: #555;
}

.tab-item.active .tab-dot {
  background: #4ade80;
}

.tab-title {
  font-family: 'Inter', -apple-system, sans-serif;
  font-weight: 500;
}

.tab-close {
  font-size: 14px;
  line-height: 1;
  opacity: 0;
  transition: opacity 0.15s;
  padding: 0 2px;
  color: #666;
}

.tab-item:hover .tab-close {
  opacity: 1;
}

.tab-close:hover {
  color: #ff6b6b;
}

.tabs-actions {
  flex-shrink: 0;
}

.btn-add-tab {
  width: 24px;
  height: 24px;
  border-radius: 6px;
  border: 1px solid #333;
  background: transparent;
  color: #888;
  font-size: 16px;
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
  transition: all 0.15s;
}

.btn-add-tab:hover {
  background: #333;
  color: #fff;
  border-color: #555;
}

.terminal-status-bar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 6px 16px;
  background: #151515;
  border-bottom: 1px solid #222;
  font-size: 11px;
  font-family: 'JetBrains Mono', 'Consolas', monospace;
}

.status-left, .status-right {
  display: flex;
  align-items: center;
  gap: 8px;
}

.status-indicator {
  width: 6px;
  height: 6px;
  border-radius: 50%;
}

.status-indicator.online {
  background: #4ade80;
  box-shadow: 0 0 4px #4ade8066;
}

.status-host {
  color: #e0e0e0;
  font-weight: 600;
}

.status-ip {
  color: #888;
}

.status-sep {
  color: #444;
}

.status-badge {
  padding: 1px 6px;
  border-radius: 3px;
  background: #1a3a1a;
  color: #4ade80;
  font-size: 9px;
  font-weight: 700;
  letter-spacing: 0.5px;
}

.btn-load-mod {
  border: 1px solid #3b82f6;
  background: rgba(59, 130, 246, 0.15);
  color: #93c5fd;
  font-size: 11px;
  padding: 2px 10px;
  border-radius: 4px;
  cursor: pointer;
  margin-right: 8px;
}
.btn-load-mod:hover:not(:disabled) {
  background: rgba(59, 130, 246, 0.3);
}
.btn-load-mod:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.status-meta {
  color: #777;
}

.terminal-content {
  flex: 1;
  overflow: hidden;
  position: relative;
  background: #0d0d0d;
}

.terminal-empty-state {
  padding: 40px;
  text-align: center;
  color: #555;
  font-size: 13px;
}

.terminal-instance {
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
}
</style>
