<template>
  <div class="view-shell payload-shell">
    <section class="payload-toolbar">
      <div class="payload-toolbar__metrics">
        <div class="chip">活跃监听器 {{ activeListeners.length }}</div>
        <div class="chip">模式 {{ form.mode === 'build' ? '源码构建' : '模板补丁' }}</div>
        <div class="chip">客户端 {{ profileLabel }}</div>
      </div>
    </section>

    <section class="payload-grid">
      <article class="surface-card builder-card">
        <div class="panel-head">
          <div>
            <span class="panel-kicker">Build Config</span>
            <h3>载荷参数</h3>
          </div>
          <div class="chip">Core v3</div>
        </div>

        <el-form :model="form" label-position="top" class="payload-form">
          <div class="section-block">
            <div class="section-title">
              <span class="section-index">01</span>
              <div>
                <strong>目标平台</strong>
                <p>统一选择系统与架构，后续会自动同步下载文件名和 stager。</p>
              </div>
            </div>

            <div class="platform-grid">
              <button
                v-for="platform in platformGroups"
                :key="platform.key"
                type="button"
                class="platform-card"
                :class="{ 'platform-card--active': platform.active }"
                @click="form.combinedType = platform.defaultValue"
              >
                <div class="platform-card__head">
                  <div class="platform-card__icon">
                    <el-icon><component :is="platform.icon" /></el-icon>
                  </div>
                  <div>
                    <strong>{{ platform.label }}</strong>
                    <span>{{ platform.caption }}</span>
                  </div>
                </div>

                <el-radio-group v-model="form.combinedType" class="platform-options">
                  <el-radio-button
                    v-for="option in platform.options"
                    :key="option.value"
                    :label="option.value"
                  >
                    {{ option.label }}
                  </el-radio-button>
                </el-radio-group>
              </button>
            </div>
          </div>

          <div class="section-block form-grid">
            <el-form-item label="监听器" required>
              <el-select
                v-model="form.listenerId"
                placeholder="按客户端类型筛选后的监听器"
                @change="onListenerChange"
              >
                <el-option
                  v-for="listener in filteredListeners"
                  :key="listener.id"
                  :label="`${listener.protocol} | 端口 ${listener.port}`"
                  :value="listener.id"
                />
              </el-select>
            </el-form-item>

            <el-form-item
              v-if="!isBindTcpListener(selectedListener?.protocol)"
              label="回连地址"
            >
              <el-input
                v-model="form.lhost"
                placeholder="填写公网 IP 或域名"
                :prefix-icon="MapLocation"
              />
            </el-form-item>
          </div>

          <div class="section-block mode-panel">
            <div class="section-title">
              <span class="section-index">02</span>
              <div>
                <strong>生成方式</strong>
                <p>按模板页风格拆分为两种模式，兼顾速度和对抗性。</p>
              </div>
            </div>

            <div class="mode-switch">
              <button
                type="button"
                class="mode-switch__item"
                :class="{ 'mode-switch__item--active': form.mode === 'build' }"
                @click="form.mode = 'build'"
              >
                <span>源码构建</span>
                <small>完整编译，静态链接</small>
              </button>
              <button
                type="button"
                class="mode-switch__item"
                :class="{ 'mode-switch__item--active': form.mode === 'patch' }"
                @click="form.mode = 'patch'"
              >
                <span>模板补丁</span>
                <small>秒级生成</small>
              </button>
            </div>

            <div class="mode-note">
              <el-icon><Cpu /></el-icon>
              <span>{{ modeDescription }}</span>
            </div>

            <div class="section-title profile-section-title">
              <span class="section-index">02b</span>
              <div>
                <strong>客户端类型</strong>
                <p>仅两种方向：反向（回连）与正向（bind）。BOF / inject / ad 按需加载模块。</p>
              </div>
            </div>

            <div class="profile-switch">
              <button
                v-for="item in profileOptions"
                :key="item.value"
                type="button"
                class="profile-switch__item"
                :class="{ 'profile-switch__item--active': form.profile === item.value }"
                @click="onClientTypeChange(item.value)"
              >
                <span>{{ item.label }}</span>
                <small>{{ item.caption }}</small>
              </button>
            </div>

            <div class="mode-note profile-hint">
              <el-icon><Cpu /></el-icon>
              <span>{{ profileDescription }}</span>
            </div>

            <el-alert
              type="info"
              :closable="false"
              show-icon
              :title="form.profile === 'forward'
                ? '正向：目标监听，面板主动接入。须选 正向TCP；生成后使用「正向接入」。'
                : '反向：Agent 主动回连。须选 TCP / WebSocket / DNS。'"
              class="profile-alert"
            />

            <div class="option-grid">
              <div class="option-card">
                <span class="option-card__label">休眠时间</span>
                <strong>{{ form.sleepTime }} 秒</strong>
                <el-input-number v-model="form.sleepTime" :min="0" controls-position="right" />
              </div>

              <div class="option-card">
                <span class="option-card__label">自动销毁</span>
                <strong>{{ form.autoDestruct ? '已启用' : '未启用' }}</strong>
                <el-switch v-model="form.autoDestruct" />
              </div>

              <div class="option-card" :class="{ 'option-card--disabled': form.mode !== 'build' }">
                <span class="option-card__label">UPX 压缩</span>
                <strong>{{ form.mode === 'build' && form.useUPX ? '已启用' : '未启用' }}</strong>
                <el-switch
                  v-model="form.useUPX"
                  :disabled="form.mode !== 'build'"
                />
              </div>
            </div>

            <el-alert
              v-if="form.mode === 'build' && form.useUPX"
              type="error"
              :closable="false"
              show-icon
              title="风险：现代 AV 对 UPX 特征敏感，生产投递不推荐。默认应保持关闭。"
              class="profile-alert"
            />
          </div>

          <div class="build-preview">
            <div class="build-preview__copy">
              <span class="build-preview__label">回连预览</span>
              <code class="build-preview__value">{{ previewUrl }}</code>
            </div>

            <el-button
              type="primary"
              class="generate-btn"
              :loading="loading"
              @click="doGenerate"
            >
              <el-icon v-if="!loading"><Download /></el-icon>
              生成载荷
            </el-button>
          </div>
        </el-form>
      </article>

      <aside class="section-stack payload-sidebar">
        <article class="surface-card sidebar-card">
          <div class="panel-head panel-head--tight">
            <div>
              <span class="panel-kicker">Quick Stager</span>
              <h3>一键上线命令</h3>
            </div>
            <el-button link @click="fetchStagerCommand">
              <el-icon><Refresh /></el-icon>
            </el-button>
          </div>

          <div class="stager-state" v-loading="stagerLoading">
            <p class="dialog-hint stager-host-hint">
              <strong>下载地址</strong> = 当前面板 Host（目标机能访问的 Web 端口）；
              <strong>回连地址</strong> = 上方「回连地址」+ 监听器端口（Agent C2）。
              二者不要混用。
            </p>
            <div class="stager-meta" style="margin-bottom: 8px">
              <div class="stager-meta__row">
                <span>交付方式</span>
                <el-radio-group v-model="stagerDelivery" size="small" @change="fetchStagerCommand">
                  <el-radio-button label="disk">落盘 EXE</el-radio-button>
                  <el-radio-button label="fileless">内存上线</el-radio-button>
                </el-radio-group>
              </div>
            </div>
            <el-alert
              v-if="stagerDelivery === 'fileless'"
              type="warning"
              :closable="false"
              show-icon
              class="stager-alert"
              title="内存上线 ≠ BOF"
              description="此处将 Stage0 Agent 打成 shellcode 在目标内存执行（上线本身）。上线后的 BOF 走 bof 模块（进程内）、shellcode 注入走 inject。杀软对注入极敏感，实验室优先。"
            />
            <div v-if="stagerMeta.panel_host || stagerMeta.callback" class="stager-meta">
              <div class="stager-meta__row">
                <span>面板下载 Host</span>
                <code>{{ stagerMeta.panel_host || '—' }}</code>
              </div>
              <div class="stager-meta__row">
                <span>Agent 回连 Host</span>
                <code>{{ stagerMeta.callback || form.lhost || '—' }}</code>
              </div>
              <div class="stager-meta__row" v-if="stagerMeta.profile">
                <span>客户端</span>
                <code>{{ stagerMeta.profile_label || stagerMeta.profile }}</code>
              </div>
              <div class="stager-meta__row" v-if="stagerMeta.delivery">
                <span>交付</span>
                <code>{{ stagerMeta.delivery === 'fileless' ? '内存上线' : '落盘 EXE' }}</code>
              </div>
              <div class="stager-meta__row" v-if="stagerMeta.stage2_url">
                <span>Stage2 URL</span>
                <code class="stage2-url" :title="stagerMeta.stage2_url">{{ stagerMeta.stage2_url }}</code>
              </div>
              <div class="stager-meta__row" v-if="stagerMeta.stage2_bytes">
                <span>Shellcode</span>
                <code>{{ formatBytes(stagerMeta.stage2_bytes) }} · TTL {{ stagerMeta.stage2_ttl_sec || 600 }}s</code>
              </div>
              <div class="stager-meta__row" v-if="stagerMeta.expires_at">
                <span>过期</span>
                <code>{{ stagerMeta.expires_at }}</code>
              </div>
            </div>

            <!-- 落盘：CMD / PS 分栏，后端 recommended 决定默认 -->
            <template v-if="stagerDelivery === 'disk' && (stagerCommand || stagerCommandPs)">
              <div class="cmd-tabs">
                <button
                  type="button"
                  class="cmd-tab"
                  :class="{ 'cmd-tab--active': diskTab === 'ps' }"
                  @click="diskTab = 'ps'"
                >PS 直拉 推荐</button>
                <button
                  type="button"
                  class="cmd-tab"
                  :class="{ 'cmd-tab--active': diskTab === 'cmd' }"
                  @click="diskTab = 'cmd'"
                >CMD</button>
                <button
                  type="button"
                  class="cmd-tab"
                  :class="{ 'cmd-tab--active': diskTab === 'psbat' }"
                  @click="diskTab = 'psbat'"
                  v-if="stagerCommandPsBat"
                >PS+bat</button>
              </div>
              <div class="terminal-card terminal-card--sm">
                <code>{{ activeDiskCommand || '—' }}</code>
              </div>
              <div class="sidebar-actions">
                <el-button type="primary" class="sidebar-button" :disabled="!activeDiskCommand" @click="copyText(activeDiskCommand)">
                  <el-icon><CopyDocument /></el-icon>
                  复制当前命令
                </el-button>
              </div>
              <ul class="fileless-notes" v-if="stagerNotes.length">
                <li v-for="(n, i) in stagerNotes" :key="i">{{ n }}</li>
              </ul>
            </template>

            <!-- 内存上线 -->
            <template v-if="stagerDelivery === 'fileless' && (stagerCommandPs || stagerCommandStager)">
              <div class="cmd-tabs">
                <button type="button" class="cmd-tab" :class="{ 'cmd-tab--active': filelessTab === 'ps' }" @click="filelessTab = 'ps'">PS 一行 推荐</button>
                <button type="button" class="cmd-tab" :class="{ 'cmd-tab--active': filelessTab === 'inline' }" @click="filelessTab = 'inline'" v-if="stagerCommandPsInline">内联</button>
                <button type="button" class="cmd-tab" :class="{ 'cmd-tab--active': filelessTab === 'stager' }" @click="filelessTab = 'stager'">Stager</button>
                <button type="button" class="cmd-tab" :class="{ 'cmd-tab--active': filelessTab === 'url' }" @click="filelessTab = 'url'" v-if="stagerMeta.stage2_url">Stage2 URL</button>
              </div>
              <div class="terminal-card terminal-card--sm">
                <code>{{ activeFilelessCommand || '—' }}</code>
              </div>
              <div class="sidebar-actions">
                <el-button type="primary" class="sidebar-button" :disabled="!activeFilelessCommand" @click="copyText(activeFilelessCommand)">
                  <el-icon><CopyDocument /></el-icon>
                  复制当前命令
                </el-button>
              </div>
              <ul class="fileless-notes" v-if="stagerNotes.length">
                <li v-for="(n, i) in stagerNotes" :key="i">{{ n }}</li>
              </ul>
            </template>

            <div v-if="!stagerLoading && !stagerCommand && !stagerCommandPs" class="empty-copy">
              选择监听器和平台后点刷新。落盘需 assets 模板；内存上线需 Donut 可转换该模板。
            </div>
          </div>
        </article>

        <article class="surface-card sidebar-card">
          <div class="panel-head panel-head--tight">
            <div>
              <span class="panel-kicker">Operational Notes</span>
              <h3>投递建议</h3>
            </div>
          </div>

          <div class="tips-stack">
            <div class="tip-row">
              <div class="tip-row__icon">
                <el-icon><Lock /></el-icon>
              </div>
              <p>建议优先选择 WebSocket 监听器，并通过域名或 CDN 出口伪装常规业务流量。</p>
            </div>

            <div class="tip-row">
              <div class="tip-row__icon">
                <el-icon><Share /></el-icon>
              </div>
              <p>如果需要快速大规模投递，优先使用模板补丁模式；需要更强对抗时切回源码构建。</p>
            </div>

            <div class="tip-row">
              <div class="tip-row__icon">
                <el-icon><Monitor /></el-icon>
              </div>
              <p>休眠时间写入 agent：首次回连前等待 N 秒（0=立即连接）。与内置随机静默无关，完全按此处配置。</p>
            </div>

            <div class="tip-row">
              <div class="tip-row__icon">
                <el-icon><Share /></el-icon>
              </div>
              <p>
                <strong>内存上线 ≠ BOF</strong>：内存上线是把 Stage0 Agent 打成 shellcode 执行（上线本身）。
                上线后 BOF 走 <code>bof</code> 模块，shellcode 注入走 <code>inject</code>。
              </p>
            </div>
          </div>
        </article>

        <article class="surface-card sidebar-card">
          <div class="panel-head panel-head--tight">
            <div>
              <span class="panel-kicker">Build Status</span>
              <h3>构建状态</h3>
            </div>
            <div class="status-pill" v-if="currentTaskId">
              {{ buildStatusText }}
            </div>
          </div>

          <div class="status-grid">
            <div class="status-cell">
              <span>当前任务</span>
              <strong class="mono">{{ currentTaskId ? currentTaskId.slice(0, 8) : '--------' }}</strong>
            </div>
            <div class="status-cell">
              <span>阶段</span>
              <strong>{{ stageLabel }}</strong>
            </div>
            <div class="status-cell">
              <span>耗时</span>
              <strong class="mono">{{ elapsedTime }}s</strong>
            </div>
          </div>

          <div class="sidebar-actions" v-if="currentTaskId">
            <el-button class="sidebar-button" @click="openBuildConsole">查看控制台</el-button>
            <el-button class="sidebar-button" @click="exportLogs" :disabled="!logBuffer.length">导出日志</el-button>
          </div>
        </article>
      </aside>
    </section>

    <el-dialog
      v-model="terminalDialogVisible"
      width="1040px"
      class="build-dialog premium-dialog"
      :show-close="false"
      destroy-on-close
      @opened="onTerminalOpened"
      @closed="onTerminalClosed"
    >
      <template #header>
        <div class="dialog-header">
          <div>
            <span class="panel-kicker">Build Console</span>
            <h3>任务 {{ currentTaskId ? currentTaskId.slice(0, 8) : '--------' }}</h3>
          </div>

          <div class="dialog-actions">
            <el-button circle plain @click="minimizeTerminal">
              <el-icon><Minus /></el-icon>
            </el-button>
            <el-button circle plain @click="closeBuildSession">
              <el-icon><Close /></el-icon>
            </el-button>
          </div>
        </div>
      </template>

      <div class="dialog-content">
        <div class="status-grid status-grid--dialog">
          <div class="status-cell">
            <span>状态</span>
            <strong>{{ buildStatusText }}</strong>
          </div>
          <div class="status-cell">
            <span>阶段</span>
            <strong>{{ stageLabel }}</strong>
          </div>
          <div class="status-cell">
            <span>目标架构</span>
            <strong class="mono">{{ form.combinedType }}</strong>
          </div>
          <div class="status-cell">
            <span>耗时</span>
            <strong class="mono">{{ elapsedTime }}s</strong>
          </div>
        </div>

        <div class="pipeline">
          <div
            v-for="step in buildSteps"
            :key="step.id"
            class="pipeline-step"
            :class="{
              'pipeline-step--active': buildStage >= step.id,
              'pipeline-step--done': buildStage > step.id
            }"
          >
            <div class="pipeline-step__dot">{{ step.id }}</div>
            <span>{{ step.label }}</span>
          </div>
        </div>

        <div class="terminal-toolbar">
          <span>实时构建输出</span>
          <div class="terminal-toolbar__actions">
            <el-button link @click="exportLogs">导出日志</el-button>
            <el-button link @click="clearTerminal">清空缓冲</el-button>
          </div>
        </div>

        <div class="terminal-wrap">
          <div ref="terminalContainer" class="xterm-view"></div>
        </div>
      </div>
    </el-dialog>

    <transition name="pop">
      <button
        v-if="isMinimized && currentTaskId"
        type="button"
        class="build-bubble"
        @click="restoreTerminal"
      >
        <el-icon><Cpu /></el-icon>
        <div>
          <strong>{{ buildFinished ? '构建结果已返回' : '构建任务进行中' }}</strong>
          <span>ID {{ currentTaskId.slice(0, 8) }} · {{ buildStatusText }}</span>
        </div>
      </button>
    </transition>
  </div>
</template>

<script setup>
import { computed, nextTick, onMounted, onUnmounted, ref, watch } from 'vue'
import {
  ChromeFilled,
  Close,
  CopyDocument,
  Cpu,
  Download,
  Lock,
  MapLocation,
  Minus,
  Monitor,
  Platform,
  Refresh,
  Share
} from '@element-plus/icons-vue'
import { ElMessage } from 'element-plus'
import { getListeners, generateClient, request } from '@/api'
import { Terminal as XTerm } from '@xterm/xterm'
import { FitAddon } from '@xterm/addon-fit'
import '@xterm/xterm/css/xterm.css'

const loading = ref(false)
const activeListeners = ref([])
const stagerLoading = ref(false)
const stagerCommand = ref('')
const stagerCommandPs = ref('')
const stagerCommandPsInline = ref('')
const stagerCommandPsBat = ref('')
const stagerCommandStager = ref('')
const stagerNotes = ref([])
const stagerDelivery = ref('disk') // disk | fileless
const diskTab = ref('cmd') // cmd | ps | psbat
const filelessTab = ref('ps') // ps | stager | url
const stagerMeta = ref({
  panel_host: '',
  callback: '',
  profile: '',
  profile_label: '',
  delivery: 'disk',
  stage2_url: '',
  stage2_bytes: 0,
  stage2_ttl_sec: 0,
  expires_at: ''
})

const formatBytes = (n) => {
  const v = Number(n) || 0
  if (v < 1024) return `${v} B`
  if (v < 1024 * 1024) return `${(v / 1024).toFixed(1)} KB`
  return `${(v / (1024 * 1024)).toFixed(2)} MB`
}

const activeDiskCommand = computed(() => {
  if (diskTab.value === 'ps') return stagerCommandPs.value
  if (diskTab.value === 'psbat') return stagerCommandPsBat.value || stagerCommandPs.value
  return stagerCommand.value
})

const activeFilelessCommand = computed(() => {
  if (filelessTab.value === 'stager') return stagerCommandStager.value
  if (filelessTab.value === 'inline') return stagerCommandPsInline.value || stagerCommandPs.value
  if (filelessTab.value === 'url') return stagerMeta.value.stage2_url
  return stagerCommandPs.value
})

const emptyStagerMeta = () => ({
  panel_host: '',
  callback: '',
  profile: '',
  profile_label: '',
  delivery: stagerDelivery.value || 'disk',
  stage2_url: '',
  stage2_bytes: 0,
  stage2_ttl_sec: 0,
  expires_at: ''
})

const currentTaskId = ref('')
const terminalDialogVisible = ref(false)
const isMinimized = ref(false)
const buildStage = ref(1)
const buildStatusText = ref('等待任务')
const elapsedTime = ref(0)
const logBuffer = ref([])
const buildFinished = ref(false)

const terminalContainer = ref(null)

let xterm = null
let fitAddon = null
let ws = null
let buildTimer = null
let resizeHandler = null

const form = ref({
  combinedType: 'windows_amd64',
  listenerId: '',
  lhost: window.location.hostname || '127.0.0.1',
  mode: 'build',
  autoDestruct: false,
  sleepTime: 0,
  aesKey: '',
  useUPX: false,
  encryption_salt: '',
  obfuscation_mode: 'none',
  // 两种产品：reverse/minimal=日常作业内置 | forward=正向全功能
  profile: 'reverse'
})

const profileOptions = [
  {
    value: 'reverse',
    label: '反向客户端',
    caption: '回连 · 与正向同能力 ~0.8MB',
    direction: 'reverse'
  },
  {
    value: 'forward',
    label: '正向客户端',
    caption: '目标监听 · 与反向同能力 ~0.8MB',
    direction: 'forward'
  }
]

const platformGroups = computed(() => [
  {
    key: 'windows',
    label: 'Windows',
    caption: '桌面与服务器环境',
    icon: Platform,
    defaultValue: 'windows_amd64',
    active: form.value.combinedType.startsWith('windows'),
    options: [
      { label: 'X64 标准版', value: 'windows_amd64' },
      { label: 'X86 兼容版', value: 'windows_i386' }
    ]
  },
  {
    key: 'linux',
    label: 'Linux',
    caption: '常规服务器与 ARM',
    icon: ChromeFilled,
    defaultValue: 'linux_amd64',
    active: form.value.combinedType.startsWith('linux'),
    options: [
      { label: 'AMD64', value: 'linux_amd64' },
      { label: 'ARM64 / M1', value: 'linux_arm64' }
    ]
  }
])

const buildSteps = computed(() => {
  const steps = [
    { id: 1, label: '环境检查' },
    { id: 2, label: '核心编译' }
  ]
  if (form.value.mode === 'build' && form.value.useUPX) {
    steps.push({ id: 3, label: 'UPX 压缩' })
    steps.push({ id: 4, label: '完成' })
  } else {
    steps.push({ id: 3, label: '完成' })
  }
  return steps
})

const selectedListener = computed(() =>
  activeListeners.value.find((listener) => listener.id === form.value.listenerId)
)

const isBindTcpListener = (protocol) => {
  const value = String(protocol || '').toLowerCase()
  return value === '正向tcp' || value === 'bind-tcp' || value === 'bind_tcp' || value.includes('bind')
}

const currentDirection = computed(() => {
  const hit = profileOptions.find((p) => p.value === form.value.profile)
  return hit?.direction || 'reverse'
})

/** 按客户端方向过滤监听器：反向=非 bind；正向=仅 bind */
const filteredListeners = computed(() => {
  const list = activeListeners.value || []
  if (currentDirection.value === 'forward') {
    return list.filter((l) => isBindTcpListener(l.protocol))
  }
  return list.filter((l) => !isBindTcpListener(l.protocol))
})

const previewUrl = computed(() => {
  if (!selectedListener.value) return '---'

  const protocol = (selectedListener.value.protocol || '').toLowerCase()
  if (protocol === 'websocket') return `ws://${form.value.lhost}:${selectedListener.value.port}/ws`
  if (isBindTcpListener(protocol)) return `LOCAL_BIND:${selectedListener.value.port}`
  if (protocol === 'dns') return `NS:${selectedListener.value.ns_domain}`
  return `${selectedListener.value.protocol}://${form.value.lhost}:${selectedListener.value.port}`
})

const modeDescription = computed(() => (
  form.value.mode === 'build'
    ? '源码构建：产品档 minimal；BOF / inject / ad 按需 L2 模块。'
    : '模板补丁：秒级生成；模板均为 minimal。'
))

const profileLabel = computed(() => {
  const hit = profileOptions.find((p) => p.value === form.value.profile)
  return hit ? hit.label : form.value.profile
})

const profileDescription = computed(() => {
  if (form.value.profile === 'forward') {
    return '正向客户端：目标机监听，面板主动接入。须选 正向TCP 监听器。'
  }
  return '反向客户端：Agent 主动回连。须选 TCP / WebSocket / DNS。'
})

const onClientTypeChange = (value) => {
  form.value.profile = value
  // 切换方向时若当前监听器不匹配则清空
  const stillOk = filteredListeners.value.some((l) => l.id === form.value.listenerId)
  if (!stillOk) {
    form.value.listenerId = filteredListeners.value[0]?.id || ''
    if (form.value.listenerId) {
      const ln = activeListeners.value.find((l) => l.id === form.value.listenerId)
      if (ln) onListenerChange(ln.id)
    }
  }
}

const stageLabel = computed(() => {
  if (buildStage.value <= 1) return '环境检查'
  if (buildStage.value === 2) return '核心编译'
  if (form.value.useUPX && buildStage.value === 3) return 'UPX 压缩'
  return buildFinished.value ? '已完成' : '处理中'
})

// 切到补丁模式时强制关闭 UPX（补丁不走 cargo UPX）
watch(
  () => form.value.mode,
  (mode) => {
    if (mode !== 'build') {
      form.value.useUPX = false
    }
  }
)

watch(
  [
    () => form.value.combinedType,
    () => form.value.listenerId,
    () => form.value.lhost,
    () => form.value.profile
  ],
  () => {
    fetchStagerCommand()
  }
)

const syncBuildTimer = (running) => {
  window.clearInterval(buildTimer)
  if (running) {
    buildTimer = window.setInterval(() => {
      elapsedTime.value += 1
    }, 1000)
  }
}

const hydrateTerminal = () => {
  if (!terminalContainer.value) return

  xterm = new XTerm({
    theme: {
      background: '#0f0f10',
      foreground: '#f2f2f2',
      cursor: '#ffffff'
    },
    fontSize: 13,
    fontFamily: 'Consolas, SFMono-Regular, monospace',
    convertEol: true
  })

  fitAddon = new FitAddon()
  xterm.loadAddon(fitAddon)
  xterm.open(terminalContainer.value)
  fitAddon.fit()

  if (logBuffer.value.length) {
    xterm.write(logBuffer.value.join('\r\n'))
    xterm.write('\r\n')
  }
}

const disposeTerminal = () => {
  if (xterm) {
    xterm.dispose()
    xterm = null
  }
  fitAddon = null
}

const pushTerminalLog = (line) => {
  logBuffer.value.push(line)
  if (xterm) {
    xterm.writeln(line)
  }
}

const openBuildConsole = async () => {
  if (!currentTaskId.value) return
  isMinimized.value = false
  terminalDialogVisible.value = true
  await nextTick()
}

const restoreTerminal = () => {
  openBuildConsole()
}

const minimizeTerminal = () => {
  isMinimized.value = true
  terminalDialogVisible.value = false
}

const closeBuildSocket = () => {
  if (ws) {
    ws.close()
    ws = null
  }
}

const closeBuildSession = () => {
  terminalDialogVisible.value = false
  isMinimized.value = false
  closeBuildSocket()
  syncBuildTimer(false)
  disposeTerminal()
  currentTaskId.value = ''
  buildFinished.value = false
  buildStatusText.value = '等待任务'
  buildStage.value = 1
  elapsedTime.value = 0
}

const onTerminalOpened = async () => {
  await nextTick()
  disposeTerminal()
  hydrateTerminal()
}

const onTerminalClosed = () => {
  disposeTerminal()
  if (!isMinimized.value && buildFinished.value) {
    closeBuildSocket()
  }
}

const clearTerminal = () => {
  logBuffer.value = []
  xterm?.clear()
}

const exportLogs = () => {
  if (!logBuffer.value.length) return
  const blob = new Blob([logBuffer.value.join('\n')], { type: 'text/plain' })
  const link = document.createElement('a')
  link.href = URL.createObjectURL(blob)
  link.download = `build_${currentTaskId.value ? currentTaskId.value.slice(0, 8) : 'logs'}.txt`
  link.click()
}

const downloadArtifact = async (url) => {
  const response = await request.get(url, { responseType: 'blob' })
  const disposition = response.headers['content-disposition'] || ''
  let filename = disposition.match(/filename\*?=['"]?([^;\n"']+)/i)?.[1] || url.split('/').pop()
  if (filename.includes("''")) {
    filename = decodeURIComponent(filename.replace(/.*''/, ''))
  }
  const link = document.createElement('a')
  link.href = URL.createObjectURL(response.data)
  link.download = filename
  link.click()
}

const attachBuildSocket = async () => {
  const configuredBase = import.meta.env.VITE_API_BASE_URL || ''
  let socketBase = `${window.location.protocol === 'https:' ? 'wss:' : 'ws:'}//${window.location.host}`

  if (configuredBase && configuredBase !== '/') {
    if (configuredBase.startsWith('http://') || configuredBase.startsWith('https://')) {
      socketBase = configuredBase.replace(/^http/, 'ws')
    } else {
      const normalizedBase = configuredBase.startsWith('/') ? configuredBase : `/${configuredBase}`
      socketBase = `${window.location.protocol === 'https:' ? 'wss:' : 'ws:'}//${window.location.host}${normalizedBase}`
    }
  }

  let ticket = ''
  try {
    const res = await request.post('/api/auth/ws-ticket', { purpose: 'build_logs' })
    ticket = res?.data?.ticket || ''
  } catch (_) {
    ticket = ''
  }
  if (!ticket) {
    pushTerminalLog('[FAIL] 未登录或会话已过期，无法获取构建日志升级票据')
    buildStatusText.value = '鉴权失败'
    buildFinished.value = true
    syncBuildTimer(false)
    return
  }

  closeBuildSocket()
  ws = new WebSocket(
    `${socketBase}/api/build/logs/${currentTaskId.value}?ticket=${encodeURIComponent(ticket)}`
  )

  ws.onopen = () => {
    pushTerminalLog('[*] 构建日志通道已连接')
  }

  ws.onerror = () => {
    pushTerminalLog('[FAIL] 构建日志 WebSocket 连接失败（鉴权/网络）')
    if (!buildFinished.value) {
      buildStatusText.value = '日志通道连接失败'
    }
  }

  ws.onclose = (ev) => {
    if (!buildFinished.value && buildStatusText.value === '正在准备构建环境') {
      pushTerminalLog(`[FAIL] 日志通道已断开 (code=${ev.code})，构建可能仍在后台进行，请刷新后重试`)
      buildStatusText.value = '日志通道断开'
      buildFinished.value = true
      syncBuildTimer(false)
    }
  }

  ws.onmessage = async (event) => {
    const payload = JSON.parse(event.data)

    if (payload.type === 'log') {
      pushTerminalLog(payload.content)
      const text = String(payload.content).toLowerCase()
      // 任意构建日志都先离开「准备环境」；命中编译关键字再进编译阶段
      if (buildStage.value < 2) {
        buildStage.value = 1
        if (text.includes('沙箱') || text.includes('sandbox') || text.includes('准备')) {
          buildStatusText.value = '正在准备沙箱环境'
        } else {
          buildStatusText.value = '构建进行中'
        }
      }
      if (text.includes('cargo') || text.includes('compiling') || text.includes('profile')) {
        buildStage.value = 2
        buildStatusText.value = '正在编译核心'
      } else if (text.includes('upx') && form.value.useUPX) {
        buildStage.value = 3
        buildStatusText.value = '正在 UPX 压缩'
      }
      return
    }

    if (payload.type === 'success') {
      pushTerminalLog(`[OK] ${payload.content}`)
      buildStage.value = form.value.useUPX ? 4 : 3
      buildStatusText.value = '构建成功'
      buildFinished.value = true
      syncBuildTimer(false)
      await downloadArtifact(payload.content)
      return
    }

    if (payload.type === 'error') {
      pushTerminalLog(`[FAIL] ${payload.content}`)
      buildStatusText.value = '构建失败'
      buildFinished.value = true
      syncBuildTimer(false)
    }
  }
}

const fetchListenersData = async () => {
  try {
    const response = await getListeners()
    activeListeners.value = (response.data || []).filter((listener) => listener.status === 'Running')
    if (!form.value.listenerId && activeListeners.value.length > 0) {
      form.value.listenerId = activeListeners.value[0].id
      onListenerChange(form.value.listenerId)
    }
  } catch {
    ElMessage.error('无法加载监听器列表')
  }
}

const onListenerChange = (id) => {
  const listener = activeListeners.value.find((item) => item.id === id)
  if (!listener) return
  form.value.obfuscation_mode = listener.obfuscate_mode || 'none'
}

const handleDirectDownload = (response) => {
  const blob = response.data
  const disposition = response.headers['content-disposition'] || ''
  let filename = disposition.match(/filename\*?=['"]?([^;\n"']+)/i)?.[1] || ''
  if (filename.includes("''")) {
    filename = decodeURIComponent(filename.replace(/.*''/, ''))
  }
  if (!filename) {
    const os = form.value.combinedType.split('_')[0]
    const ext = os === 'windows' ? '.exe' : ''
    filename = `agent_${form.value.combinedType}${ext}`
  }
  const link = document.createElement('a')
  link.href = URL.createObjectURL(blob)
  link.download = filename
  link.click()
}

const doGenerate = async () => {
  if (!form.value.listenerId) {
    ElMessage.warning('请先选择监听器')
    return
  }

  loading.value = true
  try {
    if (!filteredListeners.value.some((l) => l.id === form.value.listenerId)) {
      ElMessage.warning('请选择与客户端类型匹配的监听器（反向 / 正向）')
      loading.value = false
      return
    }

    const payload = {
      os: form.value.combinedType.split('_')[0],
      arch: form.value.combinedType,
      listener_id: form.value.listenerId,
      host: form.value.lhost,
      method: form.value.mode,
      auto_destruct: form.value.autoDestruct,
      sleep_time: form.value.sleepTime,
      aes_key: form.value.aesKey,
      use_upx: form.value.mode === 'build' ? form.value.useUPX : false,
      encryption_salt: form.value.encryption_salt,
      obfuscation_mode: form.value.obfuscation_mode,
      profile: form.value.profile || 'reverse'
    }

    const response = await generateClient(payload)
    const blobData = response.data

    if (blobData.type === 'application/json' || blobData.size < 2048) {
      const text = await blobData.text()
      const json = JSON.parse(text)
      if (json.task_id) {
        currentTaskId.value = json.task_id
        logBuffer.value = []
        elapsedTime.value = 0
        buildStage.value = 1
        buildStatusText.value = '正在准备构建环境'
        buildFinished.value = false
        terminalDialogVisible.value = true
        isMinimized.value = false
        syncBuildTimer(true)
        attachBuildSocket()
        return
      }
    }

    handleDirectDownload(response)
    ElMessage.success('载荷已生成并开始下载')
  } catch {
    ElMessage.error('生成失败，请检查监听器与构建配置')
  } finally {
    loading.value = false
  }
}

const fetchStagerCommand = async () => {
  if (!form.value.listenerId) {
    stagerCommand.value = ''
    stagerCommandPs.value = ''
    stagerCommandPsInline.value = ''
    stagerCommandStager.value = ''
    stagerNotes.value = []
    stagerMeta.value = emptyStagerMeta()
    return
  }
  stagerLoading.value = true
  try {
    const parts = form.value.combinedType.split('_')
    const os = parts[0]
    const arch = parts.slice(1).join('_') || 'amd64'
    const delivery = stagerDelivery.value || 'disk'
    // host = Agent 回连地址；下载域名由后端使用当前面板 Host，勿混用
    const response = await request.get('/api/stager', {
      params: {
        listener_id: form.value.listenerId,
        os,
        arch,
        host: form.value.lhost,
        profile: form.value.profile || 'reverse',
        delivery
      }
    })
    const d = response.data || {}
    stagerCommandPs.value = d.command_ps || ''
    stagerCommandPsInline.value = d.command_ps_inline || ''
    stagerCommandPsBat.value = d.command_ps_bat || ''
    stagerCommandStager.value = d.command_stager || ''
    stagerNotes.value = Array.isArray(d.notes) ? d.notes : []
    if (delivery === 'fileless') {
      stagerCommand.value = d.command_ps || d.command || ''
      filelessTab.value = 'ps'
    } else {
      stagerCommand.value = d.command_cmd || d.command || ''
      // 后端 recommended 决定默认 tab：command_ps → ps，其他 → cmd
      diskTab.value = d.recommended === 'command_ps' ? 'ps' : 'cmd'
    }
    stagerMeta.value = {
      panel_host: d.panel_host || '',
      callback: d.callback || form.value.lhost || '',
      profile: d.profile || form.value.profile || '',
      profile_label: d.profile_label || profileLabel.value,
      delivery: d.delivery || delivery,
      stage2_url: d.stage2_url || d.download || '',
      stage2_bytes: d.stage2_bytes || 0,
      stage2_ttl_sec: d.stage2_ttl_sec || 0,
      expires_at: d.expires_at || ''
    }
    if (delivery === 'fileless' && d.stage2_bytes) {
      ElMessage.success(`内存 Stage2 已生成（${formatBytes(d.stage2_bytes)}，约 10 分钟有效）`)
    }
  } catch (e) {
    stagerCommand.value = ''
    stagerCommandPs.value = ''
    stagerCommandPsInline.value = ''
    stagerCommandPsBat.value = ''
    stagerCommandStager.value = ''
    stagerNotes.value = []
    stagerMeta.value = emptyStagerMeta()
    const msg = e?.response?.data?.error || '一键上线命令生成失败'
    const hint = e?.response?.data?.hint
    ElMessage.error(hint ? `${msg}（${hint}）` : msg)
  } finally {
    stagerLoading.value = false
  }
}

const copyText = async (text) => {
  if (!text) return
  await navigator.clipboard.writeText(text)
  ElMessage.success('已复制到剪贴板')
}

const copyStagerCommand = async () => {
  await copyText(stagerCommand.value)
}

onMounted(async () => {
  await fetchListenersData()

  resizeHandler = () => {
    fitAddon?.fit()
  }
  window.addEventListener('resize', resizeHandler)
})

onUnmounted(() => {
  window.removeEventListener('resize', resizeHandler)
  syncBuildTimer(false)
  closeBuildSocket()
  disposeTerminal()
})
</script>

<style scoped>
.payload-shell {
  flex: 1;
  min-height: 0;
  gap: 20px;
}

.payload-toolbar {
  display: flex;
  justify-content: flex-end;
}

.payload-toolbar__metrics {
  display: flex;
  gap: 10px;
  flex-wrap: wrap;
}

.stager-host-hint {
  margin: 0 0 10px;
  font-size: 12px;
  line-height: 1.45;
  opacity: 0.85;
}

.stager-meta {
  display: flex;
  flex-direction: column;
  gap: 6px;
  margin: 0 0 12px;
  padding: 10px 12px;
  border-radius: 10px;
  background: rgba(0, 0, 0, 0.22);
  border: 1px solid rgba(255, 255, 255, 0.06);
}

.stager-meta__row {
  display: flex;
  justify-content: space-between;
  gap: 12px;
  font-size: 12px;
}

.stager-meta__row span {
  opacity: 0.7;
  flex-shrink: 0;
}

.stager-alert {
  margin-bottom: 10px;
}

.cmd-tabs {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  margin: 10px 0 8px;
}

.cmd-tab {
  border: 1px solid rgba(255, 255, 255, 0.12);
  background: rgba(255, 255, 255, 0.04);
  color: inherit;
  border-radius: 999px;
  padding: 4px 10px;
  font-size: 12px;
  cursor: pointer;
}

.cmd-tab--active {
  border-color: var(--el-color-primary);
  background: color-mix(in srgb, var(--el-color-primary) 22%, transparent);
  font-weight: 600;
}

.stage2-url {
  max-width: 200px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  display: inline-block;
  vertical-align: bottom;
}

.fileless-block {
  margin-top: 12px;
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.fileless-block__label {
  font-size: 12px;
  font-weight: 600;
  opacity: 0.85;
}

.terminal-card--sm code {
  font-size: 11px;
  word-break: break-all;
  white-space: pre-wrap;
  max-height: 120px;
  overflow: auto;
  display: block;
}

.fileless-notes {
  margin: 12px 0 0;
  padding-left: 18px;
  font-size: 11px;
  line-height: 1.5;
  opacity: 0.8;
}

.stager-meta__row code {
  text-align: right;
  word-break: break-all;
  font-size: 12px;
}

.profile-switch {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 10px;
  margin-bottom: 12px;
}

.profile-switch__item {
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  gap: 4px;
  padding: 12px 14px;
  border: 1px solid rgba(255, 255, 255, 0.08);
  border-radius: 12px;
  background: rgba(0, 0, 0, 0.18);
  color: inherit;
  cursor: pointer;
  text-align: left;
  transition: border-color 0.15s ease, background 0.15s ease;
}

.profile-switch__item span {
  font-weight: 600;
}

.profile-switch__item small {
  opacity: 0.72;
  line-height: 1.35;
}

.profile-switch__item--active {
  border-color: rgba(64, 158, 255, 0.65);
  background: rgba(64, 158, 255, 0.12);
}

.profile-section-title {
  margin-top: 8px;
}

.profile-hint,
.profile-alert {
  margin-bottom: 12px;
}

.option-card--disabled {
  opacity: 0.55;
}

.payload-grid {
  display: grid;
  grid-template-columns: minmax(0, 1.45fr) minmax(320px, 0.8fr);
  gap: 20px;
  min-height: 0;
}

.builder-card,
.sidebar-card {
  padding: 24px;
}

.panel-head--tight {
  margin-bottom: 16px;
}
.panel-head h3,
.dialog-header h3 {
  margin: 0;
  font-size: 24px;
  letter-spacing: -0.04em;
}

.payload-form {
  display: flex;
  flex-direction: column;
  gap: 24px;
}

.section-block {
  display: flex;
  flex-direction: column;
  gap: 18px;
}

.section-title {
  display: flex;
  align-items: flex-start;
  gap: 14px;
}

.section-index {
  width: 34px;
  height: 34px;
  display: grid;
  place-items: center;
  border-radius: 12px;
  background: var(--surface-muted);
  color: var(--text-strong);
  font-size: 12px;
  font-weight: 800;
}

.section-title strong {
  display: block;
  margin-bottom: 4px;
  font-size: 15px;
}

.section-title p {
  margin: 0;
  color: var(--text-body);
  line-height: 1.6;
  font-size: 13px;
}

.platform-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 16px;
}

.platform-card {
  padding: 20px;
  border: 1px solid var(--line-soft);
  border-radius: 22px;
  background: var(--surface-soft);
  text-align: left;
  cursor: pointer;
  transition: transform 0.16s ease, border-color 0.16s ease, background 0.16s ease;
}

.platform-card:hover {
  transform: translateY(-1px);
  border-color: var(--line-strong);
}

.platform-card--active {
  background: #ffffff;
  border-color: var(--text-strong);
  box-shadow: var(--shadow-soft);
}

.platform-card__head {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 14px;
}

.platform-card__icon {
  width: 42px;
  height: 42px;
  display: grid;
  place-items: center;
  border-radius: 14px;
  background: var(--surface-muted);
  font-size: 18px;
}

.platform-card__head strong,
.platform-card__head span {
  display: block;
}

.platform-card__head span {
  margin-top: 4px;
  font-size: 12px;
  color: var(--text-muted);
}

.platform-options {
  width: 100%;
}

.platform-options :deep(.el-radio-button) {
  flex: 1;
}

.platform-options :deep(.el-radio-button__inner) {
  width: 100%;
}

.form-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 18px;
}

.mode-panel {
  padding: 22px;
  border-radius: 24px;
  background: var(--surface-soft);
  border: 1px solid var(--line-soft);
}

.mode-switch {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 12px;
}

.mode-switch__item {
  padding: 16px 18px;
  border: 1px solid var(--line-soft);
  border-radius: 18px;
  background: rgba(255, 255, 255, 0.82);
  text-align: left;
  cursor: pointer;
}

.mode-switch__item span,
.mode-switch__item small {
  display: block;
}

.mode-switch__item span {
  font-weight: 800;
  color: var(--text-strong);
}

.mode-switch__item small {
  margin-top: 4px;
  font-size: 12px;
  color: var(--text-muted);
}

.mode-switch__item--active {
  border-color: var(--text-strong);
  background: #ffffff;
}

.mode-note {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 14px 16px;
  border-radius: 18px;
  background: rgba(255, 255, 255, 0.8);
  color: var(--text-body);
  line-height: 1.6;
  font-size: 13px;
}

.option-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 14px;
}

.option-card {
  display: flex;
  flex-direction: column;
  gap: 12px;
  padding: 16px;
  border-radius: 18px;
  border: 1px solid var(--line-soft);
  background: rgba(255, 255, 255, 0.9);
}

.option-card__label {
  font-size: 11px;
  font-weight: 800;
  text-transform: uppercase;
  letter-spacing: 0.12em;
  color: var(--text-muted);
}

.option-card strong {
  font-size: 16px;
}

.build-preview {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 20px;
  padding-top: 6px;
  border-top: 1px solid var(--line-soft);
}

.build-preview__copy {
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.build-preview__label {
  font-size: 11px;
  color: var(--text-muted);
  text-transform: uppercase;
  letter-spacing: 0.12em;
  font-weight: 700;
}

.build-preview__value {
  color: var(--text-strong);
  font-size: 13px;
  word-break: break-all;
}

.generate-btn {
  min-width: 150px;
}

.stager-state,
.tips-stack,
.status-grid {
  display: flex;
  flex-direction: column;
  gap: 14px;
}

.terminal-card {
  padding: 16px;
  border-radius: 18px;
  background: #0f0f10;
  color: #f2f2f2;
}

.terminal-card__dots {
  display: flex;
  gap: 6px;
  margin-bottom: 12px;
}

.terminal-card__dots span {
  width: 8px;
  height: 8px;
  border-radius: 999px;
  background: rgba(255, 255, 255, 0.26);
}

.terminal-card code {
  display: block;
  line-height: 1.7;
  word-break: break-all;
  font-size: 12px;
  font-family: Consolas, SFMono-Regular, monospace;
}

.empty-copy {
  padding: 22px 0 4px;
  font-size: 13px;
  color: var(--text-muted);
  line-height: 1.7;
}

.sidebar-actions {
  display: flex;
  gap: 10px;
  flex-wrap: wrap;
}

.sidebar-button {
  flex: 1;
  min-width: 120px;
}

.tip-row {
  display: flex;
  gap: 12px;
  align-items: flex-start;
}

.tip-row__icon {
  width: 38px;
  height: 38px;
  display: grid;
  place-items: center;
  border-radius: 14px;
  background: var(--surface-muted);
  color: var(--text-strong);
  flex-shrink: 0;
}

.tip-row p {
  margin: 0;
  font-size: 13px;
  color: var(--text-body);
  line-height: 1.7;
}

.status-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 12px;
}

.status-grid--dialog {
  grid-template-columns: repeat(4, minmax(0, 1fr));
}

.status-cell {
  display: flex;
  flex-direction: column;
  gap: 6px;
  padding: 14px 16px;
  border-radius: 18px;
  background: var(--surface-soft);
  border: 1px solid var(--line-soft);
}

.status-cell span {
  font-size: 11px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.12em;
  color: var(--text-muted);
}

.status-cell strong {
  font-size: 14px;
}

.dialog-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 18px;
}

.dialog-actions {
  display: flex;
  gap: 10px;
}

.dialog-content {
  display: flex;
  flex-direction: column;
  gap: 18px;
}

.pipeline {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 12px;
}

.pipeline-step {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 14px 16px;
  border-radius: 18px;
  background: var(--surface-soft);
  border: 1px solid var(--line-soft);
  color: var(--text-muted);
  font-size: 13px;
  font-weight: 700;
}

.pipeline-step__dot {
  width: 26px;
  height: 26px;
  display: grid;
  place-items: center;
  border-radius: 999px;
  background: #ffffff;
  border: 1px solid var(--line-soft);
  font-size: 11px;
}

.pipeline-step--active,
.pipeline-step--done {
  color: var(--text-strong);
}

.pipeline-step--active {
  border-color: var(--text-strong);
}

.pipeline-step--active .pipeline-step__dot {
  background: var(--text-strong);
  color: #ffffff;
  border-color: var(--text-strong);
}

.pipeline-step--done .pipeline-step__dot {
  border-color: var(--text-strong);
}

.terminal-toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 14px;
  padding: 0 4px;
}

.terminal-toolbar span {
  font-size: 12px;
  font-weight: 700;
  color: var(--text-muted);
  text-transform: uppercase;
  letter-spacing: 0.12em;
}

.terminal-toolbar__actions {
  display: flex;
  gap: 10px;
}

.terminal-wrap {
  height: 420px;
  padding: 16px;
  border-radius: 22px;
  background: #0f0f10;
}

.xterm-view {
  width: 100%;
  height: 100%;
}

.build-bubble {
  position: fixed;
  right: 28px;
  bottom: 28px;
  display: inline-flex;
  align-items: center;
  gap: 14px;
  padding: 14px 18px;
  border: 0;
  border-radius: 20px;
  background: #111111;
  color: #ffffff;
  box-shadow: 0 16px 40px rgba(17, 17, 17, 0.18);
  cursor: pointer;
  z-index: 2100;
}

.build-bubble strong,
.build-bubble span {
  display: block;
  text-align: left;
}

.build-bubble strong {
  font-size: 13px;
}

.build-bubble span {
  margin-top: 4px;
  font-size: 11px;
  opacity: 0.72;
}

.pop-enter-active,
.pop-leave-active {
  transition: opacity 0.18s ease, transform 0.18s ease;
}

.pop-enter-from,
.pop-leave-to {
  opacity: 0;
  transform: translateY(8px);
}

@media (max-width: 1240px) {
  .payload-grid {
    grid-template-columns: 1fr;
  }
}

@media (max-width: 900px) {
  .payload-toolbar__metrics {
    width: 100%;
  }

  .platform-grid,
  .form-grid,
  .option-grid,
  .status-grid,
  .status-grid--dialog,
  .pipeline {
    grid-template-columns: 1fr;
  }

  .build-preview {
    flex-direction: column;
    align-items: stretch;
  }

  .generate-btn,
  .sidebar-button {
    width: 100%;
  }
}

@media (max-width: 720px) {
  .payload-toolbar {
    flex-direction: column;
    align-items: stretch;
  }

  .builder-card,
  .sidebar-card,
  .terminal-wrap {
    padding: 18px;
  }

  .panel-head h3,
  .dialog-header h3 {
    font-size: 20px;
  }

  .mode-switch {
    grid-template-columns: 1fr;
  }

  .dialog-header,
  .terminal-toolbar {
    flex-direction: column;
    align-items: flex-start;
  }

  .build-bubble {
    left: 14px;
    right: 14px;
    bottom: 14px;
  }
}
</style>
