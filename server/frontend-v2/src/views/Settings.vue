<template>
  <div class="view-shell settings-shell">
    <section class="surface-card settings-panel">
      <el-tabs v-model="activeTab" class="premium-tabs">
        <el-tab-pane name="users">
          <template #label>
            <div class="tab-label">
              <el-icon><User /></el-icon>
              <span>人员与访问控制</span>
            </div>
          </template>

          <div class="tab-inner">
            <div class="section-title-line tab-toolbar mb-20">
              <h3 class="section-h3">后台操作员列表</h3>
              <el-button class="premium-btn purple-btn" :icon="Plus" @click="openUserDialog()">新增资产操作员</el-button>
            </div>

            <div class="section-card">
              <el-table :data="users" v-loading="loading" class="premium-table">
                <el-table-column prop="username" label="账户名">
                  <template #default="scope">
                    <div class="user-id-cell">
                      <el-avatar :size="24" class="mini-avatar">{{ scope.row.username.charAt(0).toUpperCase() }}</el-avatar>
                      <span class="u-name">{{ scope.row.username }}</span>
                    </div>
                  </template>
                </el-table-column>

                <el-table-column label="角色权限" width="160" align="center">
                  <template #default="scope">
                    <div class="role-chip" :class="scope.row.role">
                      {{ scope.row.role === 'admin' ? '系统管理员' : '战术操作员' }}
                    </div>
                  </template>
                </el-table-column>

                <el-table-column label="账号状态" width="120" align="center">
                  <template #default="scope">
                    <el-switch
                      v-model="scope.row.is_active"
                      @change="toggleUserStatus(scope.row)"
                      active-color="var(--text-strong)"
                    />
                  </template>
                </el-table-column>

                <el-table-column label="操作" width="180" align="center">
                  <template #default="scope">
                    <el-button link class="action-btn purple" @click="openUserDialog(scope.row)">鉴权变更</el-button>
                    <el-button
                      link
                      class="action-btn red"
                      @click="deleteUser(scope.row)"
                      :disabled="scope.row.username === 'admin'"
                    >
                      注销
                    </el-button>
                  </template>
                </el-table-column>
              </el-table>
            </div>

            <div class="section-card section-card--spaced">
              <div class="section-head mb-20">
                <h3 class="section-h3">登录审计流</h3>
                <span class="section-meta">{{ loginLogs.length }} entries</span>
              </div>

              <el-table :data="loginLogs" size="small" class="premium-table audit-table">
                <el-table-column prop="created_at" label="时间戳" width="180">
                  <template #default="scope">{{ formatDate(scope.row.created_at) }}</template>
                </el-table-column>
                <el-table-column prop="username" label="操作账户" width="120" />
                <el-table-column prop="ip" label="源 IP" width="140" />
                <el-table-column label="结果状态" width="100">
                  <template #default="scope">
                    <div class="audit-status" :class="scope.row.status">
                      {{ scope.row.status === 'success' ? '通过' : '拒绝' }}
                    </div>
                  </template>
                </el-table-column>
                <el-table-column prop="user_agent" label="终端环境代理" show-overflow-tooltip />
              </el-table>
            </div>
          </div>
        </el-tab-pane>

        <el-tab-pane name="notifications">
          <template #label>
            <div class="tab-label">
              <el-icon><Bell /></el-icon>
              <span>自动化通知集</span>
            </div>
          </template>

          <div class="tab-inner">
            <div class="section-title-line tab-toolbar mb-20">
              <h3 class="section-h3">外部推送隧道</h3>
              <el-button class="premium-btn purple-btn" :icon="Plus" @click="openWebhookDialog()">接入新 Webhook</el-button>
            </div>

            <div v-if="webhooks.length" class="webhook-grid">
              <div v-for="hook in webhooks" :key="hook.id" class="webhook-bento-card">
                <div class="bento-header">
                  <div class="bento-logo-box">
                    <img :src="getWebhookIcon(hook.type)" class="bento-icon" />
                    <span>{{ hook.name }}</span>
                  </div>
                  <el-switch v-model="hook.is_enabled" @change="saveWebhook(hook)" active-color="var(--text-strong)" />
                </div>

                <div class="bento-url">{{ hook.url }}</div>

                <div class="bento-footer">
                  <div class="event-chips">
                    <span v-for="ev in hook.events.split(',')" :key="ev" class="mini-chip">
                      {{ ev === 'agent_online' ? 'Agent 上线' : 'Agent 离线' }}
                    </span>
                  </div>

                  <div class="bento-actions">
                    <el-button link class="action-btn purple" @click="openWebhookDialog(hook)">配置</el-button>
                    <el-button link class="action-btn red" @click="deleteWebhook(hook.id)">注销</el-button>
                  </div>
                </div>
              </div>
            </div>

            <div v-else class="empty-state-card">
              <div class="empty-state-copy">
                <h4>还没有接入推送通道</h4>
                <p>接入 Webhook 后，这里会显示通知通道、事件订阅状态和启用开关。</p>
              </div>
              <el-button class="premium-btn purple-btn" :icon="Plus" @click="openWebhookDialog()">接入第一个 Webhook</el-button>
            </div>
          </div>
        </el-tab-pane>

        <el-tab-pane name="policies">
          <template #label>
            <div class="tab-label">
              <el-icon><Setting /></el-icon>
              <span>核心运行策略</span>
            </div>
          </template>

          <div class="tab-inner policy-form">
            <el-form label-position="top">
              <div class="policy-shell">
                <div class="policy-side">
                  <div class="form-group glass-panel-sub">
                    <div class="policy-card-head">
                      <label class="group-label">安全特征伪装</label>
                      <span class="policy-card-tip">Cloak</span>
                    </div>

                    <el-form-item label="全局反连地址 Host">
                      <el-input v-model="globalConfig.system_c2_host" placeholder="c2.domain.com" />
                    </el-form-item>

                    <el-form-item label="探测屏蔽重定向 (404 Cloak URL)">
                      <el-input v-model="globalConfig.opsec_cloak_url" placeholder="https://www.bing.com" />
                    </el-form-item>
                  </div>

                  <div class="form-group glass-panel-sub">
                    <div class="policy-card-head">
                      <label class="group-label">鉴权与自动化</label>
                      <span class="policy-card-tip">Access</span>
                    </div>

                    <el-form-item label="Master API Token">
                      <el-input v-model="globalConfig.system_api_token" show-password>
                        <template #append>
                          <el-button @click="copyToken">复制</el-button>
                        </template>
                      </el-input>
                    </el-form-item>

                    <div class="switch-row">
                      <div class="row-label">
                        <span>启用 MCP 自动化网关</span>
                        <small>允许外部脚本通过 Token 访问接口群</small>
                      </div>
                      <el-switch v-model="globalConfig.system_mcp_enabled" active-value="true" inactive-value="false" active-color="var(--text-strong)" />
                    </div>
                    <div class="switch-row">
                      <div class="row-label">
                        <span>MCP 只读模式</span>
                        <small>默认开启：仅查询。关闭后 MCP 可提交写操作，但<strong>全部增删改</strong>须在顶部「MCP 确认」由管理员批准后才执行（含完整 Shell 命令展示）</small>
                      </div>
                      <el-switch v-model="globalConfig.mcp_read_only" active-value="true" inactive-value="false" active-color="var(--text-strong)" />
                    </div>
                  </div>
                </div>
              </div>

              <div class="form-footer-action">
                <el-button type="primary" class="huge-save-btn" @click="saveGlobalSettings">同步核心配置至集群</el-button>
              </div>
            </el-form>
          </div>
        </el-tab-pane>

        <el-tab-pane name="maintenance">
          <template #label>
            <div class="tab-label">
              <el-icon><DataLine /></el-icon>
              <span>数据维护与熔断</span>
            </div>
          </template>

          <div class="tab-inner">
            <div class="maintenance-grid">
              <div class="m-card glass-panel-sub">
                <div class="m-icon blue"><el-icon><Download /></el-icon></div>
                <div class="m-copy">
                  <h4 class="m-title">全量数据冷备份</h4>
                  <p class="m-desc">导出当前数据库所有资产标识、通信日志及任务审计历史为 JSON 格式。</p>
                </div>
                <el-button plain class="m-btn" @click="exportData">执行全量导出</el-button>
              </div>

              <div class="m-card glass-panel-sub">
                <div class="m-icon red"><el-icon><Delete /></el-icon></div>
                <div class="m-copy">
                  <h4 class="m-title">环境一键熔断</h4>
                  <p class="m-desc">立即清除所有 Agent 回连记录、历史指令流。此操作不可逆。</p>
                </div>
                <el-button type="danger" class="m-btn" @click="resetDatabase">紧急熔断环境</el-button>
              </div>
            </div>
          </div>
        </el-tab-pane>
      </el-tabs>
    </section>

    <el-dialog v-model="userDialog.visible" :title="userDialog.isEdit ? '人员鉴权变更' : '人员准入授权'" width="420px" class="premium-dialog" center>
      <div class="dialog-inner">
        <el-form :model="userDialog.form" label-position="top">
          <el-form-item label="操作员 ID">
            <el-input v-model="userDialog.form.username" :disabled="userDialog.isEdit" :prefix-icon="User" />
          </el-form-item>
          <el-form-item label="访问密文 (密码)">
            <el-input v-model="userDialog.form.password" type="password" show-password placeholder="保持不变请留空" :prefix-icon="Lock" />
          </el-form-item>
          <el-form-item label="授权角色">
            <el-select v-model="userDialog.form.role" style="width: 100%">
              <el-option label="系统管理员" value="admin" />
              <el-option label="战术操作员" value="operator" />
            </el-select>
          </el-form-item>
        </el-form>
      </div>
      <template #footer>
        <div class="dialog-footer">
          <el-button @click="userDialog.visible = false" class="plain-btn">取消</el-button>
          <el-button type="primary" class="purple-btn" @click="saveUser">确认同步</el-button>
        </div>
      </template>
    </el-dialog>

    <el-dialog v-model="webhookDialog.visible" title="Webhook 通道集成" width="500px" class="premium-dialog" center>
      <div class="dialog-inner">
        <el-form :model="webhookDialog.form" label-position="top">
          <el-form-item label="推送渠道名称">
            <el-input v-model="webhookDialog.form.name" placeholder="例如: 蓝队预警频道" />
          </el-form-item>
          <el-form-item label="集成协议类型">
            <el-radio-group v-model="webhookDialog.form.type" class="platform-tabs">
              <el-radio-button label="dingtalk">钉钉</el-radio-button>
              <el-radio-button label="feishu">飞书</el-radio-button>
              <el-radio-button label="telegram">TG</el-radio-button>
            </el-radio-group>
          </el-form-item>
          <el-form-item label="转发接口 URL (Callback URL)">
            <el-input v-model="webhookDialog.form.url" type="textarea" :rows="2" placeholder="https://oapi.dingtalk.com/..." />
          </el-form-item>
        </el-form>
      </div>
      <template #footer>
        <div class="dialog-footer">
          <el-button @click="webhookDialog.visible = false" class="plain-btn">取消</el-button>
          <el-button type="primary" class="purple-btn" @click="submitWebhook">激活通道</el-button>
        </div>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { onMounted, reactive, ref } from 'vue'
import { Bell, DataLine, Delete, Download, Lock, Plus, Setting, User } from '@element-plus/icons-vue'
import api from '../api/index'
import { ElMessage, ElMessageBox } from 'element-plus'

const activeTab = ref('users')
const loading = ref(false)

const users = ref([])
const loginLogs = ref([])
const webhooks = ref([])
const globalConfig = reactive({
  system_c2_host: '',
  system_api_token: '',
  system_mcp_enabled: 'true',
  mcp_read_only: 'true',
  opsec_cloak_url: ''
})

const userDialog = reactive({
  visible: false,
  isEdit: false,
  form: { id: null, username: '', password: '', role: 'operator' }
})

const webhookDialog = reactive({
  visible: false,
  isEdit: false,
  form: { id: null, name: '', type: 'dingtalk', url: '', events: '' },
  selectedEvents: ['agent_online']
})

const fetchAll = async () => {
  loading.value = true
  try {
    const [u, logs, hooks, conf, mcp] = await Promise.all([
      api.get('/api/settings/users'),
      api.get('/api/settings/logs/login'),
      api.get('/api/settings/webhooks'),
      api.get('/api/settings/config'),
      api.get('/api/settings/mcp').catch(() => ({ data: null }))
    ])
    users.value = u.data || []
    loginLogs.value = logs.data || []
    webhooks.value = hooks.data || []
    conf.data.forEach((item) => {
      if (Object.prototype.hasOwnProperty.call(globalConfig, item.key)) {
        globalConfig[item.key] = item.value
      }
    })
    if (mcp?.data) {
      globalConfig.system_mcp_enabled = mcp.data.enabled ? 'true' : 'false'
      globalConfig.mcp_read_only = mcp.data.read_only ? 'true' : 'false'
    }
  } catch (error) {
    ElMessage.error('同步异常')
  } finally {
    loading.value = false
  }
}

const openUserDialog = (row = null) => {
  userDialog.isEdit = !!row
  userDialog.form = row ? { ...row, password: '' } : { id: null, username: '', password: '', role: 'operator' }
  userDialog.visible = true
}

const saveUser = async () => {
  try {
    if (userDialog.isEdit) await api.put(`/api/settings/users/${userDialog.form.id}`, userDialog.form)
    else await api.post('/api/settings/users', userDialog.form)
    userDialog.visible = false
    fetchAll()
  } catch (error) {
    ElMessage.error('无法同步人员信息')
  }
}

const toggleUserStatus = async (user) => {
  try {
    await api.put(`/api/settings/users/${user.id}`, { is_active: user.is_active })
  } catch (error) {
    user.is_active = !user.is_active
    ElMessage.error('状态变更被阻止')
  }
}

const deleteUser = (user) => {
  ElMessageBox.confirm(`确认注销账户 ${user.username} 吗？`, '核心警告', { type: 'warning' }).then(async () => {
    await api.delete(`/api/settings/users/${user.id}`)
    fetchAll()
  })
}

const openWebhookDialog = (row = null) => {
  webhookDialog.form = row ? { ...row } : { id: null, name: '', type: 'dingtalk', url: '', events: 'agent_online' }
  webhookDialog.visible = true
}

const submitWebhook = async () => {
  webhookDialog.form.events = 'agent_online,agent_offline'
  await saveWebhook(webhookDialog.form)
  webhookDialog.visible = false
}

const saveWebhook = async (hook) => {
  try {
    await api.post('/api/settings/webhooks', hook)
    fetchAll()
  } catch (error) {
    ElMessage.error('Webhook 同步失败')
  }
}

const deleteWebhook = (id) => {
  api.delete(`/api/settings/webhooks/${id}`).then(() => fetchAll())
}

const getWebhookIcon = (type) => {
  const icons = {
    dingtalk: 'https://img.icons8.com/color/48/000000/dingtalk.png',
    feishu: 'https://img.icons8.com/color/48/000000/lark.png',
    slack: 'https://img.icons8.com/color/48/000000/slack-new.png',
    telegram: 'https://img.icons8.com/color/48/000000/telegram-app.png'
  }
  return icons[type] || ''
}

const saveGlobalSettings = async () => {
  // MCP + sensitive/auth keys go through dedicated endpoints (blocked on generic config API)
  const skipKeys = new Set([
    'system_mcp_enabled',
    'mcp_read_only',
    'mcp_api_token',
    'mcp_allowed_cidrs',
    'system_api_token',
    'web_auth_user',
    'web_auth_password'
  ])
  const payload = Object.entries(globalConfig)
    .filter(([key]) => !skipKeys.has(key))
    .map(([key, value]) => {
      let group = 'access'
      if (key.startsWith('opsec')) group = 'opsec'
      else if (key.includes('token')) group = 'security'
      return { key, value: String(value), group }
    })
  try {
    if (payload.length) {
      await api.post('/api/settings/config', payload)
    }
    await api.put('/api/settings/mcp', {
      enabled: globalConfig.system_mcp_enabled === 'true',
      read_only: globalConfig.mcp_read_only === 'true'
    })
    ElMessage.success('配置同步成功')
  } catch (error) {
    ElMessage.error(error?.response?.data?.error || '保存同步冲突')
  }
}

const copyToken = () => {
  navigator.clipboard.writeText(globalConfig.system_api_token)
  ElMessage.success('Token 已复制')
}

const exportData = () => {
  window.open('/api/maintenance/export', '_blank')
}

const resetDatabase = () => {
  ElMessageBox.confirm('环境熔断将清空所有战利品记录，确认继续吗？', '熔断确认', { type: 'error' }).then(async () => {
    await api.post('/api/maintenance/reset')
    fetchAll()
  })
}

const formatDate = (ts) => (ts ? new Date(ts).toLocaleString() : '---')

onMounted(fetchAll)
</script>

<style scoped>
.settings-shell {
  width: 100%;
}

.settings-panel {
  padding: 24px;
  border-radius: var(--radius-lg, 24px);
  background: var(--bg-elevated, #ffffff);
  border: 1px solid var(--line-soft, rgba(17, 17, 17, 0.08));
  box-shadow: var(--shadow-panel, 0 14px 32px rgba(17, 17, 17, 0.04));
}

.mb-20 {
  margin-bottom: 20px;
}

.tab-inner {
  padding: 12px 0 0;
}

.tab-toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  flex-wrap: wrap;
}

.section-title-line {
  display: flex;
}

.section-h3 {
  margin: 0;
  font-size: 18px;
  line-height: 1.2;
  color: var(--text-strong);
}

.section-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
}

.section-meta {
  font-size: 12px;
  font-weight: 700;
  color: var(--text-muted);
}

.section-card {
  padding: 14px;
  border: 1px solid rgba(17, 17, 17, 0.09);
  border-radius: 18px;
  background: linear-gradient(180deg, rgba(255, 255, 255, 0.96), rgba(250, 250, 250, 0.94));
  box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.7);
}

.section-card--spaced {
  margin-top: 18px;
}

.user-id-cell {
  display: flex;
  align-items: center;
  gap: 10px;
}

.u-name {
  font-weight: 700;
  color: var(--text-strong);
}

.mini-avatar,
.role-chip,
.m-icon,
.purple-btn,
.huge-save-btn {
  background: var(--text-strong) !important;
  color: var(--bg-panel-strong) !important;
  box-shadow: none !important;
}

.role-chip {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-width: 120px;
  padding: 8px 12px;
  border-radius: 12px;
  font-weight: 700;
}

.role-chip.operator,
.role-chip.admin,
.audit-status,
.mini-chip {
  background: var(--surface-muted) !important;
  color: var(--text-strong) !important;
  border: 1px solid var(--line-control) !important;
}

.audit-status {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-width: 68px;
  padding: 6px 10px;
  border-radius: 10px;
  font-weight: 700;
}

.premium-tabs :deep(.el-tabs__header) {
  margin: 0 0 20px 0 !important;
  padding: 6px 10px !important;
  background: #f5f5f7 !important;
  border: 1px solid rgba(17, 17, 17, 0.06) !important;
  border-radius: 16px !important;
}

.premium-tabs :deep(.el-tabs__nav-wrap::after) {
  display: none !important;
}

.premium-tabs :deep(.el-tabs__item) {
  height: 38px !important;
  line-height: 38px !important;
  padding: 0 16px !important;
  border-radius: 12px !important;
  font-size: 13px !important;
  font-weight: 700 !important;
  color: var(--text-muted) !important;
  transition: all 0.2s ease !important;
}

.premium-tabs :deep(.el-tabs__item:hover) {
  color: var(--text-strong) !important;
}

.premium-tabs :deep(.el-tabs__item.is-active) {
  background: #ffffff !important;
  color: var(--text-strong) !important;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.06) !important;
}

.premium-tabs :deep(.el-tabs__active-bar) {
  display: none !important;
}

.tab-label {
  display: inline-flex;
  align-items: center;
  gap: 8px;
}

.action-btn {
  font-weight: 700;
}

.webhook-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 18px;
}

.webhook-bento-card,
.glass-panel-sub {
  border: 1px solid rgba(17, 17, 17, 0.1);
  border-radius: 18px;
  background: linear-gradient(180deg, rgba(255, 255, 255, 0.97), rgba(249, 249, 249, 0.95));
  box-shadow: 0 8px 24px rgba(17, 17, 17, 0.03);
}

.webhook-bento-card {
  padding: 16px;
}

.bento-header,
.bento-footer,
.switch-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
}

.bento-header {
  margin-bottom: 14px;
}

.bento-logo-box {
  display: flex;
  align-items: center;
  gap: 12px;
  min-width: 0;
  font-weight: 700;
  color: var(--text-strong);
}

.bento-icon {
  width: 34px;
  height: 34px;
  border-radius: 10px;
}

.bento-url,
.m-desc,
.row-label small {
  color: var(--text-muted) !important;
}

.bento-url {
  padding: 10px 12px;
  border-radius: 12px;
  font-size: 13px;
  line-height: 1.5;
  word-break: break-all;
  border: 1px solid rgba(17, 17, 17, 0.06);
}

.bento-footer {
  margin-top: 14px;
  align-items: flex-start;
}

.event-chips {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
}

.mini-chip {
  display: inline-flex;
  align-items: center;
  padding: 6px 10px;
  border-radius: 999px;
  font-size: 12px;
  font-weight: 700;
}

.bento-actions {
  display: flex;
  gap: 12px;
}

.empty-state-card {
  min-height: 180px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 18px;
  padding: 22px;
  border: 1px dashed var(--line-control);
  border-radius: 18px;
  background: linear-gradient(180deg, rgba(255, 255, 255, 0.92), rgba(248, 248, 248, 0.94));
}

.empty-state-copy h4 {
  margin: 0 0 8px;
  font-size: 20px;
  color: var(--text-strong);
}

.empty-state-copy p {
  margin: 0;
  max-width: 520px;
  line-height: 1.7;
  color: var(--text-muted);
}

.policy-form .el-form {
  display: flex;
  flex-direction: column;
  gap: 14px;
}

.policy-shell {
  display: grid;
  grid-template-columns: 1fr;
  gap: 14px;
}

.policy-side .form-group {
  padding: 16px;
}

.policy-side {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 14px;
}

.policy-card-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  margin-bottom: 12px;
}

.policy-card-tip {
  display: inline-flex;
  align-items: center;
  padding: 5px 10px;
  border-radius: 999px;
  background: rgba(17, 17, 17, 0.05);
  color: var(--text-muted);
  font-size: 11px;
  font-weight: 700;
  letter-spacing: 0.08em;
  text-transform: uppercase;
}

.group-label {
  display: inline-block;
  margin-bottom: 0;
  font-size: 11px;
  font-weight: 700;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: var(--text-muted);
}

.form-group {
  min-height: 100%;
}

.switch-row {
  margin-top: 6px;
  padding-top: 12px;
  border-top: 1px solid rgba(17, 17, 17, 0.06);
}

.row-label {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.row-label span {
  font-weight: 700;
  color: var(--text-strong);
}

.form-footer-action {
  display: flex;
  justify-content: flex-start;
}

.maintenance-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 14px;
}

.m-card {
  display: flex;
  align-items: center;
  gap: 14px;
  min-height: 156px;
  padding: 16px;
}

.m-copy {
  flex: 1;
  min-width: 0;
}

.m-icon {
  width: 44px;
  height: 44px;
  display: flex;
  align-items: center;
  justify-content: center;
  border-radius: 14px;
  font-size: 18px;
  flex: 0 0 44px;
}

.m-title {
  margin: 0 0 8px;
  font-size: 16px;
  color: var(--text-strong);
}

.m-desc {
  margin: 0;
  line-height: 1.65;
  font-size: 13px;
}

.m-btn {
  align-self: flex-end;
}

.policy-form :deep(.el-form-item) {
  margin-bottom: 12px;
}

.policy-form :deep(.el-form-item:last-child) {
  margin-bottom: 0;
}

.policy-form :deep(.el-input-group__append) {
  border-left: 1px solid rgba(17, 17, 17, 0.06);
  background: rgba(245, 245, 245, 0.9);
}

.policy-form :deep(.el-input-group__append .el-button) {
  height: 36px;
  padding: 0 12px;
  border-radius: 12px !important;
}

.dialog-inner {
  padding-top: 8px;
}

.dialog-footer {
  display: flex;
  justify-content: flex-end;
  gap: 12px;
}

.plain-btn {
  border-radius: 10px;
  font-weight: 700;
}

@media (max-width: 1100px) {
  .webhook-grid,
  .maintenance-grid,
  .policy-side {
    grid-template-columns: 1fr;
  }
}

@media (max-width: 820px) {
  .tab-inner {
    padding: 18px;
  }

  .empty-state-card,
  .bento-footer,
  .switch-row,
  .m-card {
    flex-direction: column;
    align-items: flex-start;
  }

  .m-btn,
  .form-footer-action {
    width: 100%;
  }
}
</style>
