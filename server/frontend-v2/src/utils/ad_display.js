/** AD 任务展示：OP/状态中文、错误码与摘要截断、详情格式化 */

export const AD_OP_LABELS = {
  ad_ping: '连通探测',
  ping: '连通探测',
  ad_discover: '域/DC 发现',
  ad_ldap_query: 'LDAP 查询',
  ad_enum_users: '用户枚举',
  ad_enum_groups: '组枚举',
  ad_enum_privileged_groups: '特权组快照',
  ad_enum_computers: '计算机枚举',
  ad_enum_spns: 'SPN 枚举',
  ad_enum_trusts: '信任关系',
  ad_password_policy: '密码策略',
  ad_enum_delegation: '委派发现',
  ad_enum_gpo: 'GPO 线索',
  ad_collect_sessions: '会话采集',
  kerberoast: 'Kerberoast',
  asrep_roast: 'AS-REP Roast',
  dcsync: 'DCSync',
  ad_check_replication_rights: '复制权限探测',
  ad_graph_collect: '图采集',
  ad_acl_collect: 'ACL 聚焦',
  ad_artifact_wipe: '产物清理'
}

export const AD_STATUS_LABELS = {
  pending: '等待中',
  running: '执行中',
  collecting_artifact: '收集产物',
  completed: '已完成',
  success: '已完成',
  ok: '已完成',
  failed: '失败',
  error: '失败',
  wiped: '已清理',
  cancelled: '已取消',
  timeout: '超时'
}

export const AD_ERROR_LABELS = {
  not_domain_joined: '未加入域',
  domain_unavailable: '域不可用',
  ldap_error: 'LDAP 错误',
  ldap_bind_failed: 'LDAP 绑定失败',
  access_denied: '访问被拒绝',
  insufficient_privileges: '权限不足',
  timeout: '超时',
  not_implemented: '尚未实现',
  feature_disabled: '功能已关闭',
  module_required: '需要 ad 模块',
  module_not_loaded: '模块未加载',
  worker_failed: 'Worker 失败',
  worker_timeout: 'Worker 超时',
  artifact_missing: '产物缺失',
  unsupported_platform: '平台不支持',
  policy_denied: '策略拒绝',
  confirm_required: '需要确认',
  agent_offline: '主机离线',
  invalid_params: '参数无效',
  unknown: '未知错误'
}

export const AD_STATUS_TAG = {
  pending: 'info',
  running: 'warning',
  collecting_artifact: 'warning',
  completed: 'success',
  success: 'success',
  ok: 'success',
  failed: 'danger',
  error: 'danger',
  wiped: 'info',
  cancelled: 'info',
  timeout: 'danger'
}

/** OP 中文名；可传入 capabilities 覆盖 label */
export function formatOpName(op, capabilities = []) {
  const key = String(op || '').trim()
  if (!key) return '—'
  const fromCap = (capabilities || []).find((c) => c.op === key || c.op === `ad_${key}`)
  if (fromCap?.label) return fromCap.label
  if (AD_OP_LABELS[key]) return AD_OP_LABELS[key]
  // ping stored as "ping"
  if (AD_OP_LABELS[`ad_${key}`]) return AD_OP_LABELS[`ad_${key}`]
  return key
}

export function formatStatusName(status) {
  const key = String(status || '').trim().toLowerCase()
  if (!key) return '—'
  return AD_STATUS_LABELS[key] || status
}

export function statusTagType(status) {
  const key = String(status || '').trim().toLowerCase()
  return AD_STATUS_TAG[key] || 'info'
}

export function formatErrorName(code) {
  const key = String(code || '').trim()
  if (!key) return ''
  const lower = key.toLowerCase()
  if (AD_ERROR_LABELS[lower]) return AD_ERROR_LABELS[lower]
  return key
}

/** 截断展示；ellipsis 在末尾 */
export function truncateText(text, max = 48) {
  const s = String(text ?? '').replace(/\s+/g, ' ').trim()
  if (!s) return '—'
  if (s.length <= max) return s
  return `${s.slice(0, max)}…`
}

/** 表格用：错误码短展示（中文优先，再截断） */
export function errorSnippet(code, max = 28) {
  const name = formatErrorName(code)
  if (!name) return '—'
  return truncateText(name, max)
}

/** 从 summary_json 抽一行可读摘要 */
export function summarySnippet(summaryJson, max = 56) {
  if (summaryJson == null || summaryJson === '') return '—'
  let obj = summaryJson
  if (typeof summaryJson === 'string') {
    const t = summaryJson.trim()
    if (!t) return '—'
    if (t === 'pong' || t === 'ok') return t
    try {
      obj = JSON.parse(t)
    } catch {
      return truncateText(t, max)
    }
  }
  if (typeof obj !== 'object' || obj === null) {
    return truncateText(String(obj), max)
  }
  const parts = []
  if (obj.domain) parts.push(`域 ${obj.domain}`)
  if (obj.kind) parts.push(String(obj.kind))
  if (obj.hash_count != null) parts.push(`hash ${obj.hash_count}`)
  if (obj.node_count != null) parts.push(`节点 ${obj.node_count}`)
  if (obj.edge_count != null) parts.push(`边 ${obj.edge_count}`)
  if (obj.count != null) parts.push(`共 ${obj.count}`)
  if (obj.artifact) parts.push('有产物')
  if (obj.format) parts.push(String(obj.format))
  if (obj.error || obj.message) parts.push(String(obj.error || obj.message))
  if (obj.log_redacted) parts.push('已脱敏')
  if (!parts.length) {
    try {
      return truncateText(JSON.stringify(obj), max)
    } catch {
      return '—'
    }
  }
  return truncateText(parts.join(' · '), max)
}

/** 详情弹窗：美化 JSON 文本 */
export function prettyJson(value) {
  if (value == null || value === '') return ''
  if (typeof value === 'object') {
    try {
      return JSON.stringify(value, null, 2)
    } catch {
      return String(value)
    }
  }
  const s = String(value).trim()
  if (!s) return ''
  try {
    return JSON.stringify(JSON.parse(s), null, 2)
  } catch {
    return s
  }
}
