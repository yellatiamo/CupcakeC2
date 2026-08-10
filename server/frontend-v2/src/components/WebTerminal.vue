<script setup>
import { onMounted, onUnmounted, ref, nextTick } from 'vue'
import { Terminal } from '@xterm/xterm'
import { FitAddon } from '@xterm/addon-fit'
import '@xterm/xterm/css/xterm.css'
import { request } from '@/api'

const props = defineProps({
    socket: Object, 
    clientId: String,
    sessionId: {
        type: String,
        default: ''
    },
    allowPTY: {
        type: Boolean,
        default: false
    }
})

const terminalContainer = ref(null)
let term = null
let fitAddon = null
let ptySocket = null
let ptyTextBuffer = ''
let ptyMode = 'unknown'
let fallbackInputBuffer = ''
let fallbackHistoryIndex = -1
let fallbackBannerShown = false
let fallbackPrompt = '> '
let promptVisible = false
let lastPromptAt = 0
const fallbackHistory = []
const fallbackDoneToken = '__CUPCAKE_DONE__'

const historyBuffer = []
const pendingBuffer = []
const storageKey = () => `terminal_history_${props.clientId}`

const persistHistory = () => {
  try {
    localStorage.setItem(storageKey(), JSON.stringify(historyBuffer.slice(-1000)))
  } catch (_) {}
}

const restoreHistory = () => {
  try {
    const raw = localStorage.getItem(storageKey())
    if (raw) {
      const items = JSON.parse(raw)
      if (Array.isArray(items)) {
        items.forEach((line) => term && term.write(line))
      }
    }
  } catch (_) {}
}

const appendOutput = (content) => {
  if (!content) return
  const text = String(content).replace(/\r?\n/g, '\r\n')
  if (!term) {
    pendingBuffer.push(text)
    return
  }
  term.write(text)
  historyBuffer.push(text)
  persistHistory()
}

const flushPending = () => {
  if (!term || pendingBuffer.length === 0) return
  pendingBuffer.splice(0).forEach(chunk => term.write(chunk))
}

const handlePtyJsonMessage = (jsonStr) => {
  try {
    const msg = JSON.parse(jsonStr)
    if (msg && msg.type === 'PTY_MODE') {
      if (msg.content === 'fallback') {
        ptyMode = 'fallback'
        if (!fallbackBannerShown) {
          term.writeln('\x1b[2m[Line Mode] Enter 发送 | ↑↓ 历史 | Ctrl+L 清屏\x1b[0m')
          fallbackBannerShown = true
        }
      }
      return
    }
    if (msg && msg.type === 'PTY_DONE') {
      if (ptyMode !== 'yamux') {
        ptyMode = 'fallback'
        showPrompt()
      }
      return
    }
    if (msg && msg.type === 'TERM') {
      ptyMode = 'fallback'
      if (msg.content !== undefined && msg.content !== null) {
        writeFallbackOutput(String(msg.content))
      }
      return
    }
    if (msg && msg.type === 'JSON_DATA') {
      return
    }
    if (msg && msg.content !== undefined && msg.content !== null) {
      ptyMode = 'fallback'
      writeFallbackOutput(String(msg.content))
      return
    }
  } catch (_) {}
  term.write(jsonStr)
}

const consumePtyText = (chunk) => {
  if (!chunk) return
  ptyTextBuffer += String(chunk)
  const buffer = ptyTextBuffer
  let i = 0
  let start = -1
  let depth = 0
  let inString = false
  let escape = false
  let lastProcessed = 0

  while (i < buffer.length) {
    const ch = buffer[i]
    if (start === -1) {
      if (ch === '{' || ch === '[') {
        start = i
        depth = 0
      } else {
        i++
        continue
      }
    }

    if (inString) {
      if (escape) { escape = false }
      else if (ch === '\\') { escape = true }
      else if (ch === '"') { inString = false }
      i++
      continue
    }

    if (ch === '"') { inString = true; i++; continue }
    if (ch === '{' || ch === '[') { depth++ }
    else if (ch === '}' || ch === ']') {
      depth--
      if (depth === 0 && start !== -1) {
        const jsonStr = buffer.slice(start, i + 1)
        handlePtyJsonMessage(jsonStr)
        lastProcessed = i + 1
        start = -1
      }
    }
    i++
  }

  if (start !== -1 || depth > 0) {
    ptyTextBuffer = buffer.slice(start)
    return
  }

  const remaining = buffer.slice(lastProcessed)
  if (remaining) { term.write(remaining) }
  ptyTextBuffer = ''
}

const rememberFallbackCommand = (cmd) => {
  const trimmed = String(cmd || '').trim()
  if (!trimmed) { fallbackHistoryIndex = -1; return }
  if (fallbackHistory.length === 0 || fallbackHistory[fallbackHistory.length - 1] !== trimmed) {
    fallbackHistory.push(trimmed)
  }
  if (fallbackHistory.length > 100) { fallbackHistory.shift() }
  fallbackHistoryIndex = -1
}

const historyUp = () => {
  if (fallbackHistory.length === 0) return
  if (fallbackHistoryIndex === -1) { fallbackHistoryIndex = fallbackHistory.length - 1 }
  else if (fallbackHistoryIndex > 0) { fallbackHistoryIndex -= 1 }
  replaceFallbackLine(fallbackHistory[fallbackHistoryIndex])
}

const historyDown = () => {
  if (fallbackHistoryIndex === -1) return
  if (fallbackHistoryIndex < fallbackHistory.length - 1) {
    fallbackHistoryIndex += 1
    replaceFallbackLine(fallbackHistory[fallbackHistoryIndex])
    return
  }
  fallbackHistoryIndex = -1
  replaceFallbackLine('')
}

const showPrompt = () => {
  if (fallbackInputBuffer.length > 0) return
  const now = Date.now()
  if (promptVisible && now - lastPromptAt < 200) return
  term.write(fallbackPrompt)
  promptVisible = true
  lastPromptAt = now
}

const writeFallbackOutput = (content) => {
  if (!content) return
  promptVisible = false
  let text = String(content)
  if (fallbackDoneToken) {
    text = text.replace(new RegExp(fallbackDoneToken, 'g'), '')
  }
  text = text.replace(/@echo off\r?\n?/gi, '')
  text = text.replace(/echo off\r?\n?/gi, '')
  text = text.replace(/ECHO is off\.\r?\n?/gi, '')
  if (text) { term.write(text) }
}

let fallbackCursorIndex = 0

const replaceFallbackLine = (text) => {
  clearFallbackLine()
  fallbackInputBuffer = text
  fallbackCursorIndex = text.length
  if (text) { term.write(text) }
}

const clearFallbackLine = () => {
  term.write('\r\x1b[K')
  term.write(fallbackPrompt)
  fallbackInputBuffer = ''
  fallbackCursorIndex = 0
}

const handleFallbackInput = (data) => {
  if (!data) return
  const text = String(data)

  if (text === '\x1b[A') { historyUp(); return }
  if (text === '\x1b[B') { historyDown(); return }
  if (text === '\x1b[C') {
    if (fallbackCursorIndex < fallbackInputBuffer.length) { fallbackCursorIndex++; term.write('\x1b[C') }
    return
  }
  if (text === '\x1b[D') {
    if (fallbackCursorIndex > 0) { fallbackCursorIndex--; term.write('\x1b[D') }
    return
  }
  if (text.startsWith('\x1b')) return

  for (const ch of text) {
    if (ch === '\x15') { clearFallbackLine(); continue }
    if (ch === '\x0c') {
      term.clear()
      term.write('\r' + fallbackPrompt + fallbackInputBuffer)
      if (fallbackInputBuffer.length > fallbackCursorIndex) {
        term.write('\x1b[' + (fallbackInputBuffer.length - fallbackCursorIndex) + 'D')
      }
      continue
    }
    if (ch === '\x03') { replaceFallbackLine(''); term.write('^C\r\n' + fallbackPrompt); continue }
    if (ch === '\r' || ch === '\n') {
      term.write('\r\n')
      if (ptySocket && ptySocket.readyState === WebSocket.OPEN) {
        rememberFallbackCommand(fallbackInputBuffer)
        ptySocket.send(fallbackInputBuffer + '\r\n')
      }
      fallbackInputBuffer = ''
      fallbackCursorIndex = 0
      continue
    }
    if (ch === '\x7f' || ch === '\b') {
      if (fallbackCursorIndex > 0) {
        const before = fallbackInputBuffer.slice(0, fallbackCursorIndex - 1)
        const after = fallbackInputBuffer.slice(fallbackCursorIndex)
        fallbackInputBuffer = before + after
        fallbackCursorIndex--
        term.write('\b\x1b[K' + after)
        if (after.length > 0) { term.write('\x1b[' + after.length + 'D') }
      }
      if (fallbackHistoryIndex !== -1) { fallbackHistoryIndex = -1 }
      continue
    }

    const before = fallbackInputBuffer.slice(0, fallbackCursorIndex)
    const after = fallbackInputBuffer.slice(fallbackCursorIndex)
    fallbackInputBuffer = before + ch + after
    fallbackCursorIndex++
    term.write(ch + after)
    if (after.length > 0) { term.write('\x1b[' + after.length + 'D') }
    promptVisible = false
    if (fallbackHistoryIndex !== -1) { fallbackHistoryIndex = -1 }
  }
}

const initPTY = async () => {
  const protocol = window.location.protocol === 'https:' ? 'wss' : 'ws'
  let ticket = ''
  try {
    // Short-lived upgrade ticket (session bearer stays in Authorization header only)
    const res = await request.post('/api/auth/ws-ticket', { purpose: 'pty' })
    ticket = res?.data?.ticket || ''
  } catch (_) {
    ticket = ''
  }
  if (!ticket) {
    term.writeln('\r\n\x1b[31m[!] Failed to mint PTY upgrade ticket (login required).\x1b[0m')
    return
  }
  const wsUrl = `${protocol}://${window.location.host}/api/pty/${props.clientId}?session=${encodeURIComponent(props.sessionId || '')}&ticket=${encodeURIComponent(ticket)}`

  ptySocket = new WebSocket(wsUrl)
  ptySocket.binaryType = 'arraybuffer'

  ptySocket.onopen = () => {
    term.writeln('\x1b[32m[+] Interactive PTY Connected.\x1b[0m')
    term.writeln('\x1b[2m[Pipe shell] 本地回显已开启；回车执行命令\x1b[0m')
    term.focus()
  }

  ptySocket.onmessage = (event) => {
    if (event.data instanceof ArrayBuffer) {
      const bytes = new Uint8Array(event.data)
      const textPreview = new TextDecoder('utf-8').decode(bytes)

      const fallbackMagic = '{"type": "PTY_MODE", "content": "fallback"}'
      if (textPreview.includes(fallbackMagic)) {
        ptyMode = 'fallback'
        if (!fallbackBannerShown) {
          term.writeln('\x1b[2m[Line Mode] Enter 发送 | ↑↓ 历史 | Ctrl+L 清屏\x1b[0m')
          fallbackBannerShown = true
        }
        const cleanText = textPreview.replace(fallbackMagic, '')
        writeFallbackOutput(cleanText)
        return
      }

      if (ptyMode === 'fallback') {
        writeFallbackOutput(textPreview)
        return
      }

      ptyMode = 'yamux'
      term.write(bytes)
      return
    }

    if (event.data instanceof Blob) {
      event.data.text().then((text) => consumePtyText(text))
      return
    }
    consumePtyText(event.data)
  }

  ptySocket.onclose = () => {
    term.writeln('\r\n\x1b[31m[!] PTY Session Closed.\x1b[0m')
  }

  ptySocket.onerror = () => {
    term.writeln('\r\n\x1b[31m[!] PTY Connection Error.\x1b[0m')
  }

  term.onData((data) => {
    if (!ptySocket || ptySocket.readyState !== WebSocket.OPEN) return
    if (ptyMode === 'fallback') {
      handleFallbackInput(data)
      return
    }
    // Yamux pipe-shell: cmd.exe does not echo keystrokes to stdout.
    // Local echo so the user can see typing; remote still receives raw input.
    for (let i = 0; i < data.length; i++) {
      const ch = data[i]
      if (ch === '\r') {
        term.write('\r\n')
      } else if (ch === '\u007f' || ch === '\b') {
        term.write('\b \b')
      } else if (ch === '\x03') {
        term.write('^C')
      } else if (ch === '\t' || ch >= ' ') {
        term.write(ch)
      }
      // ignore other control codes for local display
    }
    ptySocket.send(data)
  })
}

const initTerminal = () => {
  term = new Terminal({
    cursorBlink: true,
    cursorStyle: 'bar',
    fontSize: 13,
    fontFamily: '"JetBrains Mono", "Cascadia Code", "Fira Code", "Consolas", monospace',
    fontWeight: '400',
    fontWeightBold: '600',
    letterSpacing: 0,
    lineHeight: 1.35,
    allowTransparency: true,
    scrollback: 10000,
    theme: {
      background: '#0d0d0d',
      foreground: '#d4d4d4',
      cursor: '#f0f0f0',
      cursorAccent: '#0d0d0d',
      selectionBackground: '#ffffff30',
      black: '#1a1a1a',
      red: '#f87171',
      green: '#4ade80',
      yellow: '#fbbf24',
      blue: '#60a5fa',
      magenta: '#c084fc',
      cyan: '#22d3ee',
      white: '#e5e5e5',
      brightBlack: '#525252',
      brightRed: '#fca5a5',
      brightGreen: '#86efac',
      brightYellow: '#fde68a',
      brightBlue: '#93c5fd',
      brightMagenta: '#d8b4fe',
      brightCyan: '#67e8f9',
      brightWhite: '#ffffff',
    }
  })
  
  fitAddon = new FitAddon()
  term.loadAddon(fitAddon)
  term.open(terminalContainer.value)
  fitAddon.fit()
  
  if (props.allowPTY) {
    initPTY()
  } else {
    restoreHistory()
    if (!localStorage.getItem(storageKey())) {
      term.writeln('\x1b[2m[System] Terminal Ready.\x1b[0m')
    }
  }

  flushPending()
}

const handleSocketMessage = (event) => {
  if (props.allowPTY) return
  if (!event || !event.data) return

  let packetType = 'TERM'
  let content = event.data

  if (typeof content === 'string') {
    try {
      const parsed = JSON.parse(content)
      if (parsed && parsed.type) {
        packetType = parsed.type
        content = parsed.content ?? ''
      }
    } catch (_) {}
  }

  if (packetType !== 'TERM') return

  if (content instanceof ArrayBuffer) {
    appendOutput(new TextDecoder().decode(new Uint8Array(content)))
  } else {
    appendOutput(content)
  }
}

const clearHistory = () => {
  historyBuffer.length = 0
  try { localStorage.removeItem(storageKey()) } catch (_) {}
}

defineExpose({ handleSocketMessage, clearHistory })

onMounted(() => {
  initTerminal()
  window.addEventListener('resize', () => fitAddon && fitAddon.fit())
})

onUnmounted(() => {
  if (ptySocket) ptySocket.close()
  if (term) term.dispose()
})
</script>

<template>
  <div class="terminal-wrapper">
    <div ref="terminalContainer" class="terminal-container"></div>
  </div>
</template>

<style scoped>
.terminal-wrapper {
  width: 100%;
  height: 100%;
  background: #0d0d0d;
  padding: 8px;
  box-sizing: border-box;
}

.terminal-container {
  width: 100%;
  height: 100%;
}

:deep(.xterm-viewport) {
  scrollbar-width: thin;
  scrollbar-color: #333 transparent;
}

:deep(.xterm-viewport::-webkit-scrollbar) {
  width: 6px;
}

:deep(.xterm-viewport::-webkit-scrollbar-track) {
  background: transparent;
}

:deep(.xterm-viewport::-webkit-scrollbar-thumb) {
  background: #333;
  border-radius: 3px;
}

:deep(.xterm-viewport::-webkit-scrollbar-thumb:hover) {
  background: #555;
}
</style>
