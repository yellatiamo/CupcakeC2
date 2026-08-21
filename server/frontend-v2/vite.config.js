import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import path from 'path'
import AutoImport from 'unplugin-auto-import/vite'
import Components from 'unplugin-vue-components/vite'
import { ElementPlusResolver } from 'unplugin-vue-components/resolvers'

export default defineConfig({
    base: '/',
    plugins: [
        vue(),
        // 自动按需导入 Element Plus API（ElMessage, ElMessageBox 等）
        AutoImport({
            resolvers: [ElementPlusResolver()],
        }),
        // 自动按需导入 Element Plus 组件（el-button, el-table 等）
        Components({
            resolvers: [
                ElementPlusResolver(),
            ],
        }),
    ],
    resolve: {
        alias: {
            '@': path.resolve(__dirname, './src'),
        },
    },
    build: {
        // Embed path is server/web/dist (//go:embed web/dist/*). Keep ../dist as
        // intermediate; compile_server / build-frontend.ps1 sync into web/dist.
        outDir: '../dist',
        emptyOutDir: true,
        // 让 Rollup 把各主要库切成独立文件（并行加载 + 长效缓存）
        rollupOptions: {
            output: {
                manualChunks(id) {
                    // Vue 核心
                    if (id.includes('node_modules/vue/') || id.includes('node_modules/@vue/')) {
                        return 'vendor-vue'
                    }
                    // Element Plus 组件库（最大贡献者）
                    if (id.includes('node_modules/element-plus')) {
                        return 'vendor-element-plus'
                    }
                    // ECharts 图表库
                    if (id.includes('node_modules/echarts') || id.includes('node_modules/zrender')) {
                        return 'vendor-echarts'
                    }
                    // Vue-ECharts
                    if (id.includes('node_modules/vue-echarts') || id.includes('node_modules/@vue-echarts')) {
                        return 'vendor-vue-echarts'
                    }
                    // Monaco 编辑器（如有）
                    if (id.includes('node_modules/monaco-editor')) {
                        return 'vendor-monaco'
                    }
                    // Vue Router & Pinia 状态管理
                    if (id.includes('node_modules/vue-router') || id.includes('node_modules/pinia')) {
                        return 'vendor-router-store'
                    }
                    // xterm 终端
                    if (id.includes('node_modules/xterm') || id.includes('node_modules/@xterm')) {
                        return 'vendor-xterm'
                    }
                    // 其余第三方依赖统一聚合
                    if (id.includes('node_modules/')) {
                        return 'vendor-misc'
                    }
                },
                // 给 chunk 和 asset 增加 hash，确保浏览器缓存友好
                chunkFileNames: 'assets/js/[name]-[hash].js',
                entryFileNames: 'assets/js/[name]-[hash].js',
                assetFileNames: 'assets/[ext]/[name]-[hash].[ext]',
            },
        },
        // 单文件警告阈值调高到 800KB（原来 500KB）避免非必要警告
        chunkSizeWarningLimit: 800,
    }
})
