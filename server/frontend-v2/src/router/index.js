import { createRouter, createWebHashHistory } from 'vue-router'
import MainLayout from '../layout/MainLayout.vue'

const routes = [
  {
    path: '/',
    component: MainLayout,
    redirect: '/dashboard',
    children: [
      {
        path: 'dashboard',
        name: 'Dashboard',
        component: () => import('../views/Dashboard.vue'),
        meta: { title: 'Dashboard' }
      },
      {
        path: 'clients',
        name: 'Clients',
        component: () => import('../views/ClientManager.vue'),
        meta: { title: 'Clients' }
      },
      {
        path: 'listeners',
        name: 'Listeners',
        component: () => import('../views/ListenerManager.vue'),
        meta: { title: 'Listeners', requiresAdmin: true }
      },
      {
        path: 'tunnels',
        name: 'Tunnels',
        component: () => import('../views/server/TunnelManager.vue'),
        meta: { title: 'Tunnels' }
      },
      {
        path: 'generator',
        name: 'Generator',
        component: () => import('../views/PayloadGenerator.vue'),
        meta: { title: 'Generator', requiresAdmin: true }
      },
      {
        path: 'modules',
        name: 'Modules',
        component: () => import('../views/ModuleManager.vue'),
        meta: { title: 'Modules' }
      },
      {
        path: 'ad',
        name: 'AdCenter',
        component: () => import('../views/AdCenter.vue'),
        meta: { title: 'AdCenter' }
      },
      {
        path: 'plugins',
        name: 'Plugins',
        component: () => import('../views/DomainScanner.vue'),
        meta: { title: 'Plugins' }
      },
      {
        path: 'history',
        name: 'History',
        component: () => import('../views/History.vue'),
        meta: { title: 'History' }
      },
      {
        // KD-5: permanent redirect from misnamed /domain → /plugins
        path: 'domain',
        redirect: '/plugins'
      },
      {
        path: 'settings',
        name: 'Settings',
        component: () => import('../views/Settings.vue'),
        meta: { title: 'Settings', requiresAdmin: true }
      },
      {
        path: 'client/:id',
        name: 'ClientDetail',
        component: () => import('../views/ClientDetail.vue'),
        redirect: (to) => ({ name: 'ClientTerminals', params: { id: to.params.id } }),
        meta: { title: 'Client Detail' },
        children: [
          {
            path: 'terminals',
            name: 'ClientTerminals',
            component: () => import('../components/TerminalTabs.vue'),
            meta: { title: 'Terminal' }
          },
          {
            path: 'files',
            name: 'ClientFiles',
            component: () => import('../views/client/FileManager.vue'),
            meta: { title: 'Files' }
          },
          {
            path: 'tunnels',
            name: 'ClientTunnels',
            component: () => import('../views/client/TunnelManager.vue'),
            meta: { title: 'Client Tunnels' }
          },
          {
            path: 'processes',
            name: 'ClientProcesses',
            component: () => import('../views/client/ProcessManager.vue'),
            meta: { title: 'Processes' }
          },
          {
            path: 'plugins',
            name: 'ClientPlugins',
            component: () => import('../views/client/PluginManager.vue'),
            meta: { title: 'Client Plugins' }
          },
          {
            path: 'modules',
            name: 'ClientModules',
            component: () => import('../views/client/ModulePanel.vue'),
            meta: { title: 'Client Modules' }
          },
          {
            path: 'ad',
            name: 'ClientAd',
            component: () => import('../views/client/AdPanel.vue'),
            meta: { title: 'Client AD' },
            props: (route) => ({ clientId: route.params.id })
          }
        ]
      }
    ]
  },
  {
    path: '/login',
    name: 'Login',
    component: () => import('../views/Login.vue'),
    meta: { title: 'Login' }
  }
]

const router = createRouter({
  history: createWebHashHistory(),
  routes
})

function currentRole() {
  try {
    const u = JSON.parse(localStorage.getItem('cupcake_user') || '{}')
    return (u.role || 'operator').toLowerCase()
  } catch {
    return 'operator'
  }
}

function isAdminRole(role) {
  return role === 'admin' || role === 'administrator'
}

router.beforeEach((to, from, next) => {
  const token = localStorage.getItem('cupcake_token')
  if (to.name !== 'Login' && !token) {
    next({ name: 'Login' })
    return
  }
  if (to.name === 'Login' && token) {
    next({ name: 'Dashboard' })
    return
  }
  if (to.matched.some((r) => r.meta?.requiresAdmin) && !isAdminRole(currentRole())) {
    next({ name: 'Dashboard' })
    return
  }
  next()
})

export default router
