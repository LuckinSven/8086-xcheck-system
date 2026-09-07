import { createRouter, createWebHistory } from 'vue-router'

import Dashboard from './views/Dashboard.vue'
import History from './views/History.vue'
import IpDiagnostics from './views/IpDiagnostics.vue'
import NewTask from './views/NewTask.vue'
import Settings from './views/Settings.vue'
import TaskProgress from './views/TaskProgress.vue'
import ThreatbookHistory from './views/ThreatbookHistory.vue'
import ThreatbookWorkspace from './views/ThreatbookWorkspace.vue'

export default createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', component: Dashboard },
    { path: '/new', component: NewTask },
    { path: '/history', component: History },
    { path: '/tasks/:id', component: TaskProgress },
    { path: '/tasks/:id/threatbook', component: ThreatbookWorkspace },
    { path: '/tasks/:id/ips/:ipId', component: IpDiagnostics },
    { path: '/threatbook-history', component: ThreatbookHistory },
    { path: '/settings', component: Settings },
  ],
})
