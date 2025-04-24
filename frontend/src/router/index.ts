import { createRouter, createWebHistory } from 'vue-router'
import InviteOrLoginView from '@/views/InviteOrLoginView.vue'

const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes: [
    {
      path: '/',
      name: 'invite',
      component: InviteOrLoginView,
      meta: {
        name: 'Invite',
      },
    },
  ],
})

export default router
