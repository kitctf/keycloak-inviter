import { createRouter, createWebHistory } from 'vue-router'
import InviteOrLoginView from '@/views/InviteOrLoginView.vue'
import RegisterView from '@/views/RegisterView.vue'

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
    {
      path: '/register/:token?',
      name: 'register',
      component: RegisterView,
      meta: {
        name: 'Register',
      },
    },
  ],
})

export default router
