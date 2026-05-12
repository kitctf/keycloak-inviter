import { createRouter, createWebHistory } from 'vue-router'
import MainOrLoginView from '@/views/MainOrLoginView.vue'
import RegisterView from '@/views/RegisterView.vue'

const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes: [
    {
      path: '/',
      name: 'home',
      component: MainOrLoginView,
      meta: {
        name: 'Home',
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
