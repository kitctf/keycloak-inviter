<template>
  <Toaster :rich-colors="true" position="top-center" class="pointer-events-auto" />
  <NavBar :user-info="userInfo" />
  <RouterView v-slot="{ Component }">
    <component :is="Component" some-prop="value" :user-info="userInfo" />
  </RouterView>
</template>

<script setup lang="ts">
import 'vue-sonner/style.css'
import { onMounted, ref } from 'vue'
import type { AboutMe } from './lib/types'
import NavBar from '@/components/NavBar.vue'
import { Toaster } from '@/components/ui/sonner'
import { fetchAboutMe } from './lib/network'

const userInfo = ref<AboutMe | undefined>(undefined)

onMounted(async () => {
  const aboutMe = await fetchAboutMe()
  if (aboutMe !== 'unauthorized') {
    userInfo.value = aboutMe
  } else {
    userInfo.value = undefined
  }
})
</script>
