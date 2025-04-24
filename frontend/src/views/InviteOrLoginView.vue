<template>
  <LoginView v-if="!userInfo" :fetching="fetchingLoginStatus" />
  <InviteView v-else :user-info="userInfo" />
</template>

<script setup lang="ts">
import { onMounted, ref } from 'vue'
import type { AboutMe } from '@/lib/types.ts'
import InviteView from '@/views/InviteView.vue'
import LoginView from '@/views/LoginView.vue'
import { fetchAboutMe } from '@/lib/network.ts'

const fetchingLoginStatus = ref<boolean>(true)
const userInfo = ref<AboutMe | null>(null)

onMounted(async () => {
  try {
    const aboutMe = await fetchAboutMe()
    if (aboutMe !== 'unauthorized') {
      userInfo.value = aboutMe
    } else {
      userInfo.value = null
    }
  } finally {
    fetchingLoginStatus.value = false
  }
})
</script>
