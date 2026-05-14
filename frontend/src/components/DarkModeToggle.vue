<template>
  <Button variant="outline" @click="next()" size="icon">
    <LucideMoon
      class="h-[1.2rem] w-[1.2rem] transition-all"
      :class="[mode == 'dark' ? 'scale-100' : 'scale-0']"
    />
    <LucideSun
      class="absolute h-[1.2rem] w-[1.2rem] transition-all"
      :class="[mode == 'light' ? 'scale-100' : 'scale-0']"
    />
    <LucideLaptopMinimal
      class="absolute h-[1.2rem] w-[1.2rem] transition-all dark:rotate-0"
      :class="[mode == 'auto' ? 'scale-100' : 'scale-0']"
    />
    <img
      src="/assets/chris.png"
      alt="Chrisliebaer theme"
      class="absolute h-[1.2rem] w-[1.2rem] transition-all dark:rotate-0"
      :class="[mode == 'chris' ? 'scale-100' : 'scale-0']"
    />
    <span class="sr-only">Toggle theme</span>
  </Button>
</template>

<script setup lang="ts">
import { LucideLaptopMinimal, LucideMoon, LucideSun } from 'lucide-vue-next'
import { toRefs, watch, watchEffect } from 'vue'
import { useColorMode, useCycleList } from '@vueuse/core'
import type { AboutMe } from '@/lib/types'
import { Button } from '@/components/ui/button'

const props = defineProps<{
  userInfo?: AboutMe
}>()
const { userInfo } = toRefs(props)

const mode = useColorMode({
  emitAuto: true,
  disableTransition: false,
  modes: {
    chris: 'chris',
  },
})

watch(userInfo, (val) => {
  if (!val) {
    return
  }
  const subs = ['88195218-4822-428e-a9e5-a9dca76764bb', '7dead6f1-4e2d-4702-820f-443bd022b31e']
  if (subs.includes(val.sub) && Math.random() <= 0.02) {
    mode.value = 'chris'
  }
})

const { state, next } = useCycleList(['auto', 'light', 'dark', 'chris'] as const, {
  initialValue: mode,
})

watchEffect(() => (mode.value = state.value))
</script>
