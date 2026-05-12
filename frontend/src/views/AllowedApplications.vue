<template>
  <Card>
    <CardHeader>
      <CardTitle>
        Welcome, <span class="gradient-primary">{{ userInfo.userName }}</span>
      </CardTitle>
      <CardDescription> Where do you want to go next? </CardDescription>
    </CardHeader>
    <CardContent
      class="grid gap-3"
      style="grid-template-columns: repeat(auto-fit, minmax(min(280px, 100%), 1fr))"
    >
      <Card
        v-for="app in allowedApplications"
        :key="app.name"
        class="w-auto gap-2 justify-between py-4 px-3"
      >
        <CardHeader class="px-1 flex items-center gap-3">
          <div class="aspect-square h-14">
            <div class="bg-muted flex items-center justify-center rounded-2xl p-3 size-14">
              <img
                v-if="app.icon == 'kithub'"
                class="contain-content aspect-square"
                src="/assets/hub.png"
              />
              <img
                v-else-if="app.icon == 'hedgedoc'"
                class="contain-content aspect-square"
                src="/assets/hedgedoc.svg"
              />
              <img
                v-else-if="app.icon == 'grafana'"
                class="contain-content aspect-square"
                src="/assets/grafana.svg"
              />
              <img
                v-else-if="app.icon == 'chat'"
                class="contain-content aspect-square"
                src="/assets/chat.png"
              />
              <img
                v-else-if="app.icon == 'vaultwarden'"
                class="contain-content aspect-square"
                src="/assets/vaultwarden.svg"
              />
              <img
                v-else-if="app.icon == 'wiki'"
                class="contain-content aspect-square"
                src="/assets/wiki.svg"
              />
              <img
                v-else-if="app.icon == 'kubernetes'"
                class="contain-content aspect-square"
                src="/assets/kubernetes.svg"
              />
              <img
                v-else-if="app.icon == 'keycloak'"
                class="contain-content aspect-square"
                src="/assets/keycloak.svg"
              />
              <LucideUserPlus v-else-if="app.icon == 'inviter'" class="aspect-square" />
              <LucideFlagTriangleRight v-else class="aspect-square" />
            </div>
          </div>
          <div class="self-start min-w-0">
            <CardTitle class="mb-1"> {{ app.name }} </CardTitle>
            <CardDescription class="text-muted-foreground line-clamp-1 text-xs text-ellipsis">
              {{ toHost(app.url) }}
            </CardDescription>
          </div>
        </CardHeader>
        <CardContent class="px-1 justify-end flex">
          <a :href="app.url" rel="noopener nofollow" target="_blank">
            <Button size="sm" class="cursor-pointer">Launch <LucideExternalLink /></Button>
          </a>
        </CardContent>
      </Card>
    </CardContent>
  </Card>
</template>

<script setup lang="ts">
import type { AboutMe, AllowedApplication } from '@/lib/types.ts'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { LucideExternalLink, LucideFlagTriangleRight, LucideUserPlus } from 'lucide-vue-next'
import Button from '@/components/ui/button/Button.vue'
import { toRefs } from 'vue'

const props = defineProps<{
  userInfo: AboutMe
  allowedApplications: AllowedApplication[]
}>()
const { userInfo, allowedApplications } = toRefs(props)

function toHost(url: string) {
  try {
    return new URL(url).host
  } catch {
    return url
  }
}
</script>
