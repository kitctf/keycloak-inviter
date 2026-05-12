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
      <a
        v-for="app in sortedApps"
        :key="app.name"
        :href="app.url"
        rel="nofollow noreferrer noopener"
        target="_blank"
      >
        <Card class="w-auto gap-2 justify-between py-4 px-3 group hover:bg-muted">
          <CardHeader class="px-1 flex items-center gap-3">
            <div class="aspect-square h-14">
              <div
                class="bg-muted group-hover:bg-background flex items-center justify-center rounded-2xl p-3 size-14"
              >
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
                <img
                  v-else-if="app.icon == 'vault'"
                  class="contain-content aspect-square"
                  src="/assets/vault.svg"
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
          <CardContent class="px-0">
            <span class="text-xs text-muted-foreground line-clamp-1 text-ellipsis">
              {{ app.description }}
            </span>
          </CardContent>
        </Card>
      </a>
    </CardContent>
  </Card>
</template>

<script setup lang="ts">
import type { AboutMe, AllowedApplication } from '@/lib/types.ts'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { LucideFlagTriangleRight, LucideUserPlus } from 'lucide-vue-next'
import { computed, toRefs } from 'vue'

const GROUP_PRIORITIES: Record<string, number> = {
  HUB: 3,
  gpnctf: 2,
  tools: 3,
  secrets: 4,
  management: 5,
}

const props = defineProps<{
  userInfo: AboutMe
  allowedApplications: AllowedApplication[]
}>()
const { userInfo, allowedApplications } = toRefs(props)

const sortedApps = computed(() => {
  return allowedApplications.value.slice().sort((a, b) => {
    const aPrio = GROUP_PRIORITIES[a.group] ?? 10
    const bPrio = GROUP_PRIORITIES[b.group] ?? 10
    if (aPrio != bPrio) {
      return aPrio < bPrio ? -1 : 1
    }
    return a.name.localeCompare(b.name)
  })
})

function toHost(url: string) {
  try {
    return new URL(url).host
  } catch {
    return url
  }
}
</script>
