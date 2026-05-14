<template>
  <nav class="px-2 py-3 border-b border-border bg-background flex">
    <div class="container flex items-center justify-between max-w-7xl max-sm:px-0" v-auto-animate>
      <div class="flex md:space-x-6 grow">
        <RouterLink
          class="flex items-center justify-center shrink-0"
          :to="{ path: userInfo ? '/' : undefined }"
        >
          <LucideLandPlot class="h-6 shrink-0" />
          <span class="ml-2 font-semibold max-md:hidden">Portal</span>
        </RouterLink>
      </div>
      <DarkModeToggle :user-info="userInfo" class="mr-2" />
      <div v-if="userInfo">
        <DropdownMenu>
          <DropdownMenuTrigger as-child>
            <div>
              <Button variant="outline" size="icon" class="cursor-pointer">
                <LucideUser />
              </Button>
            </div>
          </DropdownMenuTrigger>
          <DropdownMenuContent>
            <DropdownMenuLabel class="flex flex-col space-y-1">
              {{ userInfo.userName }}
            </DropdownMenuLabel>
            <DropdownMenuSeparator />
            <DropdownMenuItem class="cursor-pointer" @click="doLogout">
              Logout
              <span class="grow" />
              <LucideLogOut />
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            <a href="https://github.com/kitctf/keycloak-inviter" target="_blank" rel="noopener">
              <DropdownMenuItem class="cursor-pointer">
                GitHub
                <span class="grow" />
                <LucideExternalLink />
              </DropdownMenuItem>
            </a>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
    </div>
  </nav>
</template>

<script setup lang="ts">
import { LucideExternalLink, LucideLandPlot, LucideLogOut, LucideUser } from 'lucide-vue-next'
import type { AboutMe } from '@/lib/types'
import { BACKEND_URL } from '@/lib/fetching'
import Button from './ui/button/Button.vue'
import DarkModeToggle from './DarkModeToggle.vue'
import DropdownMenu from './ui/dropdown-menu/DropdownMenu.vue'
import DropdownMenuContent from './ui/dropdown-menu/DropdownMenuContent.vue'
import DropdownMenuItem from './ui/dropdown-menu/DropdownMenuItem.vue'
import DropdownMenuLabel from './ui/dropdown-menu/DropdownMenuLabel.vue'
import DropdownMenuSeparator from './ui/dropdown-menu/DropdownMenuSeparator.vue'
import DropdownMenuTrigger from './ui/dropdown-menu/DropdownMenuTrigger.vue'
import { toRefs } from 'vue'
import { vAutoAnimate } from '@formkit/auto-animate'

const props = defineProps<{
  userInfo?: AboutMe
}>()
const { userInfo } = toRefs(props)

function doLogout() {
  const form = document.createElement('form')
  form.action = `${BACKEND_URL}/logout`
  form.method = 'POST'
  document.body.appendChild(form)
  form.submit()
}
</script>
