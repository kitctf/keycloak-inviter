<template>
  <nav class="px-2 py-3 border-b border-border bg-background">
    <div class="container flex items-center justify-between max-w-7xl max-sm:px-0">
      <div class="flex md:space-x-6 flex-grow">
        <div class="flex items-center justify-center flex-shrink-0">
          <LucideUserPlus class="h-[24px] flex-shrink-0" />
          <span class="ml-2 font-semibold max-md:hidden">keycloak inviter</span>
        </div>
      </div>
    </div>
  </nav>
</template>

<script setup lang="ts">
import { LucideUserPlus } from 'lucide-vue-next'
</script>
