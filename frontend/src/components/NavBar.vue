<template>
  <nav class="px-2 py-3 border-b border-border bg-background">
    <div class="container flex items-center justify-between max-w-7xl max-sm:px-0">
      <div class="flex md:space-x-6 grow">
        <div class="flex items-center justify-center shrink-0">
          <LucideLandPlot class="h-6 shrink-0" />
          <span class="ml-2 font-semibold max-md:hidden">Dashboard</span>
        </div>
      </div>
    </div>
  </nav>
</template>

<script setup lang="ts">
import { LucideLandPlot } from 'lucide-vue-next'
</script>
