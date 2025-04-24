<template>
  <Toaster :rich-colors="true" position="top-center" class="pointer-events-auto" />
  <NavBar />
  <RouterView />
</template>

<script setup lang="ts">
import NavBar from '@/components/NavBar.vue'
import { Toaster } from '@/components/ui/sonner'
</script>
