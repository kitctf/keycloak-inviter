<template>
  <a :href="BACKEND_URL + '/login'">
    <Button class="cursor-pointer">Do it! Lock in!</Button>
  </a>
</template>

<script setup lang="ts">
import { BACKEND_URL } from '@/lib/fetching.ts'
import { Button } from '@/components/ui/button'
</script>
