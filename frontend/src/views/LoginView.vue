<template>
  <PageContainer>
    <Card>
      <CardHeader>
        <CardTitle>Unauthenticated</CardTitle>
        <CardDescription>Log in to keycloak inviter</CardDescription>
      </CardHeader>
      <CardContent v-if="fetching">
        <LucideLoaderCircle class="animate-spin" />
        Loading...
      </CardContent>
      <CardContent v-else>
        <a :href="BACKEND_URL + '/login'">
          <Button class="cursor-pointer">Log in</Button>
        </a>
      </CardContent>
    </Card>
  </PageContainer>
</template>

<script setup lang="ts">
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { BACKEND_URL } from '@/lib/fetching.ts'
import { Button } from '@/components/ui/button'
import { LucideLoaderCircle } from 'lucide-vue-next'
import PageContainer from '@/components/PageContainer.vue'
import { toRefs } from 'vue'

const props = defineProps<{
  fetching: boolean
}>()
const { fetching } = toRefs(props)
</script>
