<template>
  <PageContainer>
    <Card>
      <CardHeader>
        <CardTitle>
          Hey <span class="gradient-primary">{{ userInfo.userName }}</span
          >, invite a user
        </CardTitle>
        <CardDescription>You apparently have the power</CardDescription>
      </CardHeader>
      <CardContent>
        <form @submit="onSubmit" class="grid grid-cols-1 lg:grid-cols-2 gap-4 p-1">
          <FormField v-slot="{ componentField }" name="email">
            <FormItem class="col-span-2">
              <FormLabel>E-mail<span class="text-destructive-foreground -ml-1">*</span></FormLabel>
              <FormControl>
                <Input type="text" placeholder="foo@kitctf.de" v-bind="componentField" />
              </FormControl>
              <FormDescription>The email address</FormDescription>
              <FormMessage />
            </FormItem>
          </FormField>
          <FormField v-slot="{ componentField }" name="firstName">
            <FormItem>
              <FormLabel>First name</FormLabel>
              <FormControl>
                <Input type="text" placeholder="Max" v-bind="componentField" />
              </FormControl>
              <FormDescription>The first name of the person</FormDescription>
              <FormMessage />
            </FormItem>
          </FormField>
          <FormField v-slot="{ componentField }" name="lastName">
            <FormItem>
              <FormLabel>Last name</FormLabel>
              <FormControl>
                <Input type="text" placeholder="Musterfrau" v-bind="componentField" />
              </FormControl>
              <FormDescription>The last name of the person</FormDescription>
              <FormMessage />
            </FormItem>
          </FormField>
          <Button class="w-fit cursor-pointer" type="submit" :disabled="sendingInvite">
            <LucideLoaderCircle class="animate-spin" v-show="false" />
            Invite user
          </Button>
        </form>
        <div
          v-if="error"
          class="bg-accent rounded-lg my-2 p-2 text-destructive-foreground whitespace-pre break-all"
        >
          {{ error }}
        </div>
      </CardContent>
    </Card>
  </PageContainer>
</template>

<script setup lang="ts">
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import {
  FormControl,
  FormDescription,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from '@/components/ui/form'
import { nextTick, onMounted, ref, toRefs } from 'vue'
import type { AboutMe } from '@/lib/types.ts'
import { BACKEND_URL } from '@/lib/fetching.ts'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { LucideLoaderCircle } from 'lucide-vue-next'
import PageContainer from '@/components/PageContainer.vue'
import { fetchAddUser } from '@/lib/network.ts'
import { toTypedSchema } from '@vee-validate/zod'
import { toast } from 'vue-sonner'
import { useForm } from 'vee-validate'
import { z } from 'zod'

const sendingInvite = ref(false)
const error = ref<string | null>(null)

const props = defineProps<{
  userInfo: AboutMe
}>()
const { userInfo } = toRefs(props)

const formSchema = toTypedSchema(
  z.object({
    email: z.string().email(),
    firstName: z.string().min(2).max(60).optional(),
    lastName: z.string().min(2).max(60).optional(),
  }),
)
const form = useForm({
  validationSchema: formSchema,
})

onMounted(() => {
  const stored = sessionStorage.getItem('user')
  if (!stored) {
    return
  }
  nextTick(() => {
    toast.info('Restoring form data from local state')
    form.resetForm({
      values: JSON.parse(stored),
    })
  })
})

const onSubmit = form.handleSubmit(async (values) => {
  sendingInvite.value = true
  error.value = null

  try {
    sessionStorage.setItem('user', JSON.stringify(values))
    const response = await toast
      .promise(fetchAddUser(values), {
        description: `Inviting user ${values.email}`,
        loading: 'Inviting user...',
        success: () => 'User invited',
        error: (data: unknown) => {
          error.value = (data as Error).message || 'Unknown error'
          return 'Invite failed'
        },
      })!
      .unwrap()

    if (response === 'success') {
      form.resetForm()
      sessionStorage.removeItem('user')
      error.value = null
      return
    }
    window.location.href = `${BACKEND_URL}/login`
  } finally {
    sendingInvite.value = false
  }
})
</script>
