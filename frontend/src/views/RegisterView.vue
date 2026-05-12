<template>
  <PageContainer>
    <Card>
      <CardHeader>
        <CardTitle>Register an account</CardTitle>
        <CardDescription>
          You can create an account on your own if you have a magic token
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form @submit="onSubmit" class="grid grid-cols-1 lg:grid-cols-2 gap-4 p-1">
          <FormField v-slot="{ componentField }" name="email">
            <FormItem>
              <FormLabel>E-mail<span class="text-destructive-foreground -ml-1">*</span></FormLabel>
              <FormControl>
                <Input type="text" placeholder="foo@kitctf.de" v-bind="componentField" />
              </FormControl>
              <FormDescription>The email address</FormDescription>
              <FormMessage />
            </FormItem>
          </FormField>
          <FormField v-slot="{ componentField }" name="username">
            <FormItem>
              <FormLabel>
                Username<span class="text-destructive-foreground -ml-1">*</span>
              </FormLabel>
              <FormControl>
                <Input type="text" placeholder="username" v-bind="componentField" />
              </FormControl>
              <FormDescription>What shall we call you?</FormDescription>
              <FormMessage />
            </FormItem>
          </FormField>
          <FormField v-slot="{ componentField }" name="token">
            <FormItem>
              <FormLabel>
                Magic token<span class="text-destructive-foreground -ml-1">*</span>
              </FormLabel>
              <FormControl>
                <Input type="text" placeholder="abcdefgh" v-bind="componentField" />
              </FormControl>
              <FormDescription>The magic token, pre filled from the url</FormDescription>
              <FormMessage />
            </FormItem>
          </FormField>
          <Button
            class="lg:col-span-2 w-fit cursor-pointer"
            type="submit"
            :disabled="sendingRequest"
          >
            <LucideLoaderCircle class="animate-spin" v-show="false" />
            Invite user
          </Button>
        </form>
        <Alert variant="destructive" v-if="error">
          <LucideAlertCircle />
          <AlertTitle>An error occurred</AlertTitle>
          <AlertDescription class="break-all whitespace-pre leading-4 font-mono">
            {{ error }}
          </AlertDescription>
        </Alert>
        <Alert class="mt-2" v-if="!error && justRegistered">
          <LucideCheckCircle2 />
          <AlertTitle>Success! An invitation has been sent.</AlertTitle>
          <AlertDescription>
            <ol>
              <li>Follow the steps in the E-Mail to create your account.</li>
              <li>
                Afterwards, check out the
                <RouterLink :to="{ path: '/' }" class="underline text-blue-400"
                  >dashboard</RouterLink
                >.
              </li>
            </ol>
          </AlertDescription>
        </Alert>
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
import { LucideAlertCircle, LucideCheckCircle2, LucideLoaderCircle } from 'lucide-vue-next'
import { computed, nextTick, onMounted, ref, watch } from 'vue'
import Alert from '@/components/ui/alert/Alert.vue'
import AlertDescription from '@/components/ui/alert/AlertDescription.vue'
import AlertTitle from '@/components/ui/alert/AlertTitle.vue'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import PageContainer from '@/components/PageContainer.vue'
import { fetchRegister } from '@/lib/network.ts'
import { toTypedSchema } from '@vee-validate/zod'
import { toast } from 'vue-sonner'
import { useForm } from 'vee-validate'
import { useRoute } from 'vue-router'
import { z } from 'zod'

const sendingRequest = ref(false)
const error = ref<string | null>(null)
const justRegistered = ref<boolean>(false)

const formSchema = toTypedSchema(
  z.object({
    email: z.string().email(),
    username: z.string().min(2).max(40),
    token: z.string(),
  }),
)
const form = useForm({
  validationSchema: formSchema,
})

const route = useRoute()
const urlToken = computed(() => route.params.token)

watch(
  urlToken,
  (token) => {
    if (token) {
      form.setFieldValue('token', token as string)
    }
  },
  { immediate: true },
)

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
  sendingRequest.value = true
  error.value = null
  justRegistered.value = false

  try {
    const response = await toast
      .promise(fetchRegister(values), {
        description: `Registering with ${values.email}`,
        loading: 'Registering...',
        success: () => 'Registered',
        error: (data: unknown) => {
          error.value = (data as Error).message || 'Unknown error'
          return 'Register failed'
        },
      })!
      .unwrap()

    if (response === 'success') {
      form.resetForm()
      error.value = null
      justRegistered.value = true
    }
  } finally {
    sendingRequest.value = false
  }
})
</script>
