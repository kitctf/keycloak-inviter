<template>
  <PageContainer>
    <Card>
      <CardHeader>
        <CardTitle>Create an Account</CardTitle>
        <CardDescription>
          You can create an account on your own — if you have a magic token
        </CardDescription>
      </CardHeader>
      <CardContent v-auto-animate>
        <form @submit="onSubmit" class="grid grid-cols-1 lg:grid-cols-2 gap-4 p-1">
          <FormField v-slot="{ componentField }" name="email">
            <FormItem>
              <FormLabel>E-mail<span class="text-destructive-foreground -ml-1">*</span></FormLabel>
              <FormControl>
                <Input type="text" placeholder="mail@example.com" v-bind="componentField" />
              </FormControl>
              <FormDescription>Your email address</FormDescription>
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
            :disabled="
              sendingRequest || !(form.isFieldDirty('email') || form.isFieldDirty('username'))
            "
          >
            <LucideLoaderCircle class="animate-spin" v-show="false" />
            Create Account
          </Button>
        </form>
        <Alert variant="destructive" v-if="error">
          <LucideAlertCircle />
          <AlertTitle>An error occurred</AlertTitle>
          <AlertDescription class="break-all whitespace-pre leading-4 font-mono">
            {{ error }}
          </AlertDescription>
        </Alert>
        <Alert class="mt-2 bg-green-50/20 border-green-300" v-if="!error && justRegistered">
          <LucideCheckCircle2 />
          <AlertTitle>
            Success! An invitation has been sent to
            <span class="gradient-primary">{{ justRegistered.email }}</span>
          </AlertTitle>
          <AlertDescription>
            <ol class="list-inside list-['-_']">
              <li>
                Follow the steps in the E-Mail to create your account. It might take a few minutes
                to arrive.
              </li>
              <li>
                Afterwards, check out the
                <RouterLink :to="{ path: '/' }" class="underline text-blue-400 font-bold"
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
import { vAutoAnimate } from '@formkit/auto-animate'
import { z } from 'zod'

const sendingRequest = ref(false)
const error = ref<string | null>(null)
const justRegistered = ref<{ username: string; email: string } | null>(null)

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
  justRegistered.value = null
  const loadingToast = toast.loading('Registering...')

  try {
    const response = await fetchRegister(values)

    if (response === 'success') {
      error.value = null
      justRegistered.value = values
      form.resetForm({
        values: values,
      })
    }
  } catch (e) {
    if (e instanceof Error) {
      error.value = e.message || 'Unknown error'
    } else {
      error.value = 'Unknown error'
    }
  } finally {
    toast.dismiss(loadingToast)
    sendingRequest.value = false
  }
})
</script>
