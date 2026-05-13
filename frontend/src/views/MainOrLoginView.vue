<template>
  <LoginView v-if="!userInfo" :fetching="fetchingLoginStatus" />
  <PageContainer v-else>
    <AllowedApplications
      v-if="userInfo && allowedApps && !userInfo.canInvite"
      :user-info="userInfo"
      :allowed-applications="allowedApps"
    />
    <Tabs default-value="dashboard" v-if="userInfo.canInvite">
      <TabsList>
        <TabsTrigger value="dashboard"> Dashboard </TabsTrigger>
        <TabsTrigger value="invite"> Invite </TabsTrigger>
      </TabsList>
      <TabsContent value="dashboard">
        <AllowedApplications
          v-if="userInfo && allowedApps"
          :user-info="userInfo"
          :allowed-applications="allowedApps"
        />
      </TabsContent>
      <TabsContent value="invite">
        <InviteView :user-info="userInfo" />
      </TabsContent>
    </Tabs>
  </PageContainer>
</template>

<script setup lang="ts">
import { type AboutMe, type AllowedApplication } from '@/lib/types.ts'
import { onMounted, ref, toRefs } from 'vue'
import AllowedApplications from './AllowedApplications.vue'
import InviteView from '@/views/InviteView.vue'
import LoginView from '@/views/LoginView.vue'
import PageContainer from '@/components/PageContainer.vue'
import Tabs from '@/components/ui/tabs/Tabs.vue'
import TabsContent from '@/components/ui/tabs/TabsContent.vue'
import TabsList from '@/components/ui/tabs/TabsList.vue'
import TabsTrigger from '@/components/ui/tabs/TabsTrigger.vue'
import { fetchApplications } from '@/lib/network.ts'

const fetchingLoginStatus = ref<boolean>(true)
const allowedApps = ref<AllowedApplication[] | null>(null)

const props = defineProps<{
  userInfo: AboutMe
}>()
const { userInfo } = toRefs(props)

onMounted(async () => {
  try {
    const allowedApplications = await fetchApplications()
    if (allowedApplications != 'unauthorized') {
      allowedApps.value = allowedApplications
    }
  } finally {
    fetchingLoginStatus.value = false
  }
})
</script>
