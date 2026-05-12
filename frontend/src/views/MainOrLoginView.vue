<template>
  <LoginView v-if="!userInfo" :fetching="fetchingLoginStatus" />
  <PageContainer v-else>
    <Tabs default-value="dashboard">
      <TabsList>
        <TabsTrigger value="dashboard"> Dashboard </TabsTrigger>
        <TabsTrigger value="invite" v-if="userInfo.canInvite"> Invite </TabsTrigger>
      </TabsList>
      <TabsContent value="dashboard">
        <AllowedApplications
          v-if="userInfo && allowedApps"
          :user-info="userInfo"
          :allowed-applications="allowedApps"
        />
      </TabsContent>
      <TabsContent value="invite" v-if="userInfo.canInvite">
        <InviteView :user-info="userInfo" />
      </TabsContent>
    </Tabs>
  </PageContainer>
</template>

<script setup lang="ts">
import { type AboutMe, type AllowedApplication } from '@/lib/types.ts'
import { fetchAboutMe, fetchApplications } from '@/lib/network.ts'
import { onMounted, ref } from 'vue'
import AllowedApplications from './AllowedApplications.vue'
import InviteView from '@/views/InviteView.vue'
import LoginView from '@/views/LoginView.vue'
import PageContainer from '@/components/PageContainer.vue'
import Tabs from '@/components/ui/tabs/Tabs.vue'
import TabsContent from '@/components/ui/tabs/TabsContent.vue'
import TabsList from '@/components/ui/tabs/TabsList.vue'
import TabsTrigger from '@/components/ui/tabs/TabsTrigger.vue'

const fetchingLoginStatus = ref<boolean>(true)
const userInfo = ref<AboutMe | null>(null)
const allowedApps = ref<AllowedApplication[] | null>(null)

onMounted(async () => {
  try {
    const aboutMe = await fetchAboutMe()
    if (aboutMe !== 'unauthorized') {
      userInfo.value = aboutMe
    } else {
      userInfo.value = null
    }

    const allowedApplications = await fetchApplications()
    if (allowedApplications != 'unauthorized') {
      allowedApps.value = allowedApplications
    }
  } finally {
    fetchingLoginStatus.value = false
  }
})
</script>
