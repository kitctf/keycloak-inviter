import { type AboutMe, AboutMeSchema } from '@/lib/types.ts'
import { BACKEND_URL, fetchWithError } from '@/lib/fetching.ts'

export async function fetchAboutMe(): Promise<AboutMe | 'unauthorized'> {
  const response = await fetchWithError(
    `${BACKEND_URL}/about-me`,
    {
      credentials: 'include',
    },
    {
      extraSuccessStatus: [401],
    },
  )
  if (response.status === 401) {
    return 'unauthorized'
  }
  const data = await response.json()
  return AboutMeSchema.parse(data)
}

export async function fetchAddUser(payload: {
  email: string
  firstName?: string
  lastName?: string
}): Promise<'success' | 'unauthorized'> {
  const response = await fetchWithError(
    `${BACKEND_URL}/invite-user`,
    {
      credentials: 'include',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(payload),
    },
    { extraSuccessStatus: [401], hideError: true },
  )

  if (response.status === 200) {
    return 'success'
  }
  return 'unauthorized'
}

export async function fetchRegister(payload: {
  email: string
  username: string
}): Promise<'success'> {
  await fetchWithError(
    `${BACKEND_URL}/register`,
    {
      credentials: 'include',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(payload),
    },
    { extraSuccessStatus: [], hideError: true },
  )

  return 'success'
}
