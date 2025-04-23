import { toast } from 'vue-sonner'

export const BACKEND_URL = import.meta.env.VITE_BACKEND_URL

export class FetchError extends Error {
  readonly status: number

  constructor(message: string, status: number) {
    super(`(HTTP ${status}) ${message}`)
    this.status = status
  }
}

export async function fetchWithError(
  url: string,
  init?: RequestInit,
  extra?: {
    extraSuccessStatus: number[]
  },
): Promise<Response> {
  if (!url.startsWith('http')) {
    url = BACKEND_URL + (url.startsWith('/') ? '' : '/') + url
  }
  const response = await fetch(url, init)
  if (
    !response.ok &&
    !(extra?.extraSuccessStatus && extra.extraSuccessStatus.includes(response.status))
  ) {
    // TODO: Prettify WebErrors
    let text = await response.text().catch(() => 'unknown')
    try {
      const json = JSON.parse(text)
      text = json.message
    } catch {}

    const error = new FetchError(text, response.status)
    toast.error('Error during request', {
      description: 'The error was ' + error,
    })
    throw error
  }
  return response
}
