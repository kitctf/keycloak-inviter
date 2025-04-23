import { z } from 'zod'

export const AboutMeSchema = z.object({
  sub: z.string(),
  userName: z.string(),
})

export type AboutMe = z.infer<typeof AboutMeSchema>
