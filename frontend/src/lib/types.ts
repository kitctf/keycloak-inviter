import { z } from 'zod'

export const AboutMeSchema = z.object({
  sub: z.string(),
  userName: z.string(),
})

export const AllowedApplicationSchema = z.object({
  url: z.string(),
  name: z.string(),
  icon: z
    .enum([
      'chat',
      'grafana',
      'hedgedoc',
      'inviter',
      'keycloak',
      'kithub',
      'kubernetes',
      'vaultwarden',
      'wiki',
    ])
    .optional()
    .catch(undefined),
})

export type AboutMe = z.infer<typeof AboutMeSchema>
export type AllowedApplication = z.infer<typeof AllowedApplicationSchema>
