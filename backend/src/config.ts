/*
 * Centralized runtime configuration.
 *
 * Every value is read from the environment exactly once, on startup, into a
 * frozen object. Nothing else in the codebase should call `process.env`
 * directly — import `config` instead. This keeps env access auditable and
 * makes the full surface of tunables visible in one place.
 */

/** Read a required env var, failing fast on startup if it is missing. */
const required = (key: string): string => {
  const val = process.env[key]
  if (!val) throw new Error(`Missing required env var: ${key}`)
  return val
}

/** Read an integer env var, falling back to a default when unset. */
const int = (key: string, fallback: number): number => {
  const val = process.env[key]
  return val ? parseInt(val, 10) : fallback
}

export const config = {
  /* HTTP port. Тайник defaults to 3110 (redirects sits on 3100). */
  port: int('PORT', 3110),

  fiali: {
    /* Base URL of the fia.li public API — used for the `/me` auth lookup. */
    baseUrl: process.env['FIALI_BASE_URL'] ?? 'https://api.fia.li',
  },

  s2s: {
    /* Billing internal API, reached service-to-service for per-plan limits. */
    billingUrl: process.env['BILLING_URL'] ?? 'http://billing:3003',
    /* Shared HMAC secret for S2S signing. Empty = S2S lookups are skipped. */
    secret: process.env['INTERNAL_SECRET'] ?? '',
    /* This service's identity in the S2S signature and limits path. */
    serviceName: 'tainik' as const,
  },

  redis: {
    host: process.env['REDIS_HOST'] ?? 'redis',
    port: int('REDIS_PORT', 6379),
    password: process.env['REDIS_PASSWORD'],
    /* All keys namespaced — zero collision with other fia.li services. */
    keyPrefix: 'tainik:',
  },

  cors: {
    /* Comma-separated origins for multi-panel support. */
    origins: (process.env['ALLOWED_ORIGINS'] ?? 'https://panel.fia.li').split(','),
  },

  cache: {
    /* `/me` validation TTL — short enough to catch revoked sessions quickly. */
    authTtl: int('AUTH_CACHE_TTL', 30),
  },
} as const
