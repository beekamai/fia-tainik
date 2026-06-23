import { createHmac } from 'crypto'
import { config } from '../config'

/**
 * Lightweight service-to-service (S2S) client for HMAC-signed requests to
 * fia.li internal APIs.
 *
 * The signing scheme matches @fia-li/core (internal-auth.ts):
 *   signature = HMAC-SHA256(`${timestamp}:${serviceName}`, secret) → base64url
 *
 * The billing service verifies the signature and the timestamp freshness, so
 * the three headers below are all that's required to authenticate as Тайник.
 */

const hmacSign = (data: string, secret: string): string =>
  createHmac('sha256', secret).update(data).digest('base64url')

const buildS2sHeaders = (): Record<string, string> => {
  const ts = String(Date.now())
  const { serviceName, secret } = config.s2s
  return {
    'X-Service-Name': serviceName,
    'X-Service-Timestamp': ts,
    'X-Service-Signature': hmacSign(`${ts}:${serviceName}`, secret),
  }
}

interface S2sResponse<T> {
  status: number
  data: T
}

/**
 * Fetch a user's service limits from the billing internal API:
 *   GET {billingUrl}/internal/user/:userId/services/:slug/limits
 *
 * Returns the limit map, or `null` when there is no subscription / the service
 * is not part of the user's plan / anything fails.
 *
 * This function NEVER throws — a billing outage must not block note creation.
 * Callers treat `null` as "use the safe FREE defaults" (see services/limits.ts).
 */
export const fetchUserServiceLimits = async (
  userId: string,
  slug: string,
): Promise<Record<string, number | boolean | string> | null> => {
  if (!config.s2s.secret) {
    console.warn('[s2s] INTERNAL_SECRET not configured — skipping billing lookup')
    return null
  }

  try {
    const url = `${config.s2s.billingUrl}/internal/user/${userId}/services/${encodeURIComponent(slug)}/limits`
    const res = await fetch(url, {
      method: 'GET',
      headers: {
        ...buildS2sHeaders(),
        Accept: 'application/json',
      },
      signal: AbortSignal.timeout(3_000),
    })

    if (!res.ok) return null

    const body = (await res.json()) as S2sResponse<Record<string, number | boolean | string> | null>
    return body.data ?? null
  } catch (err) {
    console.error('[s2s] billing limits fetch failed:', (err as Error).message)
    return null
  }
}
