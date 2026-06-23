import { Elysia } from 'elysia'
import { redis, keys } from '../redis/client'
import { config } from '../config'

/*
 * Auth plugin — resolves the fia.li user behind a request.
 *
 * Тайник never manages its own sessions. It trusts the fia.li platform: the
 * panel forwards the user's credential (a Bearer token, or the `access_token`
 * cookie), and we validate it by calling fia.li `GET /me` with that same
 * token. If `/me` returns a user, the request is authenticated.
 *
 * Only the CREATE route uses this — reading and burning notes is public by
 * design (the secrecy lives in the URL-fragment key, not in an account).
 */

/**
 * Minimal shape we consume from fia.li `/me`. The real profile is larger;
 * we only need an identity to attribute notes and enforce per-user limits.
 */
export interface UserProfile {
  id: string
  email: string
  /* fia.li returns more fields — kept open so we don't fight the upstream shape. */
  [key: string]: unknown
}

/** fia.li wraps successful bodies as { status: 1, data: T }. */
interface FiaLiEnvelope<T> {
  status: number
  data: T
}

/** Hash the raw credential so we never store a live token as a Redis key. */
const hashCredential = async (input: string): Promise<string> => {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input))
  return Buffer.from(buf).toString('hex')
}

/**
 * Extract the bearer token from a request.
 *
 * Two transports, same token semantics:
 *   - `Authorization: Bearer <token>` (API clients)
 *   - `Cookie: access_token=<token>`  (browser panel)
 *
 * Returns `{ token, credentialRaw }` where `credentialRaw` is the full header
 * value used as the cache-key seed (so two transports never alias each other).
 */
const extractCredential = (
  request: Request,
): { token: string; credentialRaw: string } | null => {
  const authHeader = request.headers.get('Authorization')
  if (authHeader?.startsWith('Bearer ')) {
    return { token: authHeader.slice(7), credentialRaw: authHeader }
  }

  const cookieHeader = request.headers.get('Cookie')
  if (cookieHeader) {
    const match = cookieHeader.match(/access_token=([^;]+)/)
    const token = match?.[1]
    if (token) return { token, credentialRaw: cookieHeader }
  }

  return null
}

/** Call fia.li `/me` with the forwarded token. Returns the user or null. */
const fetchProfile = async (token: string): Promise<UserProfile | null> => {
  try {
    const res = await fetch(`${config.fiali.baseUrl}/me`, {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: 'application/json',
      },
      signal: AbortSignal.timeout(5_000),
    })

    if (!res.ok) return null

    const body = (await res.json()) as FiaLiEnvelope<UserProfile> | UserProfile
    /* Unwrap the standard { status, data } envelope; tolerate a raw body too. */
    const user = body && typeof body === 'object' && 'data' in body
      ? (body as FiaLiEnvelope<UserProfile>).data
      : (body as UserProfile)

    return user?.id ? user : null
  } catch (err) {
    console.error('[auth] /me lookup failed:', (err as Error).message)
    return null
  }
}

/** 401 carrier — handled by this plugin's scoped onError below. */
class AuthError extends Error {
  status: number
  constructor(message = 'Unauthorized') {
    super(message)
    this.status = 401
  }
}

/*
 * The plugin: a global `derive` that attaches `user` to the context.
 *
 * Flow:
 *   1. Extract the forwarded credential → 401 if absent.
 *   2. Serve from the short-lived Redis cache when warm (keyed by a hash of
 *      the credential), so a burst of requests is one `/me` call.
 *   3. Otherwise validate via `/me`, cache briefly, and attach the user.
 */
export const authPlugin = new Elysia({ name: 'auth' })
  .error({ AUTH_ERROR: AuthError })
  .onError({ as: 'global' }, ({ error, set }) => {
    if (error instanceof AuthError) {
      set.status = 401
      return { message: error.message }
    }
  })
  .derive({ as: 'global' }, async ({ request }) => {
    const cred = extractCredential(request)
    if (!cred) throw new AuthError()

    const cacheKey = keys.auth(await hashCredential(cred.credentialRaw))

    const cached = await redis.get(cacheKey)
    if (cached) {
      return { user: JSON.parse(cached) as UserProfile }
    }

    const user = await fetchProfile(cred.token)
    if (!user) throw new AuthError()

    await redis.set(cacheKey, JSON.stringify(user), 'EX', config.cache.authTtl)
    return { user }
  })
