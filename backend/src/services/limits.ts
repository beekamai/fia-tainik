import { redis, keys } from '../redis/client'
import { fetchUserServiceLimits } from './s2s'
import { HttpError } from '../errors'

/*
 * Per-plan limit enforcement.
 *
 * Limits come from the user's fia.li subscription, fetched over S2S from the
 * billing service. When billing is unreachable or the user has no plan entry
 * for Тайник, we fall back to the conservative FREE defaults below — the
 * service stays available, it just behaves as the free tier.
 *
 * A value of `-1` means "unlimited" for the numeric limits (matches the
 * convention used across fia.li services and surfaced in the manifest).
 */

export interface TainikLimits {
  /** Notes a user may CREATE per calendar day. -1 = unlimited. */
  maxNotesPerDay: number
  /** Hardest cap on a note's TTL in hours; requests above this are clamped. */
  maxTtlHours: number
  /** Largest allowed ciphertext, in kilobytes. */
  maxNoteSizeKb: number
}

export const FREE_LIMITS: TainikLimits = {
  maxNotesPerDay: 10,
  maxTtlHours: 24,
  maxNoteSizeKb: 32,
}

/**
 * Coerce a raw S2S limit map into a fully-typed TainikLimits, filling any
 * missing/invalid field from FREE_LIMITS. Billing is loosely typed
 * (Record<string, number|boolean|string>), so we validate each field.
 */
const coerceLimits = (raw: Record<string, number | boolean | string> | null): TainikLimits => {
  if (!raw) return FREE_LIMITS

  const num = (key: keyof TainikLimits): number => {
    const v = raw[key]
    return typeof v === 'number' && Number.isFinite(v) ? v : FREE_LIMITS[key]
  }

  return {
    maxNotesPerDay: num('maxNotesPerDay'),
    maxTtlHours: num('maxTtlHours'),
    maxNoteSizeKb: num('maxNoteSizeKb'),
  }
}

/**
 * Resolve the effective limits for a user.
 * S2S lookup → FREE fallback. Never throws.
 */
export const getLimits = async (userId: string): Promise<TainikLimits> => {
  const raw = await fetchUserServiceLimits(userId, 'tainik')
  return coerceLimits(raw)
}

/** Current date as YYYY-MM-DD in UTC — the daily-counter bucket. */
const todayUtc = (): string => new Date().toISOString().slice(0, 10)

/** Seconds remaining until the next UTC midnight (for counter expiry). */
const secondsUntilUtcMidnight = (): number => {
  const now = new Date()
  const midnight = Date.UTC(
    now.getUTCFullYear(),
    now.getUTCMonth(),
    now.getUTCDate() + 1,
    0,
    0,
    0,
  )
  return Math.ceil((midnight - now.getTime()) / 1000)
}

/**
 * Atomically increment the user's daily create-counter and reject once the
 * plan's `maxNotesPerDay` is reached.
 *
 * Important ordering: we INCR *first*, then compare. INCR is atomic, so even
 * concurrent creates each get a distinct count and the quota can't be raced
 * past. The counter is set to expire at the next UTC midnight, so it
 * self-resets daily without a sweep job.
 *
 * Note: the increment is charged even if a later step fails. That's an
 * intentional, simple trade-off for an abuse-prevention counter — slightly
 * conservative, never permissive.
 */
export const assertUnderDailyQuota = async (
  userId: string,
  limits: TainikLimits,
): Promise<void> => {
  if (limits.maxNotesPerDay === -1) return /* unlimited */

  const key = keys.dailyCount(userId, todayUtc())
  const count = await redis.incr(key)

  /* First write of the day: attach the midnight expiry. */
  if (count === 1) {
    await redis.expire(key, secondsUntilUtcMidnight())
  }

  if (count > limits.maxNotesPerDay) {
    throw new HttpError(403, 'Daily note limit reached for your plan')
  }
}

/**
 * Clamp a requested TTL to the plan's ceiling (and a floor of 1 hour).
 * The caller passes the user's requested hours; we return what will be used.
 */
export const clampTtl = (ttlHours: number, limits: TainikLimits): number => {
  const ceiling = Math.max(1, limits.maxTtlHours)
  return Math.min(Math.max(1, Math.floor(ttlHours)), ceiling)
}

/**
 * Reject ciphertexts larger than the plan allows.
 * `ciphertextBytes` is the real byte length of the payload (see notes route),
 * compared against `maxNoteSizeKb * 1024`.
 */
export const assertSize = (ciphertextBytes: number, limits: TainikLimits): void => {
  if (ciphertextBytes > limits.maxNoteSizeKb * 1024) {
    throw new HttpError(413, `Note exceeds the ${limits.maxNoteSizeKb} KB limit for your plan`)
  }
}
