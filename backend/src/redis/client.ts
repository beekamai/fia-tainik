import Redis from 'ioredis'
import { config } from '../config'

/*
 * Single shared ioredis connection.
 *
 * Тайник keeps *all* of its state here: note ciphertexts (with a TTL),
 * a short-lived `/me` auth cache, and per-user daily counters. There is no
 * database — Redis' native expiry and atomic GETDEL are exactly the
 * primitives a self-destructing-notes service needs.
 */
export const redis = new Redis({
  host: config.redis.host,
  port: config.redis.port,
  password: config.redis.password,
  keyPrefix: config.redis.keyPrefix,
  /* Fail fast on startup rather than silently queueing commands. */
  enableOfflineQueue: false,
  lazyConnect: true,
})

redis.on('error', (err) => {
  console.error('[redis] connection error:', err.message)
})

export const connectRedis = async (): Promise<void> => {
  await redis.connect()
  console.log('[redis] connected')
}

/*
 * Key builders — centralized so the layout is documented in one spot and
 * typos can't silently fork the keyspace. All of these are additionally
 * prefixed with `tainik:` by ioredis (see config.redis.keyPrefix).
 */
export const keys = {
  /** The note itself: JSON { ciphertext, createdAt }, expires via TTL. */
  note: (id: string) => `note:${id}`,
  /** Cached `/me` profile, keyed by a hash of the forwarded credential. */
  auth: (hash: string) => `auth:${hash}`,
  /** Per-user daily create counter, e.g. count:<userId>:2026-06-23. */
  dailyCount: (userId: string, day: string) => `count:${userId}:${day}`,
} as const
