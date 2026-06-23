import { Elysia } from 'elysia'
import cors from '@elysiajs/cors'
import { config } from './config'
import { connectRedis } from './redis/client'
import { notesRoutes } from './routes/notes'

/*
 * Тайник — zero-knowledge self-destructing notes for the fia.li community.
 *
 * The server is deliberately tiny: it stores client-encrypted ciphertext in
 * Redis with a TTL and burns it on first read. It never sees plaintext or the
 * encryption key (which lives in the URL fragment, client-side only). All it
 * enforces is the creator's per-plan limits. See README.md for the full model.
 */

/* Connect to Redis before serving — fail fast if it's unreachable. */
await connectRedis()

const app = new Elysia()
  .use(
    cors({
      origin: config.cors.origins,
      credentials: true,
      allowedHeaders: ['Content-Type', 'Authorization'],
      methods: ['GET', 'POST', 'OPTIONS'],
    }),
  )

  /* Health check — for the Docker HEALTHCHECK and any load balancer. */
  .get('/health', () => ({ status: 'ok', ts: Date.now() }))

  /*
   * Manifest — consumed by the fia.li registry to sync this service's
   * configurable capabilities (the per-plan limits). Kept in sync with the
   * root manifest.json and with services/limits.ts defaults.
   */
  .get('/manifest', () => ({
    slug: 'tainik',
    name: 'Тайник',
    version: '1.0.0',
    capabilities: [
      {
        key: 'maxNotesPerDay',
        type: 'number',
        label: 'Заметок в день',
        description: 'Лимит создаваемых заметок в сутки (-1 = безлимит)',
        defaultValue: 10,
      },
      {
        key: 'maxTtlHours',
        type: 'number',
        label: 'Макс. срок жизни (ч)',
        description: 'Максимальный TTL заметки в часах',
        defaultValue: 24,
      },
      {
        key: 'maxNoteSizeKb',
        type: 'number',
        label: 'Макс. размер (КБ)',
        description: 'Максимальный размер шифротекста',
        defaultValue: 32,
      },
    ],
  }))

  /* The notes API (create / probe / reveal). */
  .use(notesRoutes)

  /*
   * Global error handler. Maps known cases to clean responses and, crucially,
   * never leaks internals: unexpected errors are logged server-side and
   * answered with a generic 500.
   */
  .onError(({ code, error, set }) => {
    const status = 'status' in error ? (error.status as number) : undefined
    const message = 'message' in error ? (error.message as string) : 'Error'

    if (code === 'VALIDATION') {
      set.status = 422
      return { message: 'Validation error', details: error.message }
    }

    if (code === 'NOT_FOUND') {
      set.status = 404
      return { message: 'Not found' }
    }

    /* Errors that carry an explicit HTTP status (HttpError, AuthError). */
    if (status) {
      set.status = status
      return { message }
    }

    /* Unexpected — log it, but don't expose details to the client. */
    console.error('[error]', error)
    set.status = 500
    return { message: 'Internal server error' }
  })

  .listen(config.port)

console.log(`[fia-tainik] running on :${config.port}`)

export type App = typeof app
