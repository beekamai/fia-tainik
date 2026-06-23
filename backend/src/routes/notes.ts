import { Elysia, t } from 'elysia'
import { redis, keys } from '../redis/client'
import { authPlugin } from '../plugins/auth'
import { HttpError } from '../errors'
import {
  getLimits,
  assertSize,
  assertUnderDailyQuota,
  clampTtl,
} from '../services/limits'

/*
 * Notes API — the entire surface of Тайник.
 *
 * Zero-knowledge contract (read this before touching anything here):
 *   - The body field `ciphertext` is an opaque, client-encrypted blob. The
 *     encryption key lives ONLY in the URL fragment on the client and is never
 *     sent to the server. We store the ciphertext verbatim and can't read it.
 *   - There is therefore no server-side crypto in this file, by design. Adding
 *     any would break the zero-knowledge guarantee.
 *
 * Three endpoints:
 *   POST /notes            — auth required; store a ciphertext with a TTL.
 *   GET  /notes/:id        — public; existence probe, does NOT burn.
 *   POST /notes/:id/reveal — public; atomic read-once burn (GETDEL).
 */

/** What we persist per note. The TTL handles expiry; no `expiresAt` stored. */
interface StoredNote {
  ciphertext: string
  createdAt: number
}

/*
 * Note ids are 32 lowercase hex chars (a dash-stripped UUIDv4). We still
 * validate `:id` strictly so a malformed path is a clean 404 rather than a
 * Redis lookup on attacker-controlled input.
 */
const ID_RE = /^[a-f0-9]{32}$/
const newId = (): string => crypto.randomUUID().replace(/-/g, '')

const assertValidId = (id: string): void => {
  if (!ID_RE.test(id)) throw new HttpError(404, 'Note not found')
}

export const notesRoutes = new Elysia({ prefix: '/api/tainik' })

  /*
   * POST /api/tainik/notes — create a self-destructing note.
   *
   * The only authenticated route: we need an identity to attribute the note
   * and to enforce the creator's per-plan limits. Reading/burning is public.
   */
  .use(authPlugin)
  .post(
    '/notes',
    async ({ user, body }) => {
      const limits = await getLimits(user.id)

      /*
       * `ciphertext` is base64. Enforce the plan's size cap against the real
       * decoded byte length, not the (larger) base64 string length, so the
       * limit reflects actual stored payload.
       */
      const ciphertextBytes = Buffer.from(body.ciphertext, 'base64').length
      assertSize(ciphertextBytes, limits)

      /* Abuse control: atomic daily counter; throws 403 when over quota. */
      await assertUnderDailyQuota(user.id, limits)

      /* Honour the request but never exceed the plan's TTL ceiling. */
      const ttlHours = clampTtl(body.ttlHours, limits)

      const id = newId()
      const note: StoredNote = { ciphertext: body.ciphertext, createdAt: Date.now() }

      /* Store with a hard TTL — Redis evicts it automatically when unread. */
      await redis.set(keys.note(id), JSON.stringify(note), 'EX', ttlHours * 3600)

      return {
        id,
        ttlHours,
        expiresAt: new Date(Date.now() + ttlHours * 3600 * 1000).toISOString(),
      }
    },
    {
      body: t.Object({
        /* Opaque client-side ciphertext (base64). 200k chars ≈ 150 KB raw. */
        ciphertext: t.String({ maxLength: 200_000 }),
        /* Requested lifetime; clamped to the plan ceiling server-side. */
        ttlHours: t.Number({ minimum: 1 }),
      }),
    },
  )

  /*
   * GET /api/tainik/notes/:id — existence probe. PUBLIC, and deliberately
   * non-destructive: the recipient's "reveal?" screen calls this, and so do
   * link-preview bots (chat apps, crawlers) — none of which should burn the
   * note. Returns only a boolean, never the ciphertext.
   */
  .get(
    '/notes/:id',
    async ({ params: { id } }) => {
      assertValidId(id)
      const exists = (await redis.exists(keys.note(id))) === 1
      return { exists }
    },
    { params: t.Object({ id: t.String() }) },
  )

  /*
   * POST /api/tainik/notes/:id/reveal — read-once burn. PUBLIC.
   *
   * GETDEL is atomic: it returns the value and deletes the key in a single
   * operation. So two concurrent reveals can't both win — exactly one gets the
   * ciphertext, everyone else gets a 404. This is the self-destruct guarantee.
   */
  .post(
    '/notes/:id/reveal',
    async ({ params: { id } }) => {
      assertValidId(id)

      const raw = await redis.getdel(keys.note(id))
      if (!raw) throw new HttpError(404, 'Note not found or already read')

      const note = JSON.parse(raw) as StoredNote
      return { ciphertext: note.ciphertext }
    },
    { params: t.Object({ id: t.String() }) },
  )
