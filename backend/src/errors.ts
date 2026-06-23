/*
 * HTTP error carrier.
 *
 * Routes and services `throw new HttpError(status, message)` instead of using
 * Elysia's `error()` helper. The global `onError` handler in index.ts reads
 * the `status` field and turns it into the response — see index.ts.
 */
export class HttpError extends Error {
  status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}
