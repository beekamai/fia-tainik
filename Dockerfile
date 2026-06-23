# Pinned Bun on Alpine — matches the sibling `redirects` service.
FROM oven/bun:1.2.23-alpine AS base
WORKDIR /app

# --- deps: install into a cacheable layer -----------------------------------
FROM base AS deps
# bun.lock is optional here (the `*` keeps the COPY from failing when absent).
# Generate and commit one with `bun install` for reproducible builds.
COPY package.json bun.lock* ./
RUN bun install --frozen-lockfile

# --- runner ------------------------------------------------------------------
FROM base AS runner

# Installed dependencies.
COPY --from=deps /app/node_modules ./node_modules

# App source.
COPY package.json ./
COPY tsconfig.json ./
COPY backend ./backend

ENV NODE_ENV=production

EXPOSE 3110

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://localhost:3110/health || exit 1

CMD ["bun", "run", "backend/src/index.ts"]
