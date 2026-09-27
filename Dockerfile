FROM node:20-alpine AS builder

# Enable corepack for pnpm
RUN corepack enable pnpm

WORKDIR /app
COPY package.json pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile

COPY . .
RUN pnpm build

FROM node:20-alpine AS runner

RUN corepack enable pnpm

WORKDIR /app
COPY --from=builder /app/package.json ./
COPY --from=builder /app/pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile --prod

COPY --from=builder /app/dist ./dist

# Symlink the CLI entry point
RUN mkdir -p /usr/local/bin && ln -s /app/dist/cli/index.js /usr/local/bin/gitleak-radar

# Define entrypoint to allow seamless scanning of mounted volumes
ENTRYPOINT ["node", "/app/dist/cli/index.js"]
CMD ["scan", "/scan"]
