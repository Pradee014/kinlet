# Build stage: full image has the toolchain better-sqlite3 needs.
FROM node:22-bookworm AS build
RUN corepack enable
WORKDIR /app
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml tsconfig.base.json ./
COPY packages ./packages
COPY apps ./apps
RUN pnpm install --frozen-lockfile
RUN pnpm -r build
RUN CI=true pnpm install --prod --frozen-lockfile --force

# Runtime stage.
FROM node:22-bookworm-slim
ENV NODE_ENV=production
WORKDIR /app
COPY --from=build /app ./
RUN mkdir -p /data && chown node:node /data
USER node
ENV PORT=8080 KINLET_DATA=/data
EXPOSE 8080
CMD ["node", "apps/server/dist/index.js"]
