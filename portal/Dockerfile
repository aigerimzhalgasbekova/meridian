# Multi-stage: build both workspaces, ship only the compiled server +
# static web assets on a slim runtime image.

FROM node:22-slim AS build
WORKDIR /app
COPY package.json package-lock.json ./
COPY server/package.json server/
COPY web/package.json web/
RUN npm ci
COPY . .
RUN npm run build

FROM node:22-slim AS deps
WORKDIR /app
COPY package.json package-lock.json ./
COPY server/package.json server/
COPY web/package.json web/
RUN npm ci --omit=dev -w server

FROM node:22-slim
ENV NODE_ENV=production
# /app is root-owned read-only application code; point the default outbox
# somewhere the non-root node user can write.
ENV OUTBOX_DIR=/tmp/outbox
# Amazon RDS CA bundle so Postgres TLS can be *verified* (sslmode=verify-full
# with sslrootcert=<this path> in the DSN) instead of downgraded to no-verify.
# Checksum-pinned: a build must fail, not silently trust, if the bundle a
# mirror serves ever differs. Bump the pin when AWS rotates the bundle.
# --chmod matters: URL ADDs default to 600 root-only and the server runs as
# the unprivileged node user. Deliberately NOT under /etc/ssl — an ADD there
# re-created the directory chain with root-only perms and broke OpenSSL's
# own config lookup (fopen /etc/ssl/openssl.cnf -> EACCES) for that user.
ADD --checksum=sha256:e5bb2084ccf45087bda1c9bffdea0eb15ee67f0b91646106e466714f9de3c7e3 --chmod=644 \
  https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem /usr/local/share/rds-global-bundle.pem
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY --from=build /app/server/dist ./server/dist
COPY --from=build /app/web/dist ./web/dist
COPY server/schema.sql ./server/schema.sql
USER node
EXPOSE 3000
CMD ["node", "server/dist/index.js"]
