FROM node:22-alpine AS webbuild
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/consoled ./cmd/consoled

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/consoled /consoled
COPY --from=webbuild /src/web/dist /web
ENV CONSOLE_WEB_DIR=/web
USER nonroot
EXPOSE 8085
ENTRYPOINT ["/consoled"]
