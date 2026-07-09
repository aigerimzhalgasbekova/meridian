FROM golang:1.26-alpine AS build
WORKDIR /src/sentinel
COPY . .
RUN go mod download
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/sentineld ./cmd/sentineld

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/sentineld /sentineld
USER nonroot
EXPOSE 8084
# SENTINEL_TOKEN must be provided; SENTINEL_AUDIT_PATH should point at a volume.
ENTRYPOINT ["/sentineld"]
