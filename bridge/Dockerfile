FROM golang:1.26-alpine AS build
WORKDIR /src
# The bridge module depends on the keysmith module via a replace directive, so
# both are copied into the build context (see platform/compose for the layout).
COPY keysmith/ /src/keysmith/
COPY bridge/ /src/bridge/
WORKDIR /src/bridge
RUN go mod download
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/bridged ./cmd/bridged

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/bridged /bridged
USER nonroot
EXPOSE 8080
ENTRYPOINT ["/bridged"]
