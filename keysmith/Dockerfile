FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/keysmithd ./cmd/keysmithd

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/keysmithd /keysmithd
USER nonroot
EXPOSE 8081
ENTRYPOINT ["/keysmithd"]
