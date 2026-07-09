FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/sessiond ./cmd/sessiond

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/sessiond /sessiond
USER nonroot
EXPOSE 8082
ENTRYPOINT ["/sessiond"]
