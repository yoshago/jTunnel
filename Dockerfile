# --- build stage ---
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/relayd ./cmd/relayd

# --- runtime stage ---
FROM alpine:3.20
RUN addgroup -g 10001 relayd && adduser -D -u 10001 -G relayd relayd
# server-key.pem must be readable by UID 10001 or GID 10001 (see scripts/gen-certs.sh);
# keep its permissions non-world-readable (e.g. 640, group relayd/10001).
WORKDIR /app
COPY --from=build /out/relayd ./relayd
USER relayd
EXPOSE 9090
# certs/ is not baked into the image; mount it at runtime, e.g.:
#   docker run -v $(pwd)/certs:/app/certs:ro ...
ENTRYPOINT ["./relayd", "-addr=:9090", "-ca=certs/ca-cert.pem", "-cert=certs/server-cert.pem", "-key=certs/server-key.pem"]
