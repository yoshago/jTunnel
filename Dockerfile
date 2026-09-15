# --- build stage ---
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/relayd ./cmd/relayd

# --- runtime stage ---
FROM alpine:3.20
RUN adduser -D -u 10001 relayd
# When running as USER relayd, the mounted server-key.pem must be readable by
# UID 10001 or a group accessible to relayd; keep its permissions non-world-readable.
WORKDIR /app
COPY --from=build /out/relayd ./relayd
USER relayd
EXPOSE 9090
# certs/ is not baked into the image; mount it at runtime, e.g.:
#   docker run -v $(pwd)/certs:/app/certs:ro ...
ENTRYPOINT ["./relayd", "-addr=:9090", "-ca=certs/ca-cert.pem", "-cert=certs/server-cert.pem", "-key=certs/server-key.pem"]
