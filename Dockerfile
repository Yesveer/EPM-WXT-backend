# ============================================================================
# All-in-one image: vsay-agent-backend + guacd (Guacamole proxy) in ONE image.
# guacd runs on 127.0.0.1:4822; the backend talks to it locally, and because both
# share the container network, guacd reaches the per-session RDP bridge over
# 127.0.0.1 (no host.docker.internal needed).
#   docker buildx build --platform linux/amd64,linux/arm64 -t <repo>:<tag> --push .
# ============================================================================

# ---- Build stage: compile the Go backend (+ grab ca-certs & tini for the final image)
FROM golang:1.25-alpine AS builder

WORKDIR /app
# ca-certificates + tini are copied into the guacd-based final image, which is Alpine
# but minimal (no package manager use at that stage).
RUN apk add --no-cache git ca-certificates tini

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN mkdir -p /app/certs /app/agent-binaries
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o vsay-backend ./cmd/server

# ---- Runtime stage: guacd image + our backend ----
# guacamole/guacd:1.6.0 is multi-arch (amd64 + arm64), so buildx can produce both.
FROM guacamole/guacd:1.6.0

# Run both processes from our entrypoint (root — needed to write /app/certs and run guacd).
USER root

# Pick up patched versions of whatever the upstream guacd image's own Alpine
# packages have fixes available for (e.g. glib CVEs), regardless of how
# stale that base image tag is at build time.
RUN apk upgrade --no-cache

WORKDIR /app

# CA bundle (for the backend's outbound TLS: MongoDB Atlas, Cloudinary, S3) + tini
# (proper PID 1) copied from the Alpine builder — no package manager needed here.
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /sbin/tini /sbin/tini

# Backend binary + assets from the build stage.
COPY --from=builder /app/vsay-backend /app/vsay-backend
COPY --from=builder /app/certs /app/certs
COPY --from=builder /app/agent-binaries /app/agent-binaries

# Combined entrypoint (starts guacd + backend).
COPY docker-entrypoint.sh /usr/local/bin/vsay-entrypoint.sh
RUN chmod +x /usr/local/bin/vsay-entrypoint.sh /app/vsay-backend /sbin/tini && \
    mkdir -p /app/certs /tmp/guac-recordings && \
    chmod 1777 /tmp/guac-recordings

# Environment (override at runtime). GUACD_ADDR/GUACD_HOST_GATEWAY point at loopback
# because guacd is now in this same container.
ENV MONGO_URI=mongodb+srv://kaal:kaal123@machine.7vzoy0a.mongodb.net/?appName=machine \
    CLOUDINARY_URL=cloudinary://783394936861218:CFyxF9HGVNws8YujLFlfEpsJdGQ@dblrqxs6d \
    RECONCILER_INTERVAL=30s \
    OFFLINE_TIMEOUT=1m \
    GIN_MODE=release \
    MONGO_DB_NAME=vsay-prod \
    TLS_ENABLED=false \
    GRPC_TLS_ENABLED=true \
    GRPC_MTLS_ENABLED=true \
    TLS_CERT_FILE=./certs/server-cert.pem \
    TLS_KEY_FILE=./certs/server-key.pem \
    CA_CERT_FILE=./certs/ca-cert.pem \
    CA_KEY_FILE=./certs/ca-key.pem \
    SERVER_DOMAIN=agent.webxterm.me \
    GATEWAY_SECRET=vsay-gateway-super-secret-token-change-in-production-2026 \
    GUACD_ADDR=127.0.0.1:4822 \
    GUACD_HOST_GATEWAY=127.0.0.1

# HTTP, HTTPS, gRPC
EXPOSE 8080 8443 8081

# tini as PID 1 → reaps guacd + backend cleanly and forwards signals.
ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/vsay-entrypoint.sh"]
