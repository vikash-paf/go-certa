# ------------------------------------------------------------------------------
# Build Stage
# ------------------------------------------------------------------------------
FROM golang:1.24-alpine AS builder

WORKDIR /src

# Install git and build dependencies
RUN apk add --no-cache git ca-certificates

# Cache dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Compile statically linked binary with stripped debug symbols
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /bin/certa-server ./cmd/certa-server/

# ------------------------------------------------------------------------------
# Final Runtime Stage
# ------------------------------------------------------------------------------
FROM alpine:3.21

# Install basic diagnostic tools (curl, openssl for testing) and ca-certificates
RUN apk add --no-cache ca-certificates tzdata curl openssl

# Create non-root user and group
RUN addgroup -S certa && adduser -S certa -G certa

# Create persistent data directory with proper ownership
RUN mkdir -p /data && chown -R certa:certa /data

WORKDIR /app

# Copy binary from builder
COPY --from=builder /bin/certa-server /app/certa-server

# Default environment configuration
ENV CERTA_DATA_DIR=/data \
    CERTA_LISTEN_ADDR=:8080 \
    CERTA_BASE_URL=http://localhost:8080

# Expose HTTP port
EXPOSE 8080

# Declare persistent volume
VOLUME ["/data"]

# Switch to non-root user
USER certa

# Health check using Prometheus metrics endpoint
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8080/metrics || exit 1

ENTRYPOINT ["/app/certa-server"]
