# Build stage
FROM golang:1.25-alpine AS builder

WORKDIR /build

# Copy dependency files
# Note: sdk/go is a local replace directive, so we must copy its go.mod/go.sum
# before running go mod download to satisfy the dependency resolution
COPY go.mod go.sum ./
COPY sdk/go/go.mod sdk/go/go.sum ./sdk/go/
RUN go mod download

# Copy source code
COPY . .

# Build binaries (CGO not needed with modernc.org/sqlite)
# Only build essential binaries: main app + import-file
# Migration tools (migrate-chunks, migrate-encryption) can be built and run separately if needed
RUN CGO_ENABLED=0 GOOS=linux go build -a \
    -ldflags="-w -s" \
    -o safeshare ./cmd/safeshare && \
    CGO_ENABLED=0 GOOS=linux go build -a \
    -ldflags="-w -s" \
    -o import-file ./cmd/import-file

# Runtime stage
# Pin Alpine version for reproducible builds
FROM alpine:3.21

# Install runtime dependencies
# tzdata is required for Go to properly handle TZ environment variable
# Without it, time.Now() falls back to UTC regardless of TZ setting
# Use --no-scripts to avoid QEMU emulation issues with apk triggers on ARM64
# Then manually update CA certificates
RUN apk --no-cache --no-scripts add ca-certificates tzdata && \
    update-ca-certificates 2>/dev/null || true

# Create non-root user
RUN addgroup -g 1000 safeshare && \
    adduser -D -u 1000 -G safeshare safeshare

WORKDIR /app

# Copy binaries from builder
COPY --from=builder /build/safeshare .
COPY --from=builder /build/import-file .

# Create data directories
RUN mkdir -p /app/uploads /app/data && \
    chown -R safeshare:safeshare /app

# Switch to non-root user
USER safeshare

# Expose port
EXPOSE 8080

# Environment variables
ENV PORT=8080 \
    DB_PATH=/app/data/safeshare.db \
    UPLOAD_DIR=/app/uploads \
    MAX_FILE_SIZE=104857600 \
    DEFAULT_EXPIRATION_HOURS=24 \
    CLEANUP_INTERVAL_MINUTES=60 \
    PUBLIC_URL=""

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

# Run application
CMD ["./safeshare"]
