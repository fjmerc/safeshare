# Build stage
FROM golang:1.27.1-alpine AS builder

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
# Essential binaries: main app, import-file, and migrate-encryption (needed
# in-image for --upgrade-format — see cmd/migrate-encryption/README.md's
# "Docker Usage" section; it must run as the same non-root user that owns
# /app/uploads, which only holds true inside this image, not on the host).
# migrate-chunks is a one-off historical tool and is not shipped here — it
# can still be built and run separately if ever needed again.
RUN CGO_ENABLED=0 GOOS=linux go build -a \
    -ldflags="-w -s" \
    -o safeshare ./cmd/safeshare && \
    CGO_ENABLED=0 GOOS=linux go build -a \
    -ldflags="-w -s" \
    -o import-file ./cmd/import-file && \
    CGO_ENABLED=0 GOOS=linux go build -a \
    -ldflags="-w -s" \
    -o migrate-encryption ./cmd/migrate-encryption

# Runtime stage
# Pin Alpine version for reproducible builds
FROM alpine:3.24

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

# Copy binaries from builder, setting ownership at copy time (--chown)
# rather than with a separate `chown -R /app` afterward: on an overlay
# filesystem, `chown -R` over files that came from an earlier layer forces
# the storage driver to duplicate their entire content into the new layer
# (a well-known Docker sizing gotcha), roughly doubling every binary's
# contribution to the final image size. --chown avoids that entirely — the
# ownership is set as part of the same copy, no second full-content layer.
COPY --from=builder --chown=safeshare:safeshare /build/safeshare .
COPY --from=builder --chown=safeshare:safeshare /build/import-file .
COPY --from=builder --chown=safeshare:safeshare /build/migrate-encryption .

# Create data directories (nothing here comes from an earlier layer, so a
# plain chown costs nothing beyond these two empty directories' own size)
RUN mkdir -p /app/uploads /app/data && \
    chown safeshare:safeshare /app/uploads /app/data

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
