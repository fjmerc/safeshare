# Build stage
FROM golang:1.24-alpine AS builder

WORKDIR /build

# Copy dependency files
COPY go.mod go.sum ./
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
FROM alpine:latest

# Install runtime dependencies
RUN apk --no-cache add ca-certificates

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
