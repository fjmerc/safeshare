# Build stage
FROM golang:1.24-alpine AS builder

WORKDIR /build

# Copy dependency files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build binary (CGO not needed with modernc.org/sqlite)
RUN CGO_ENABLED=0 GOOS=linux go build -a \
    -ldflags="-w -s" \
    -o safeshare ./cmd/safeshare

# Runtime stage
FROM alpine:latest

# Install runtime dependencies
RUN apk --no-cache add ca-certificates

# Create non-root user
RUN addgroup -g 1000 safeshare && \
    adduser -D -u 1000 -G safeshare safeshare

WORKDIR /app

# Copy binary from builder
COPY --from=builder /build/safeshare .

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
