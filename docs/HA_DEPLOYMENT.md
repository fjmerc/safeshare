# High Availability Deployment Guide

This guide covers deploying SafeShare in a high availability (HA) configuration with multiple instances, shared storage, and database backends.

## Overview

SafeShare Enterprise supports HA deployments with:

- **Multiple application instances** behind a load balancer
- **PostgreSQL** for shared database state across instances
- **S3-compatible storage** for distributed file storage
- **Database-backed rate limiting** for consistent limits across instances
- **Graceful shutdown** that waits for in-progress uploads
- **Kubernetes-ready health checks** for orchestration

## Architecture

```
                    ┌──────────────┐
                    │ Load Balancer │
                    └──────┬───────┘
                           │
           ┌───────────────┼───────────────┐
           │               │               │
    ┌──────▼──────┐ ┌──────▼──────┐ ┌──────▼──────┐
    │ SafeShare 1 │ │ SafeShare 2 │ │ SafeShare 3 │
    └──────┬──────┘ └──────┬──────┘ └──────┬──────┘
           │               │               │
           └───────────────┼───────────────┘
                           │
              ┌────────────┴────────────┐
              │                         │
       ┌──────▼──────┐          ┌───────▼───────┐
       │  PostgreSQL │          │ S3 / MinIO    │
       │  (Primary)  │          │ (Shared)      │
       └──────┬──────┘          └───────────────┘
              │
       ┌──────▼──────┐
       │  PostgreSQL │
       │  (Replica)  │
       └─────────────┘
```

## Prerequisites

- PostgreSQL 13+ (for primary database)
- S3-compatible storage (AWS S3, MinIO, Cloudflare R2)
- Load balancer with sticky sessions support (recommended)
- Container orchestration (Kubernetes, Docker Swarm) - optional

## Database Configuration

### PostgreSQL Setup

SafeShare automatically selects PostgreSQL when `DATABASE_URL` is set:

```bash
# Required environment variable
DATABASE_URL=postgres://user:password@postgres-host:5432/safeshare?sslmode=require

# Connection pool settings (optional)
DB_MAX_OPEN_CONNS=25        # Default: 25
DB_MAX_IDLE_CONNS=10        # Default: 10
DB_CONN_MAX_LIFETIME=5m     # Default: 5 minutes
```

### PostgreSQL Connection Pooling

For high-traffic deployments, use PgBouncer:

```bash
# PgBouncer configuration
DATABASE_URL=postgres://user:password@pgbouncer-host:6432/safeshare?sslmode=disable

# Adjust pool settings for PgBouncer
DB_MAX_OPEN_CONNS=100       # Higher limit through PgBouncer
DB_MAX_IDLE_CONNS=20
```

### Database Migrations

SafeShare automatically runs migrations on startup. For multi-instance deployments, migrations use advisory locks to prevent concurrent execution:

```sql
-- SafeShare acquires this lock before running migrations
SELECT pg_advisory_lock(hashtext('safeshare_migration'));
```

### PostgreSQL High Availability

For production HA, use:

1. **Streaming Replication** - Primary + synchronous standby
2. **Patroni** - Automatic failover management
3. **Amazon RDS Multi-AZ** - Managed PostgreSQL with automatic failover

Example RDS configuration:
```bash
DATABASE_URL=postgres://user:password@safeshare-db.cluster-xxx.us-east-1.rds.amazonaws.com:5432/safeshare?sslmode=require
```

## Storage Configuration

### S3 Storage Setup

Configure S3-compatible storage for shared file access:

```bash
# Required S3 settings
STORAGE_BACKEND=s3
S3_BUCKET=safeshare-uploads
S3_REGION=us-east-1

# Authentication (choose one method)
# Option 1: Access keys
AWS_ACCESS_KEY_ID=AKIAXXXXXXXXXXXXXXXX
AWS_SECRET_ACCESS_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

# Option 2: IAM role (for EC2/ECS/EKS)
# No credentials needed - uses instance role

# Optional settings
S3_ENDPOINT=                          # Custom endpoint for MinIO/R2
S3_FORCE_PATH_STYLE=false             # Set true for MinIO
S3_ACCELERATE=false                   # Use S3 Transfer Acceleration
```

### MinIO Setup (Self-Hosted S3)

```bash
# MinIO configuration
STORAGE_BACKEND=s3
S3_BUCKET=safeshare
S3_REGION=us-east-1
S3_ENDPOINT=http://minio.example.com:9000
S3_FORCE_PATH_STYLE=true
AWS_ACCESS_KEY_ID=minioadmin
AWS_SECRET_ACCESS_KEY=minioadmin
```

### Cloudflare R2 Setup

```bash
STORAGE_BACKEND=s3
S3_BUCKET=safeshare
S3_REGION=auto
S3_ENDPOINT=https://ACCOUNT_ID.r2.cloudflarestorage.com
AWS_ACCESS_KEY_ID=R2_ACCESS_KEY
AWS_SECRET_ACCESS_KEY=R2_SECRET_KEY
```

### Encryption with S3

When using S3 storage with encryption enabled:

```bash
ENCRYPTION_KEY=$(openssl rand -hex 32)
STORAGE_BACKEND=s3
S3_BUCKET=safeshare-uploads
```

Files are encrypted client-side before upload to S3, providing end-to-end encryption regardless of S3's server-side encryption settings.

## Rate Limiting

### Database-Backed Rate Limits

In HA mode, rate limits are stored in the database for consistency across instances:

```bash
# Enable database-backed rate limiting
RATE_LIMIT_BACKEND=database           # Options: memory, database

# Rate limit settings
RATE_LIMIT_UPLOAD=10                  # Uploads per hour per IP
RATE_LIMIT_DOWNLOAD=100               # Downloads per hour per IP
RATE_LIMIT_WINDOW=3600                # Window in seconds (1 hour)
```

### Rate Limit Table Schema

SafeShare automatically creates the rate limit table:

```sql
CREATE TABLE rate_limits (
    id SERIAL PRIMARY KEY,
    key VARCHAR(255) NOT NULL,        -- IP:action format
    count INTEGER DEFAULT 0,
    window_start TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    CONSTRAINT unique_rate_limit_key UNIQUE (key)
);
```

### Distributed Lock Support

For operations requiring global coordination (like cleanup tasks), SafeShare uses database-backed distributed locks:

```sql
CREATE TABLE distributed_locks (
    lock_name VARCHAR(255) PRIMARY KEY,
    holder_id VARCHAR(255) NOT NULL,
    acquired_at TIMESTAMP NOT NULL,
    expires_at TIMESTAMP NOT NULL
);
```

## Health Checks

### Kubernetes Probes

SafeShare provides three health endpoints optimized for Kubernetes:

#### Liveness Probe (`/health/live`)

Fast check (~10ms) - Is the process alive?

```yaml
livenessProbe:
  httpGet:
    path: /health/live
    port: 8080
  initialDelaySeconds: 5
  periodSeconds: 10
  timeoutSeconds: 2
  failureThreshold: 3
```

Returns:
- `200 OK` - Process is alive, database is reachable
- `503 Service Unavailable` - Process is unhealthy (restart needed)

#### Readiness Probe (`/health/ready`)

Comprehensive check - Is the instance ready for traffic?

```yaml
readinessProbe:
  httpGet:
    path: /health/ready
    port: 8080
  initialDelaySeconds: 10
  periodSeconds: 5
  timeoutSeconds: 5
  failureThreshold: 2
```

Returns:
- `200 OK` with status "healthy" - Ready for traffic
- `503 Service Unavailable` with status "degraded" or "unhealthy" - Remove from load balancer

#### Full Health Check (`/health`)

Detailed metrics for monitoring:

```json
{
  "status": "healthy",
  "uptime_seconds": 3600,
  "database": {
    "status": "healthy",
    "latency_ms": 2,
    "connections": {
      "open": 5,
      "max": 25
    }
  },
  "storage": {
    "status": "healthy",
    "backend": "s3",
    "bucket": "safeshare-uploads"
  },
  "disk": {
    "status": "healthy",
    "free_bytes": 53687091200,
    "used_percent": 50.0
  },
  "quota": {
    "used_bytes": 5368709120,
    "limit_bytes": 53687091200,
    "used_percent": 10.0
  }
}
```

### Health Check Caching

Health check responses include cache control headers to prevent excessive database queries:

```
Cache-Control: no-store, max-age=0
X-Health-Check-Time: 2025-01-15T10:30:00Z
```

The health check includes a 5-second timeout for all backend checks.

## Graceful Shutdown

SafeShare implements a phased shutdown process to prevent data loss:

### Shutdown Phases

1. **Phase 1: Stop accepting new uploads** (immediate)
   - New upload requests return `503 Service Unavailable`
   - Existing connections continue processing

2. **Phase 2: Wait for in-progress uploads** (30 seconds default)
   - Waits for active file uploads to complete
   - Waits for chunked upload assembly workers
   - Logs warning for any abandoned uploads

3. **Phase 3: HTTP server shutdown** (10 seconds)
   - Gracefully closes existing HTTP connections
   - Returns error for any new requests

4. **Phase 4: Background worker shutdown** (5 seconds)
   - Stops cleanup worker
   - Stops expiration worker

### Kubernetes PreStop Hook

For zero-downtime deployments, use a preStop hook:

```yaml
lifecycle:
  preStop:
    exec:
      command: ["/bin/sh", "-c", "sleep 5"]
```

This gives the load balancer time to remove the pod before shutdown begins.

### Configuring Shutdown Timeouts

```bash
# Environment variables for shutdown behavior
SHUTDOWN_TIMEOUT=45                   # Total shutdown timeout (seconds)
UPLOAD_WAIT_TIMEOUT=30                # Time to wait for uploads (seconds)
HTTP_SHUTDOWN_TIMEOUT=10              # Time for HTTP drain (seconds)
```

## Kubernetes Deployment

### Complete Deployment Example

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: safeshare
  labels:
    app: safeshare
spec:
  replicas: 3
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxUnavailable: 1
      maxSurge: 1
  selector:
    matchLabels:
      app: safeshare
  template:
    metadata:
      labels:
        app: safeshare
    spec:
      terminationGracePeriodSeconds: 60
      containers:
      - name: safeshare
        image: safeshare:latest
        ports:
        - containerPort: 8080
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: safeshare-secrets
              key: database-url
        - name: ENCRYPTION_KEY
          valueFrom:
            secretKeyRef:
              name: safeshare-secrets
              key: encryption-key
        - name: STORAGE_BACKEND
          value: "s3"
        - name: S3_BUCKET
          value: "safeshare-uploads"
        - name: S3_REGION
          value: "us-east-1"
        - name: RATE_LIMIT_BACKEND
          value: "database"
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /health/live
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 10
          timeoutSeconds: 2
          failureThreshold: 3
        readinessProbe:
          httpGet:
            path: /health/ready
            port: 8080
          initialDelaySeconds: 10
          periodSeconds: 5
          timeoutSeconds: 5
          failureThreshold: 2
        lifecycle:
          preStop:
            exec:
              command: ["/bin/sh", "-c", "sleep 5"]
---
apiVersion: v1
kind: Service
metadata:
  name: safeshare
spec:
  selector:
    app: safeshare
  ports:
  - port: 80
    targetPort: 8080
  type: ClusterIP
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: safeshare
  annotations:
    nginx.ingress.kubernetes.io/proxy-body-size: "100m"
    nginx.ingress.kubernetes.io/proxy-read-timeout: "300"
spec:
  rules:
  - host: share.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: safeshare
            port:
              number: 80
```

### Horizontal Pod Autoscaler

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: safeshare
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: safeshare
  minReplicas: 2
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
```

## Docker Swarm Deployment

```yaml
version: '3.8'

services:
  safeshare:
    image: safeshare:latest
    deploy:
      replicas: 3
      update_config:
        parallelism: 1
        delay: 10s
        order: start-first
      rollback_config:
        parallelism: 1
        delay: 10s
      restart_policy:
        condition: on-failure
        delay: 5s
        max_attempts: 3
    environment:
      - DATABASE_URL=postgres://user:password@postgres:5432/safeshare
      - STORAGE_BACKEND=s3
      - S3_BUCKET=safeshare-uploads
      - RATE_LIMIT_BACKEND=database
    secrets:
      - encryption_key
    healthcheck:
      test: ["CMD", "wget", "--no-verbose", "--tries=1", "--spider", "http://localhost:8080/health/live"]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 10s
    networks:
      - safeshare-net

  postgres:
    image: postgres:15
    deploy:
      placement:
        constraints:
          - node.role == manager
    environment:
      - POSTGRES_DB=safeshare
      - POSTGRES_USER=safeshare
      - POSTGRES_PASSWORD_FILE=/run/secrets/db_password
    secrets:
      - db_password
    volumes:
      - postgres-data:/var/lib/postgresql/data
    networks:
      - safeshare-net

secrets:
  encryption_key:
    external: true
  db_password:
    external: true

volumes:
  postgres-data:

networks:
  safeshare-net:
    driver: overlay
```

## Load Balancer Configuration

### Sticky Sessions

For chunked uploads to work reliably, configure sticky sessions:

**nginx:**
```nginx
upstream safeshare {
    ip_hash;  # Sticky sessions by IP
    server safeshare-1:8080;
    server safeshare-2:8080;
    server safeshare-3:8080;
}
```

**AWS ALB:**
```bash
# Enable sticky sessions in target group
aws elbv2 modify-target-group-attributes \
  --target-group-arn <arn> \
  --attributes Key=stickiness.enabled,Value=true \
               Key=stickiness.type,Value=lb_cookie \
               Key=stickiness.lb_cookie.duration_seconds,Value=3600
```

### Health Check Configuration

Configure your load balancer to use the readiness endpoint:

```
Health check path: /health/ready
Healthy threshold: 2
Unhealthy threshold: 3
Timeout: 5 seconds
Interval: 10 seconds
```

## Monitoring and Alerting

### Key Metrics to Monitor

1. **Health status** - Alert on degraded/unhealthy
2. **Database connection pool** - Alert if connections near max
3. **Storage backend latency** - Alert on high latency
4. **Active uploads** - Monitor for stuck uploads
5. **Rate limit hits** - Monitor for abuse patterns

### Prometheus Scrape Config

```yaml
scrape_configs:
  - job_name: 'safeshare'
    kubernetes_sd_configs:
      - role: pod
    relabel_configs:
      - source_labels: [__meta_kubernetes_pod_label_app]
        action: keep
        regex: safeshare
    metrics_path: /metrics
    scrape_interval: 30s
```

### Alert Rules

```yaml
groups:
- name: safeshare
  rules:
  - alert: SafeShareUnhealthy
    expr: safeshare_health_status != 1
    for: 5m
    labels:
      severity: critical
    annotations:
      summary: "SafeShare instance unhealthy"
      
  - alert: SafeShareHighDBLatency
    expr: safeshare_db_latency_ms > 100
    for: 10m
    labels:
      severity: warning
    annotations:
      summary: "High database latency detected"
      
  - alert: SafeShareStorageError
    expr: safeshare_storage_errors_total > 0
    for: 5m
    labels:
      severity: critical
    annotations:
      summary: "Storage backend errors detected"
```

## Troubleshooting

### Common Issues

**1. Database connection errors**
```bash
# Check connection count
psql -c "SELECT count(*) FROM pg_stat_activity WHERE datname='safeshare';"

# Verify connection string
docker exec safeshare psql "$DATABASE_URL" -c "SELECT 1"
```

**2. S3 access denied**
```bash
# Test S3 credentials
aws s3 ls s3://safeshare-uploads/

# Check IAM policy
aws iam get-role-policy --role-name safeshare-role --policy-name s3-access
```

**3. Rate limits not syncing**
```bash
# Check rate limit table
psql "$DATABASE_URL" -c "SELECT * FROM rate_limits ORDER BY updated_at DESC LIMIT 10;"
```

**4. Uploads failing during rolling update**
```bash
# Check active uploads before scaling down
curl http://safeshare-pod:8080/health | jq '.active_uploads'
```

### Debug Mode

Enable debug logging for troubleshooting:

```bash
LOG_LEVEL=debug
LOG_FORMAT=json
```

## See Also

- [PRODUCTION.md](./PRODUCTION.md) - Single-instance production deployment
- [REVERSE_PROXY.md](./REVERSE_PROXY.md) - Reverse proxy configurations
- [INFRASTRUCTURE_PLANNING.md](./INFRASTRUCTURE_PLANNING.md) - Capacity planning
- [SECURITY.md](./SECURITY.md) - Security best practices
