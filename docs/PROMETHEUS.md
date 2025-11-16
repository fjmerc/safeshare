# Prometheus Metrics & Observability

SafeShare exposes production-grade Prometheus metrics for comprehensive observability and monitoring. This guide covers metrics available, setup instructions, and practical examples for monitoring your SafeShare deployment.

## Overview

SafeShare implements a `/metrics` endpoint that exposes application metrics in Prometheus format. This enables:

- **Performance Monitoring**: Track upload/download rates, request latency, and throughput
- **Capacity Planning**: Monitor storage usage, quota consumption, and file counts
- **Error Detection**: Track error rates and failed operations
- **SLA Compliance**: Measure request success rates and response times
- **Alerting**: Set up proactive alerts for critical conditions

## Quick Start

### Accessing Metrics

The metrics endpoint is publicly accessible at:

```
http://your-safeshare-instance:8080/metrics
```

Example:
```bash
curl http://localhost:8080/metrics
```

Output format (Prometheus text exposition format):
```
# HELP safeshare_uploads_total Total number of file uploads
# TYPE safeshare_uploads_total counter
safeshare_uploads_total{status="success"} 142
safeshare_uploads_total{status="failure"} 3

# HELP safeshare_http_request_duration_seconds HTTP request latency in seconds
# TYPE safeshare_http_request_duration_seconds histogram
safeshare_http_request_duration_seconds_bucket{method="POST",path="/api/upload",le="0.1"} 95
safeshare_http_request_duration_seconds_bucket{method="POST",path="/api/upload",le="0.5"} 142
...
```

## Metrics Reference

### Counter Metrics

Counters are cumulative values that only increase (reset on restart).

| Metric Name | Type | Labels | Description |
|-------------|------|--------|-------------|
| `safeshare_uploads_total` | Counter | `status` (success/failure) | Total number of file uploads |
| `safeshare_downloads_total` | Counter | `status` (success/password_failed/failure) | Total number of file downloads |
| `safeshare_chunked_uploads_total` | Counter | - | Total chunked upload sessions initialized |
| `safeshare_chunked_uploads_completed_total` | Counter | - | Total chunked upload sessions completed |
| `safeshare_chunked_upload_chunks_total` | Counter | - | Total number of chunks uploaded |
| `safeshare_http_requests_total` | Counter | `method`, `path`, `status` | Total HTTP requests by method, normalized path, and status code |
| `safeshare_errors_total` | Counter | `type` | Total errors by error type |

**Label Details:**

- `status` (uploads/downloads):
  - `success` - Operation completed successfully
  - `failure` - Operation failed (validation, storage, etc.)
  - `password_failed` - Download failed due to incorrect password (downloads only)

- `method` (HTTP requests): `GET`, `POST`, `PUT`, `DELETE`, etc.

- `path` (HTTP requests): Normalized paths to prevent cardinality explosion
  - `/api/upload` - Simple upload endpoint
  - `/api/upload/init` - Chunked upload initialization
  - `/api/upload/chunk/:id/:number` - Chunk upload (dynamic segments replaced)
  - `/api/upload/complete/:id` - Chunked upload completion
  - `/api/upload/status/:id` - Upload status check
  - `/api/claim/:code` - File download
  - `/api/claim/:code/info` - File metadata
  - `/admin/api/*` - Admin API endpoints
  - `/other` - Unmatched paths

- `status` (HTTP requests): HTTP status code (`200`, `201`, `400`, `404`, `500`, etc.)

### Histogram Metrics

Histograms track distributions and calculate quantiles.

| Metric Name | Type | Labels | Description | Buckets |
|-------------|------|--------|-------------|---------|
| `safeshare_http_request_duration_seconds` | Histogram | `method`, `path` | HTTP request latency in seconds | 0.001, 0.01, 0.05, 0.1, 0.5, 1, 2.5, 5, 10 |
| `safeshare_upload_size_bytes` | Histogram | - | Size of uploaded files in bytes | 1KB, 10KB, 100KB, 1MB, 10MB, 100MB, 1GB, 10GB |
| `safeshare_download_size_bytes` | Histogram | - | Size of downloaded files in bytes | 1KB, 10KB, 100KB, 1MB, 10MB, 100MB, 1GB, 10GB |

**Histogram Usage:**
Histograms automatically generate:
- `_bucket{le="X"}` - Count of observations ≤ X
- `_sum` - Sum of all observed values
- `_count` - Total number of observations

### Gauge Metrics

Gauges are point-in-time measurements that can go up or down.

| Metric Name | Type | Description |
|-------------|------|-------------|
| `safeshare_storage_used_bytes` | Gauge | Total storage used by active files (bytes) |
| `safeshare_active_files_count` | Gauge | Number of active (non-expired) files |
| `safeshare_active_partial_uploads_count` | Gauge | Number of in-progress chunked uploads |
| `safeshare_storage_quota_bytes` | Gauge | Storage quota limit in bytes (0 = unlimited) |
| `safeshare_storage_quota_used_percent` | Gauge | Percentage of quota used (0-100, or 0 if unlimited) |

**Note:** Gauge metrics are collected dynamically from the database on each scrape.

## Prometheus Setup

### Configuration

Add SafeShare to your `prometheus.yml` configuration:

```yaml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'safeshare'
    static_configs:
      - targets: ['safeshare:8080']
        labels:
          environment: 'production'
          service: 'safeshare'

    # Optional: Increase scrape timeout for large deployments
    scrape_timeout: 10s

    # Optional: Relabeling rules
    relabel_configs:
      - source_labels: [__address__]
        target_label: instance
        replacement: 'safeshare-prod'
```

### Docker Compose Example

```yaml
version: '3.8'

services:
  safeshare:
    image: safeshare:latest
    ports:
      - "8080:8080"
    environment:
      - ADMIN_USERNAME=admin
      - ADMIN_PASSWORD=SecurePassword123
    volumes:
      - safeshare-data:/app/data
      - safeshare-uploads:/app/uploads
    networks:
      - monitoring

  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
      - prometheus-data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--storage.tsdb.retention.time=30d'
    networks:
      - monitoring

  grafana:
    image: grafana/grafana:latest
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
    volumes:
      - grafana-data:/var/lib/grafana
    networks:
      - monitoring

networks:
  monitoring:
    driver: bridge

volumes:
  safeshare-data:
  safeshare-uploads:
  prometheus-data:
  grafana-data:
```

Start the stack:
```bash
docker-compose up -d
```

Access:
- Prometheus: http://localhost:9090
- Grafana: http://localhost:3000
- SafeShare metrics: http://localhost:8080/metrics

## Example PromQL Queries

### Upload & Download Metrics

**Upload rate (uploads per second, 5-minute average):**
```promql
rate(safeshare_uploads_total{status="success"}[5m])
```

**Download rate (downloads per second, 5-minute average):**
```promql
rate(safeshare_downloads_total{status="success"}[5m])
```

**Upload success rate (percentage):**
```promql
100 * (
  rate(safeshare_uploads_total{status="success"}[5m])
  /
  rate(safeshare_uploads_total[5m])
)
```

**Failed uploads (per minute):**
```promql
rate(safeshare_uploads_total{status="failure"}[1m]) * 60
```

**Password-protected download failures:**
```promql
rate(safeshare_downloads_total{status="password_failed"}[5m])
```

### Chunked Upload Metrics

**Chunked upload completion rate:**
```promql
rate(safeshare_chunked_uploads_completed_total[5m])
```

**Average chunks per upload:**
```promql
rate(safeshare_chunked_upload_chunks_total[5m])
/
rate(safeshare_chunked_uploads_completed_total[5m])
```

**Active chunked uploads:**
```promql
safeshare_active_partial_uploads_count
```

### HTTP Request Metrics

**Request rate by endpoint:**
```promql
rate(safeshare_http_requests_total[5m])
```

**Error rate (4xx and 5xx responses):**
```promql
rate(safeshare_http_requests_total{status=~"4..|5.."}[5m])
```

**Request error percentage:**
```promql
100 * (
  rate(safeshare_http_requests_total{status=~"4..|5.."}[5m])
  /
  rate(safeshare_http_requests_total[5m])
)
```

**Requests by status code:**
```promql
sum(rate(safeshare_http_requests_total[5m])) by (status)
```

### Latency Metrics

**Median (p50) request latency:**
```promql
histogram_quantile(0.50,
  rate(safeshare_http_request_duration_seconds_bucket[5m])
)
```

**95th percentile (p95) request latency:**
```promql
histogram_quantile(0.95,
  rate(safeshare_http_request_duration_seconds_bucket[5m])
)
```

**99th percentile (p99) request latency:**
```promql
histogram_quantile(0.99,
  rate(safeshare_http_request_duration_seconds_bucket[5m])
)
```

**Average request latency by endpoint:**
```promql
rate(safeshare_http_request_duration_seconds_sum[5m])
/
rate(safeshare_http_request_duration_seconds_count[5m])
```

**Slowest endpoints (top 5):**
```promql
topk(5,
  rate(safeshare_http_request_duration_seconds_sum[5m])
  /
  rate(safeshare_http_request_duration_seconds_count[5m])
)
```

### File Size Metrics

**Average upload size (bytes):**
```promql
rate(safeshare_upload_size_bytes_sum[5m])
/
rate(safeshare_upload_size_bytes_count[5m])
```

**Average download size (bytes):**
```promql
rate(safeshare_download_size_bytes_sum[5m])
/
rate(safeshare_download_size_bytes_count[5m])
```

**Upload size distribution (p50, p95, p99):**
```promql
histogram_quantile(0.50, rate(safeshare_upload_size_bytes_bucket[5m]))
histogram_quantile(0.95, rate(safeshare_upload_size_bytes_bucket[5m]))
histogram_quantile(0.99, rate(safeshare_upload_size_bytes_bucket[5m]))
```

### Storage & Capacity Metrics

**Current storage usage (GB):**
```promql
safeshare_storage_used_bytes / 1024 / 1024 / 1024
```

**Storage quota usage percentage:**
```promql
safeshare_storage_quota_used_percent
```

**Active files count:**
```promql
safeshare_active_files_count
```

**Storage growth rate (bytes per hour):**
```promql
rate(safeshare_storage_used_bytes[1h]) * 3600
```

**Estimated time to quota (hours):**
```promql
(safeshare_storage_quota_bytes - safeshare_storage_used_bytes)
/
rate(safeshare_storage_used_bytes[1h])
```

## Grafana Dashboard

### Adding Prometheus Data Source

1. Navigate to **Configuration → Data Sources**
2. Click **Add data source**
3. Select **Prometheus**
4. Set URL: `http://prometheus:9090` (Docker) or `http://localhost:9090` (local)
5. Click **Save & Test**

### Example Dashboard Panels

**Upload/Download Rate Panel:**
```json
{
  "targets": [
    {
      "expr": "rate(safeshare_uploads_total{status=\"success\"}[5m])",
      "legendFormat": "Uploads/sec"
    },
    {
      "expr": "rate(safeshare_downloads_total{status=\"success\"}[5m])",
      "legendFormat": "Downloads/sec"
    }
  ],
  "title": "Upload & Download Rate",
  "type": "graph"
}
```

**Storage Usage Panel (Gauge):**
```json
{
  "targets": [
    {
      "expr": "safeshare_storage_quota_used_percent"
    }
  ],
  "title": "Storage Quota Usage",
  "type": "gauge",
  "options": {
    "min": 0,
    "max": 100,
    "thresholds": {
      "mode": "absolute",
      "steps": [
        { "value": 0, "color": "green" },
        { "value": 70, "color": "yellow" },
        { "value": 90, "color": "red" }
      ]
    }
  }
}
```

**Request Latency Panel (Heatmap):**
```json
{
  "targets": [
    {
      "expr": "rate(safeshare_http_request_duration_seconds_bucket[5m])",
      "format": "heatmap",
      "legendFormat": "{{le}}"
    }
  ],
  "title": "Request Latency Distribution",
  "type": "heatmap"
}
```

**Active Files Panel (Stat):**
```json
{
  "targets": [
    {
      "expr": "safeshare_active_files_count"
    }
  ],
  "title": "Active Files",
  "type": "stat"
}
```

**Error Rate Panel:**
```json
{
  "targets": [
    {
      "expr": "100 * (rate(safeshare_http_requests_total{status=~\"4..|5..\"}[5m]) / rate(safeshare_http_requests_total[5m]))",
      "legendFormat": "Error Rate %"
    }
  ],
  "title": "HTTP Error Rate",
  "type": "graph",
  "yaxes": [
    {
      "format": "percent",
      "max": 100,
      "min": 0
    }
  ]
}
```

## Alerting Rules

### Prometheus Alert Rules

Create an `alerts.yml` file:

```yaml
groups:
  - name: safeshare_alerts
    interval: 30s
    rules:
      # Storage Alerts
      - alert: StorageQuotaNearLimit
        expr: safeshare_storage_quota_used_percent > 90
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "SafeShare storage quota nearly exhausted"
          description: "Storage usage is at {{ $value | humanizePercentage }}. Quota limit will be reached soon."

      - alert: StorageQuotaCritical
        expr: safeshare_storage_quota_used_percent > 95
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "SafeShare storage quota critical"
          description: "Storage usage is at {{ $value | humanizePercentage }}. Immediate action required."

      # Error Rate Alerts
      - alert: HighErrorRate
        expr: |
          100 * (
            rate(safeshare_http_requests_total{status=~"5.."}[5m])
            /
            rate(safeshare_http_requests_total[5m])
          ) > 5
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High error rate detected"
          description: "Error rate is {{ $value | humanizePercentage }} (threshold: 5%)"

      - alert: UploadFailureSpike
        expr: rate(safeshare_uploads_total{status="failure"}[5m]) > 0.1
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Upload failures detected"
          description: "{{ $value | humanize }} upload failures per second"

      # Latency Alerts
      - alert: HighLatency
        expr: |
          histogram_quantile(0.95,
            rate(safeshare_http_request_duration_seconds_bucket[5m])
          ) > 2
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "High request latency detected"
          description: "95th percentile latency is {{ $value | humanizeDuration }}"

      - alert: VeryHighLatency
        expr: |
          histogram_quantile(0.95,
            rate(safeshare_http_request_duration_seconds_bucket[5m])
          ) > 5
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Critical request latency"
          description: "95th percentile latency is {{ $value | humanizeDuration }}"

      # Availability Alerts
      - alert: SafeShareDown
        expr: up{job="safeshare"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "SafeShare instance is down"
          description: "SafeShare has been unreachable for 1 minute"

      # Capacity Alerts
      - alert: RapidStorageGrowth
        expr: |
          predict_linear(safeshare_storage_used_bytes[1h], 24 * 3600)
          >
          safeshare_storage_quota_bytes
        for: 30m
        labels:
          severity: warning
        annotations:
          summary: "Storage quota will be exceeded within 24 hours"
          description: "Current growth rate will exhaust quota in less than 24 hours"

      # Chunked Upload Alerts
      - alert: StalePartialUploads
        expr: safeshare_active_partial_uploads_count > 100
        for: 1h
        labels:
          severity: warning
        annotations:
          summary: "High number of incomplete chunked uploads"
          description: "{{ $value }} partial uploads are active. May indicate upload issues."
```

Add to `prometheus.yml`:
```yaml
rule_files:
  - "alerts.yml"

alerting:
  alertmanagers:
    - static_configs:
        - targets: ['alertmanager:9093']
```

### Alertmanager Configuration

Example `alertmanager.yml`:

```yaml
global:
  resolve_timeout: 5m

route:
  group_by: ['alertname', 'severity']
  group_wait: 10s
  group_interval: 10s
  repeat_interval: 12h
  receiver: 'email'
  routes:
    - match:
        severity: critical
      receiver: 'pagerduty'
      continue: true
    - match:
        severity: warning
      receiver: 'email'

receivers:
  - name: 'email'
    email_configs:
      - to: 'ops@example.com'
        from: 'alertmanager@example.com'
        smarthost: 'smtp.example.com:587'
        auth_username: 'alertmanager@example.com'
        auth_password: 'password'

  - name: 'pagerduty'
    pagerduty_configs:
      - service_key: 'YOUR_PAGERDUTY_SERVICE_KEY'
```

## Production Considerations

### Cardinality Management

**Path Normalization:**
SafeShare automatically normalizes URL paths to prevent cardinality explosion. Dynamic segments (UUIDs, claim codes) are replaced with placeholders:

- `/api/claim/abc123` → `/api/claim/:code`
- `/api/upload/chunk/uuid-1234/5` → `/api/upload/chunk/:id/:number`

**Label Best Practices:**
- Avoid high-cardinality labels (user IDs, IP addresses, timestamps)
- Current labels are carefully chosen for low cardinality
- If extending metrics, ensure new labels have bounded cardinality

### Data Retention

**Prometheus Storage:**
```yaml
# prometheus.yml
storage:
  tsdb:
    retention.time: 30d  # Retain 30 days of metrics
    retention.size: 50GB # Or 50GB, whichever comes first
```

**Disk Space Estimation:**
- Approximate: 1-2 bytes per sample
- SafeShare exposes ~30 metric series
- 15s scrape interval = 4 samples/min = 5,760 samples/day
- Estimated: 30 metrics × 5,760 samples × 30 days × 2 bytes ≈ 10 MB/month

### Performance Impact

**Metrics Collection Overhead:**
- Counter/Histogram increments: ~100-500ns (negligible)
- Gauge collection (database queries): ~1-5ms per scrape
- Default scrape interval: 15s
- Impact: <0.01% CPU overhead

**Database Queries:**
Gauge metrics execute these queries on each scrape:
```sql
SELECT COALESCE(SUM(file_size), 0), COUNT(*) FROM files WHERE expires_at > datetime('now')
SELECT COUNT(*) FROM partial_uploads WHERE completed = 0
```

For large deployments (>100K files), consider:
- Increasing scrape interval to 30s or 60s
- Adding database indexes (already optimized)
- Using a read replica for metrics queries (if needed)

### Security

**Metrics Endpoint:**
- Currently public (no authentication required)
- Metrics don't expose sensitive data (no filenames, claim codes, or IPs)
- For production, consider adding authentication via reverse proxy

**Reverse Proxy Example (nginx):**
```nginx
location /metrics {
    auth_basic "Metrics";
    auth_basic_user_file /etc/nginx/.htpasswd;
    proxy_pass http://safeshare:8080/metrics;
}
```

### High Availability

**Federation:**
For multi-instance deployments, use Prometheus federation:

```yaml
# Global Prometheus
scrape_configs:
  - job_name: 'federate'
    scrape_interval: 15s
    honor_labels: true
    metrics_path: '/federate'
    params:
      'match[]':
        - '{job="safeshare"}'
    static_configs:
      - targets:
        - 'prometheus-region-1:9090'
        - 'prometheus-region-2:9090'
```

**Load Balancer Considerations:**
If using a load balancer, ensure:
- Metrics are aggregated across all instances
- Use `sum()` aggregations in queries:
  ```promql
  sum(rate(safeshare_uploads_total[5m])) by (status)
  ```

## Troubleshooting

### Metrics Not Appearing

**Check endpoint accessibility:**
```bash
curl http://localhost:8080/metrics
```

**Verify Prometheus scrape:**
Navigate to Prometheus → Status → Targets
- Check if SafeShare target is `UP`
- Check last scrape time and errors

**Common issues:**
- Firewall blocking port 8080
- Network connectivity between Prometheus and SafeShare
- Incorrect target configuration in `prometheus.yml`

### Missing Gauge Metrics

Gauge metrics require database queries. If missing:

**Check database connectivity:**
```bash
docker exec safeshare ls -la /app/data/safeshare.db
```

**Check logs for errors:**
```bash
docker logs safeshare | grep -i error
```

### High Cardinality Warnings

If Prometheus shows cardinality warnings:

**Identify high-cardinality metrics:**
```bash
curl http://localhost:9090/api/v1/label/__name__/values | jq .
```

**Check cardinality:**
```promql
count by (__name__) ({__name__=~".+"})
```

SafeShare metrics are designed for low cardinality, but extensions or custom labels could increase it.

## Additional Resources

- [Prometheus Documentation](https://prometheus.io/docs/)
- [Grafana Documentation](https://grafana.com/docs/)
- [PromQL Query Examples](https://prometheus.io/docs/prometheus/latest/querying/examples/)
- [Alerting Best Practices](https://prometheus.io/docs/practices/alerting/)
- [SafeShare GitHub](https://github.com/fjmerc/safeshare)

## Support

For issues or questions:
- GitHub Issues: https://github.com/fjmerc/safeshare/issues
- Documentation: https://github.com/fjmerc/safeshare/tree/main/docs
