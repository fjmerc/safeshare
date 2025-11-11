#!/bin/bash
# SafeShare Database Maintenance Script
#
# Purpose: Weekly database optimization tasks
# - VACUUM: Reclaim disk space from deleted files
# - ANALYZE: Update query planner statistics
# - Checkpoint: Force WAL checkpoint
# - Integrity check: Verify database health
#
# Usage:
#   ./scripts/db-maintenance.sh
#
# Recommended: Run weekly via cron
#   0 3 * * 0 /path/to/safeshare/scripts/db-maintenance.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Configuration
CONTAINER_NAME="${CONTAINER_NAME:-safeshare}"
DB_PATH="${DB_PATH:-/app/data/safeshare.db}"
LOG_FILE="${PROJECT_ROOT}/db-maintenance.log"

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a "$LOG_FILE"
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING:${NC} $1" | tee -a "$LOG_FILE"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR:${NC} $1" | tee -a "$LOG_FILE"
    exit 1
}

# Check if container is running
if ! docker ps | grep -q "$CONTAINER_NAME"; then
    error "Container '$CONTAINER_NAME' is not running"
fi

log "Starting database maintenance for SafeShare..."

# 1. Database integrity check
log "Step 1/5: Running integrity check..."
if docker exec "$CONTAINER_NAME" sqlite3 "$DB_PATH" "PRAGMA integrity_check;" | grep -q "ok"; then
    log "✓ Integrity check passed"
else
    error "✗ Integrity check failed!"
fi

# 2. Get database size before maintenance
DB_SIZE_BEFORE=$(docker exec "$CONTAINER_NAME" sh -c "du -h $DB_PATH | cut -f1")
log "Step 2/5: Current database size: $DB_SIZE_BEFORE"

# 3. Force WAL checkpoint (flush writes to main database)
log "Step 3/5: Checkpointing WAL..."
docker exec "$CONTAINER_NAME" sqlite3 "$DB_PATH" "PRAGMA wal_checkpoint(TRUNCATE);" > /dev/null
log "✓ WAL checkpoint completed"

# 4. Update query planner statistics
log "Step 4/5: Updating query planner statistics..."
docker exec "$CONTAINER_NAME" sqlite3 "$DB_PATH" "ANALYZE;" > /dev/null
log "✓ Statistics updated"

# 5. Reclaim unused disk space (VACUUM)
log "Step 5/5: Reclaiming disk space (VACUUM)..."
log "  Note: This may take several minutes for large databases..."

# VACUUM requires exclusive lock - do this when traffic is low
docker exec "$CONTAINER_NAME" sqlite3 "$DB_PATH" "VACUUM;" > /dev/null
log "✓ VACUUM completed"

# Get database size after maintenance
DB_SIZE_AFTER=$(docker exec "$CONTAINER_NAME" sh -c "du -h $DB_PATH | cut -f1")
log "Database size after maintenance: $DB_SIZE_AFTER"

# Calculate space reclaimed
log "✅ Database maintenance completed successfully!"
log "   Before: $DB_SIZE_BEFORE"
log "   After:  $DB_SIZE_AFTER"
log ""
log "Next steps:"
log "  - Check application logs for any errors"
log "  - Verify admin dashboard loads correctly"
log "  - Monitor query performance"

# Clean up old log entries (keep last 30 days)
find "$PROJECT_ROOT" -name "db-maintenance.log" -mtime +30 -delete 2>/dev/null || true

log "Maintenance log saved to: $LOG_FILE"
