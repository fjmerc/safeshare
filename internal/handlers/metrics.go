package handlers

import (
	"database/sql"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/fjmerc/safeshare/internal/config"
	"github.com/fjmerc/safeshare/internal/metrics"
)

// MetricsHandler returns an HTTP handler for Prometheus metrics endpoint
func MetricsHandler(db *sql.DB, cfg *config.Config) http.Handler {
	// Create and register database metrics collector
	collector := metrics.NewDatabaseMetricsCollector(db, cfg.QuotaLimitGB())
	prometheus.MustRegister(collector)

	// Return promhttp handler
	return promhttp.Handler()
}
