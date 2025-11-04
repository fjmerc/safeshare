package middleware

import (
	"net/http"
)

// SecurityHeadersMiddleware adds security-related HTTP headers to all responses
// These headers protect against:
// - Clickjacking (X-Frame-Options)
// - MIME sniffing attacks (X-Content-Type-Options)
// - Cross-site scripting (Content-Security-Policy, X-XSS-Protection)
// - Information leakage (X-Content-Type-Options)
func SecurityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Prevent clickjacking: don't allow this page to be embedded in iframes
		w.Header().Set("X-Frame-Options", "DENY")

		// Prevent MIME sniffing: browser must respect Content-Type header
		// This prevents attackers from uploading .txt files that execute as JavaScript
		w.Header().Set("X-Content-Type-Options", "nosniff")

		// Content Security Policy: Restrict what resources can be loaded
		// This is a strict policy that prevents inline scripts and restricts resource loading
		csp := "default-src 'self'; " +
			"script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; " + // Allow QR code library
			"style-src 'self' 'unsafe-inline'; " + // Allow inline styles
			"img-src 'self' data: blob:; " + // Allow data URLs for QR codes
			"font-src 'self'; " +
			"connect-src 'self'; " +
			"frame-ancestors 'none'; " + // Equivalent to X-Frame-Options: DENY
			"base-uri 'self'; " +
			"form-action 'self'"
		w.Header().Set("Content-Security-Policy", csp)

		// XSS Protection: Enable browser's XSS filter
		// Most modern browsers have this enabled by default, but we set it explicitly
		w.Header().Set("X-XSS-Protection", "1; mode=block")

		// Referrer Policy: Don't send referrer information to external sites
		// This prevents leaking claim codes in referrer headers
		w.Header().Set("Referrer-Policy", "same-origin")

		// Permissions Policy: Disable unnecessary browser features
		// This reduces attack surface by disabling features like camera, microphone, geolocation
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), interest-cohort=()")

		// Call the next handler
		next.ServeHTTP(w, r)
	})
}
