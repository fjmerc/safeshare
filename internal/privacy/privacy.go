package privacy

import "sync/atomic"

// processAnonymous is the process-wide anonymous-mode switch used by log
// call sites that have no config in scope (utils, middleware, storage).
// main.go sets it once at startup; tests that flip it must restore it.
var processAnonymous atomic.Bool

// SetAnonymousMode sets the process-wide anonymous-mode switch.
func SetAnonymousMode(enabled bool) { processAnonymous.Store(enabled) }

// AnonymousMode reports the process-wide anonymous-mode switch.
func AnonymousMode() bool { return processAnonymous.Load() }

// LogFilename redacts a filename for log output per the process-wide switch.
func LogFilename(name string) string { return RedactFilename(name, AnonymousMode()) }

// LogPath redacts a request path for log output per the process-wide switch.
func LogPath(path string) string { return RedactPath(path, AnonymousMode()) }

// LogHash returns "" (log nothing identifying) for a plaintext-derived hash
// prefix in anonymous mode.
func LogHash(h string) string {
	if AnonymousMode() {
		return "[redacted]"
	}
	return h
}

// AnonymizeIP returns "anonymous" if anonymous mode is enabled,
// otherwise returns the original IP. Used for database storage.
func AnonymizeIP(ip string, anonymousMode bool) string {
	if anonymousMode {
		return "anonymous"
	}
	return ip
}

// RedactIP returns "redacted" if anonymous mode is enabled,
// otherwise returns the original IP. Used for log output.
func RedactIP(ip string, anonymousMode bool) string {
	if anonymousMode {
		return "redacted"
	}
	return ip
}

// RedactUsername returns "redacted" if anonymous mode is enabled,
// otherwise returns the original username. Used for log output of a
// username a client submitted (e.g. on a login attempt), which may be
// mistyped, belong to no account, or even be a password typed into the
// wrong field.
func RedactUsername(username string, anonymousMode bool) string {
	if anonymousMode {
		return "redacted"
	}
	return username
}

// AnonymizeUserAgent returns an empty string if anonymous mode is enabled,
// otherwise returns the original User-Agent. Used for database storage: a
// user agent is a fingerprinting signal and must not be kept in anonymous mode.
func AnonymizeUserAgent(ua string, anonymousMode bool) string {
	if anonymousMode {
		return ""
	}
	return ua
}

// RedactUserAgent returns "redacted" if anonymous mode is enabled,
// otherwise returns the original User-Agent. Used for log output.
func RedactUserAgent(ua string, anonymousMode bool) string {
	if anonymousMode {
		return "redacted"
	}
	return ua
}

// RedactFilename returns "[redacted]" if anonymous mode is enabled,
// otherwise returns the original filename. Used for log output only;
// filenames stored in the database are unchanged.
func RedactFilename(name string, anonymousMode bool) string {
	if anonymousMode {
		return "[redacted]"
	}
	return name
}

// RedactPath returns only the route prefix of a request path (the first
// segment, e.g. "/api" for "/api/claim/AbC123") if anonymous mode is
// enabled, otherwise the full path. Used for log output: claim codes are
// bearer secrets embedded in URL paths.
func RedactPath(path string, anonymousMode bool) string {
	if !anonymousMode {
		return path
	}
	if len(path) == 0 {
		return path
	}
	trimmed := path[1:]
	for i := 0; i < len(trimmed); i++ {
		if trimmed[i] == '/' {
			return "/" + trimmed[:i] + "/[redacted]"
		}
	}
	return path
}
