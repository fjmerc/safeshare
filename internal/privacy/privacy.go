package privacy

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
