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
