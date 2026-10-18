package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"filippo.io/age"
)

// Defaults for the no-JavaScript drop page (see docs/DROP_PAGE.md).
const (
	defaultDropMaxSize         = 50 * 1024 * 1024 // whole file is held in memory
	defaultDropMaxConcurrent   = 2
	defaultDropExpirationHours = 168 // a week: a drop made on Friday night must survive the weekend
)

// DropConfig configures the no-JavaScript drop page at /drop: a plain HTML
// form for senders who can't run (or trust) the server's JavaScript. The
// server encrypts each upload to Recipient before storing it, so only the
// holder of the matching age identity can read it. The page is off unless
// DROP_RECIPIENT is set.
type DropConfig struct {
	// Recipient is the age public key every drop is encrypted to
	// (DROP_RECIPIENT, "age1…" or post-quantum "age1pq1…"). nil = drop off.
	Recipient age.Recipient
	// RecipientKey is DROP_RECIPIENT as given, for display. It is a public
	// key, so it is safe to show and log.
	RecipientKey string
	// MaxSize caps one drop in bytes (DROP_MAX_SIZE, default 50 MB). The
	// whole file is held in memory, so it is also capped by MAX_FILE_SIZE
	// when a drop arrives.
	MaxSize int64
	// MaxConcurrent caps how many drops are processed at once
	// (DROP_MAX_CONCURRENT, default 2); more get 503. Memory use is roughly
	// MaxConcurrent × 3 × MaxSize.
	MaxConcurrent int
	// ExpirationHours is how long a drop is kept (DROP_EXPIRATION_HOURS,
	// default 168), capped by MAX_EXPIRATION_HOURS when it arrives.
	ExpirationHours int
}

// Enabled reports whether the drop page is on.
func (d DropConfig) Enabled() bool { return d.Recipient != nil }

// loadDropConfig reads the DROP_* settings. Unlike most settings, a value
// that doesn't parse is an error rather than silently replaced by the
// default: these control where sources' files go and how much memory they
// may use.
func loadDropConfig() (DropConfig, error) {
	d := DropConfig{
		MaxSize:         defaultDropMaxSize,
		MaxConcurrent:   defaultDropMaxConcurrent,
		ExpirationHours: defaultDropExpirationHours,
	}

	if key := strings.TrimSpace(os.Getenv("DROP_RECIPIENT")); key != "" {
		r, err := parseDropRecipient(key)
		if err != nil {
			return d, err
		}
		d.Recipient, d.RecipientKey = r, key
	}

	var err error
	if d.MaxSize, err = positiveEnvInt64("DROP_MAX_SIZE", d.MaxSize); err != nil {
		return d, err
	}
	n, err := positiveEnvInt64("DROP_MAX_CONCURRENT", int64(d.MaxConcurrent))
	if err != nil {
		return d, err
	}
	if n > 64 {
		return d, fmt.Errorf("DROP_MAX_CONCURRENT must be at most 64, got %d", n)
	}
	d.MaxConcurrent = int(n)
	if n, err = positiveEnvInt64("DROP_EXPIRATION_HOURS", int64(d.ExpirationHours)); err != nil {
		return d, err
	}
	if n > 100*365*24 {
		return d, fmt.Errorf("DROP_EXPIRATION_HOURS is too large: %d", n)
	}
	d.ExpirationHours = int(n)
	return d, nil
}

// parseDropRecipient accepts exactly one native age public key. Plugin and
// SSH recipients are refused: plugins run external programs, and one key per
// server keeps it clear who can read the drops.
func parseDropRecipient(key string) (age.Recipient, error) {
	switch {
	case strings.HasPrefix(strings.ToUpper(key), "AGE-SECRET-KEY-"), strings.HasPrefix(strings.ToUpper(key), "AGE-PLUGIN-"):
		// Never echo the value: it is a private key.
		return nil, fmt.Errorf("DROP_RECIPIENT holds an age PRIVATE key; it must be the public key (age1…, printed by age-keygen -y). Keep the private key off this server, and treat this one as exposed")
	case strings.HasPrefix(key, "age1pq1"):
		r, err := age.ParseHybridRecipient(key)
		if err != nil {
			return nil, fmt.Errorf("DROP_RECIPIENT is not a valid age post-quantum public key: %w", err)
		}
		return r, nil
	case strings.HasPrefix(key, "age1") && !strings.ContainsAny(key, " \t,\n"):
		r, err := age.ParseX25519Recipient(key)
		if err != nil {
			return nil, fmt.Errorf("DROP_RECIPIENT is not a valid age public key: %w", err)
		}
		return r, nil
	default:
		return nil, fmt.Errorf("DROP_RECIPIENT must be one age public key (age1… or age1pq1…)")
	}
}

// positiveEnvInt64 reads a positive integer setting, failing closed on a
// value that doesn't parse or isn't positive.
func positiveEnvInt64(name string, def int64) (int64, error) {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return def, nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("%s must be a positive whole number, got %q", name, v)
	}
	return n, nil
}
