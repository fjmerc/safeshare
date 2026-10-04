package models

// AuditEventType groups audit events for filtering.
type AuditEventType string

const (
	AuditEventAuth     AuditEventType = "AUTH"     // logins, MFA, sessions, passwords
	AuditEventFile     AuditEventType = "FILE"     // uploads, downloads, deletions
	AuditEventAdmin    AuditEventType = "ADMIN"    // admin actions on users, files, tokens, backups
	AuditEventSecurity AuditEventType = "SECURITY" // malware verdicts, denied downloads, audit log verify/export
	AuditEventConfig   AuditEventType = "CONFIG"   // settings changes
	AuditEventSystem   AuditEventType = "SYSTEM"   // audit log maintenance (retention prunes)
)

// AuditOutcome is the result of an audited action.
type AuditOutcome string

const (
	AuditOutcomeSuccess AuditOutcome = "SUCCESS"
	AuditOutcomeFailure AuditOutcome = "FAILURE" // e.g. wrong password
	AuditOutcomeDenied  AuditOutcome = "DENIED"  // e.g. disabled account, malware, forbidden
)

// AuditLog is one entry in the tamper-evident audit log (ADR-018).
//
// Every field is stored exactly as it is hashed: the timestamp as a
// fixed-width RFC 3339 UTC string with microseconds, Details as the JSON
// text, and "" (never NULL) for an absent value. That keeps an entry read
// back from either database byte-identical to the one that was signed.
type AuditLog struct {
	ID           int64        `json:"id"`
	Timestamp    string       `json:"timestamp"`
	EventType    AuditEventType `json:"event_type"`
	Action       string       `json:"action"`
	Outcome      AuditOutcome `json:"outcome"`
	UserID       string       `json:"user_id,omitempty"` // decimal, or "" for none
	Username     string       `json:"username,omitempty"`
	IPAddress    string       `json:"ip_address,omitempty"`
	UserAgent    string       `json:"user_agent,omitempty"`
	ResourceType string       `json:"resource_type,omitempty"`
	ResourceID   string       `json:"resource_id,omitempty"`
	Details      string       `json:"details,omitempty"` // JSON object, or ""
	PrevHash     string       `json:"prev_hash"`
	EntryHash    string       `json:"entry_hash"`
	KeyID        string       `json:"key_id"` // identifies the signing key, not secret
}

// AuditLogFilter selects entries for listing and export.
type AuditLogFilter struct {
	EventType    AuditEventType
	Outcome      AuditOutcome
	Action       string // exact
	Username     string // exact
	IPAddress    string // exact
	ResourceType string
	ResourceID   string
	Since        string // inclusive, same timestamp format as AuditLog.Timestamp
	Until        string // exclusive
	Search       string // substring of action, username, resource id or details
	BeforeID     int64  // only entries with a smaller id (keyset pagination)
	Limit        int
}

// AuditAnchor is where the verifiable chain starts once old entries have
// been pruned by retention: the id and hash of the last pruned entry.
type AuditAnchor struct {
	ID   int64
	Hash string
}
