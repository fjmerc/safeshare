package utils

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const testPreEtag = `"abc123def456"`

var testPreModTime = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

func TestEvaluatePreconditions_NoHeaders(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	out := EvaluatePreconditions(r, testPreEtag, testPreModTime)
	if out.Status != 0 {
		t.Errorf("Status = %d, want 0 (no precondition headers)", out.Status)
	}
}

func TestEvaluatePreconditions_IfMatch(t *testing.T) {
	tests := []struct {
		name   string
		header string
		want   int
	}{
		{"matching single value", testPreEtag, 0},
		{"matching in a list", `"other", ` + testPreEtag, 0},
		{"wildcard", "*", 0},
		{"non-matching", `"nope"`, http.StatusPreconditionFailed},
		{"weak validator never matches strong comparison", "W/" + testPreEtag, http.StatusPreconditionFailed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/x", nil)
			r.Header.Set("If-Match", tt.header)
			out := EvaluatePreconditions(r, testPreEtag, testPreModTime)
			if out.Status != tt.want {
				t.Errorf("Status = %d, want %d", out.Status, tt.want)
			}
		})
	}
}

func TestEvaluatePreconditions_IfUnmodifiedSince(t *testing.T) {
	tests := []struct {
		name string
		t    time.Time
		want int
	}{
		{"resource unchanged (t == modTime)", testPreModTime, 0},
		{"resource unchanged (t after modTime)", testPreModTime.Add(time.Hour), 0},
		{"resource modified since (t before modTime)", testPreModTime.Add(-time.Hour), http.StatusPreconditionFailed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/x", nil)
			r.Header.Set("If-Unmodified-Since", tt.t.Format(http.TimeFormat))
			out := EvaluatePreconditions(r, testPreEtag, testPreModTime)
			if out.Status != tt.want {
				t.Errorf("Status = %d, want %d", out.Status, tt.want)
			}
		})
	}
}

func TestEvaluatePreconditions_IfMatchTakesPrecedenceOverIfUnmodifiedSince(t *testing.T) {
	// If-Match present (and passing) means If-Unmodified-Since must not be
	// separately evaluated, even if it would have failed on its own.
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	r.Header.Set("If-Match", testPreEtag)
	r.Header.Set("If-Unmodified-Since", testPreModTime.Add(-time.Hour).Format(http.TimeFormat))
	out := EvaluatePreconditions(r, testPreEtag, testPreModTime)
	if out.Status != 0 {
		t.Errorf("Status = %d, want 0 (If-Match should have short-circuited If-Unmodified-Since)", out.Status)
	}
}

func TestEvaluatePreconditions_IfNoneMatch(t *testing.T) {
	tests := []struct {
		name   string
		method string
		header string
		want   int
	}{
		{"matching, GET -> 304", http.MethodGet, testPreEtag, http.StatusNotModified},
		{"matching, HEAD -> 304", http.MethodHead, testPreEtag, http.StatusNotModified},
		{"matching, POST -> 412", http.MethodPost, testPreEtag, http.StatusPreconditionFailed},
		{"wildcard, GET -> 304", http.MethodGet, "*", http.StatusNotModified},
		{"weak match allowed, GET -> 304", http.MethodGet, "W/" + testPreEtag, http.StatusNotModified},
		{"non-matching, GET -> proceed", http.MethodGet, `"nope"`, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(tt.method, "/x", nil)
			r.Header.Set("If-None-Match", tt.header)
			out := EvaluatePreconditions(r, testPreEtag, testPreModTime)
			if out.Status != tt.want {
				t.Errorf("Status = %d, want %d", out.Status, tt.want)
			}
		})
	}
}

func TestEvaluatePreconditions_IfModifiedSince(t *testing.T) {
	tests := []struct {
		name string
		t    time.Time
		want int
	}{
		{"not modified since (t == modTime)", testPreModTime, http.StatusNotModified},
		{"not modified since (t after modTime)", testPreModTime.Add(time.Hour), http.StatusNotModified},
		{"modified since (t before modTime)", testPreModTime.Add(-time.Hour), 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/x", nil)
			r.Header.Set("If-Modified-Since", tt.t.Format(http.TimeFormat))
			out := EvaluatePreconditions(r, testPreEtag, testPreModTime)
			if out.Status != tt.want {
				t.Errorf("Status = %d, want %d", out.Status, tt.want)
			}
		})
	}
}

func TestEvaluatePreconditions_IfModifiedSinceIgnoredForNonGetHead(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/x", nil)
	r.Header.Set("If-Modified-Since", testPreModTime.Format(http.TimeFormat))
	out := EvaluatePreconditions(r, testPreEtag, testPreModTime)
	if out.Status != 0 {
		t.Errorf("Status = %d, want 0 (If-Modified-Since only applies to GET/HEAD)", out.Status)
	}
}

func TestEvaluatePreconditions_IfNoneMatchTakesPrecedenceOverIfModifiedSince(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	r.Header.Set("If-None-Match", `"nope"`) // does not match -> proceed to check If-Modified-Since? No: precedence means IMS is skipped entirely when INM is present.
	r.Header.Set("If-Modified-Since", testPreModTime.Format(http.TimeFormat))
	out := EvaluatePreconditions(r, testPreEtag, testPreModTime)
	if out.Status != 0 {
		t.Errorf("Status = %d, want 0 (If-None-Match present should short-circuit If-Modified-Since entirely, even when INM itself doesn't match)", out.Status)
	}
}

// TestEvaluatePreconditions_ZeroModTimeIsNoCondition matches net/http's own
// isZeroTime behavior exactly (security-audit finding, round 3: an earlier
// version of this function treated an unknown modTime as always failing
// If-Unmodified-Since, i.e. 412, which is not what net/http does): with a
// zero (or Unix-epoch) modTime, both If-Unmodified-Since and
// If-Modified-Since are simply not evaluated at all — "no condition," as if
// the header weren't sent — not "always fails" or "always matches."
func TestEvaluatePreconditions_ZeroModTimeIsNoCondition(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	r.Header.Set("If-Modified-Since", testPreModTime.Format(http.TimeFormat))
	out := EvaluatePreconditions(r, testPreEtag, time.Time{})
	if out.Status != 0 {
		t.Errorf("Status = %d, want 0 (a zero modTime must be treated as no condition for If-Modified-Since)", out.Status)
	}

	r2 := httptest.NewRequest(http.MethodGet, "/x", nil)
	r2.Header.Set("If-Unmodified-Since", testPreModTime.Format(http.TimeFormat))
	out2 := EvaluatePreconditions(r2, testPreEtag, time.Time{})
	if out2.Status != 0 {
		t.Errorf("Status = %d, want 0 (a zero modTime must be treated as no condition for If-Unmodified-Since, not 412)", out2.Status)
	}

	// Unix-epoch (not just the Go zero value) must be treated identically.
	r3 := httptest.NewRequest(http.MethodGet, "/x", nil)
	r3.Header.Set("If-Unmodified-Since", testPreModTime.Format(http.TimeFormat))
	out3 := EvaluatePreconditions(r3, testPreEtag, time.Unix(0, 0))
	if out3.Status != 0 {
		t.Errorf("Status = %d, want 0 (Unix-epoch modTime must also be treated as no condition)", out3.Status)
	}
}

// TestEvaluatePreconditions_MatchesStdlibServeContent is a permanent
// differential test (security-audit finding, round 3): it runs a table of
// header combinations through both EvaluatePreconditions and the real
// http.ServeContent (on a request with no Range header at all, so it is
// always Range-satisfiable — any difference in outcome is therefore
// attributable purely to precondition handling, never to a Range decision)
// and asserts they agree. This is what guards against EvaluatePreconditions
// drifting from net/http's actual behavior — whether from a mistake in this
// port or from a future Go stdlib change to checkPreconditions itself.
func TestEvaluatePreconditions_MatchesStdlibServeContent(t *testing.T) {
	cases := []struct {
		name    string
		method  string
		headers map[string]string
		// modTime overrides testPreModTime for this case when non-zero
		// (the IsZero test case itself needs to pass an explicit,
		// deliberately-zero override, so "unset" is distinguished by a
		// separate bool rather than by the zero value being ambiguous).
		modTime    time.Time
		useModTime bool
	}{
		{name: "no headers", method: http.MethodGet},
		{name: "if-match matching", method: http.MethodGet, headers: map[string]string{"If-Match": testPreEtag}},
		{name: "if-match non-matching", method: http.MethodGet, headers: map[string]string{"If-Match": `"nope"`}},
		{name: "if-match wildcard", method: http.MethodGet, headers: map[string]string{"If-Match": "*"}},
		{name: "if-match weak never matches", method: http.MethodGet, headers: map[string]string{"If-Match": "W/" + testPreEtag}},
		{name: "if-match malformed value", method: http.MethodGet, headers: map[string]string{"If-Match": "not-a-valid-etag"}},
		{name: "if-match multiple values, second matches", method: http.MethodGet, headers: map[string]string{"If-Match": `"nope", ` + testPreEtag}},
		{name: "if-match multiple values, none match", method: http.MethodGet, headers: map[string]string{"If-Match": `"nope", "also-nope"`}},
		{name: "if-unmodified-since not modified", method: http.MethodGet, headers: map[string]string{"If-Unmodified-Since": testPreModTime.Format(http.TimeFormat)}},
		{name: "if-unmodified-since modified", method: http.MethodGet, headers: map[string]string{"If-Unmodified-Since": testPreModTime.Add(-time.Hour).Format(http.TimeFormat)}},
		{name: "if-unmodified-since malformed date", method: http.MethodGet, headers: map[string]string{"If-Unmodified-Since": "not-a-date"}},
		{name: "if-match present skips if-unmodified-since", method: http.MethodGet, headers: map[string]string{"If-Match": testPreEtag, "If-Unmodified-Since": testPreModTime.Add(-time.Hour).Format(http.TimeFormat)}},
		{name: "if-none-match matching get", method: http.MethodGet, headers: map[string]string{"If-None-Match": testPreEtag}},
		{name: "if-none-match matching head", method: http.MethodHead, headers: map[string]string{"If-None-Match": testPreEtag}},
		{name: "if-none-match matching post", method: http.MethodPost, headers: map[string]string{"If-None-Match": testPreEtag}},
		{name: "if-none-match non-matching", method: http.MethodGet, headers: map[string]string{"If-None-Match": `"nope"`}},
		{name: "if-none-match wildcard", method: http.MethodGet, headers: map[string]string{"If-None-Match": "*"}},
		{name: "if-none-match weak match", method: http.MethodGet, headers: map[string]string{"If-None-Match": "W/" + testPreEtag}},
		{name: "if-none-match malformed value", method: http.MethodGet, headers: map[string]string{"If-None-Match": "not-a-valid-etag"}},
		{name: "if-modified-since not modified get", method: http.MethodGet, headers: map[string]string{"If-Modified-Since": testPreModTime.Format(http.TimeFormat)}},
		{name: "if-modified-since modified get", method: http.MethodGet, headers: map[string]string{"If-Modified-Since": testPreModTime.Add(-time.Hour).Format(http.TimeFormat)}},
		{name: "if-modified-since ignored for post", method: http.MethodPost, headers: map[string]string{"If-Modified-Since": testPreModTime.Format(http.TimeFormat)}},
		{name: "if-none-match present skips if-modified-since", method: http.MethodGet, headers: map[string]string{"If-None-Match": `"nope"`, "If-Modified-Since": testPreModTime.Format(http.TimeFormat)}},
		{name: "if-match failing takes precedence over if-none-match", method: http.MethodGet, headers: map[string]string{"If-Match": `"nope"`, "If-None-Match": testPreEtag}},

		// --- round-4 additions -----------------------------------------

		// Zero/epoch modTime: date-based conditions must be "no condition"
		// (proceed as GET normally would), not "always fails"/"always
		// matches" — see TestEvaluatePreconditions_ZeroModTimeIsNoCondition
		// for the unit-level version of this; here it's checked against
		// real http.ServeContent too.
		{name: "zero modtime with if-modified-since", method: http.MethodGet, headers: map[string]string{"If-Modified-Since": testPreModTime.Format(http.TimeFormat)}, modTime: time.Time{}, useModTime: true},
		{name: "zero modtime with if-unmodified-since", method: http.MethodGet, headers: map[string]string{"If-Unmodified-Since": testPreModTime.Format(http.TimeFormat)}, modTime: time.Time{}, useModTime: true},
		{name: "unix-epoch modtime with if-modified-since", method: http.MethodGet, headers: map[string]string{"If-Modified-Since": testPreModTime.Format(http.TimeFormat)}, modTime: time.Unix(0, 0), useModTime: true},

		// Sub-second CreatedAt: both sides must truncate to whole seconds
		// before comparing (Last-Modified itself has no sub-second
		// precision), so a modTime with sub-second jitter still compares
		// equal to an If-*-Since header naming the truncated second.
		{name: "sub-second modtime, if-modified-since names the truncated second", method: http.MethodGet, headers: map[string]string{"If-Modified-Since": testPreModTime.Format(http.TimeFormat)}, modTime: testPreModTime.Add(500 * time.Millisecond), useModTime: true},
		{name: "sub-second modtime, if-unmodified-since names the truncated second", method: http.MethodGet, headers: map[string]string{"If-Unmodified-Since": testPreModTime.Format(http.TimeFormat)}, modTime: testPreModTime.Add(999 * time.Millisecond), useModTime: true},

		// If-Unmodified-Since passing (condNone/condTrue, not condFalse)
		// must NOT itself short-circuit the later If-None-Match check —
		// only If-Match does that (via checkIfMatch, not
		// checkIfUnmodifiedSince). This combination wasn't covered above
		// (which only tested If-Match+If-Unmodified-Since and
		// If-None-Match+If-Modified-Since together).
		{name: "if-unmodified-since passes, if-none-match also matches", method: http.MethodGet, headers: map[string]string{"If-Unmodified-Since": testPreModTime.Format(http.TimeFormat), "If-None-Match": testPreEtag}},

		// Whitespace/empty-element/comma-only ETag lists.
		{name: "if-match list with extra spaces around comma", method: http.MethodGet, headers: map[string]string{"If-Match": `"nope" ,  ` + testPreEtag}},
		{name: "if-match list with tabs around comma", method: http.MethodGet, headers: map[string]string{"If-Match": "\"nope\"\t,\t" + testPreEtag}},
		{name: "if-match comma-only list (no elements)", method: http.MethodGet, headers: map[string]string{"If-Match": ","}},
		{name: "if-match whitespace-only list", method: http.MethodGet, headers: map[string]string{"If-Match": "   "}},
		{name: "if-none-match list with extra spaces around comma", method: http.MethodGet, headers: map[string]string{"If-None-Match": `"nope" ,  ` + testPreEtag}},
		{name: "if-none-match comma-only list", method: http.MethodGet, headers: map[string]string{"If-None-Match": ","}},

		// Trailing garbage after a syntactically complete, matching ETag:
		// scanETag must stop at the closing quote and still match,
		// ignoring whatever follows rather than treating the whole value
		// as unparseable.
		{name: "if-match trailing garbage after a matching etag", method: http.MethodGet, headers: map[string]string{"If-Match": testPreEtag + " junk"}},
		{name: "if-none-match trailing garbage after a matching etag", method: http.MethodGet, headers: map[string]string{"If-None-Match": testPreEtag + " junk"}},

		// Lowercase "w/" is not the RFC 9110 weak indicator (which is
		// case-sensitive, always "W/") — must be treated as a malformed
		// entry, not silently accepted as a weak match.
		{name: "if-none-match lowercase w/ prefix is not a weak match", method: http.MethodGet, headers: map[string]string{"If-None-Match": "w/" + testPreEtag}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			modTime := testPreModTime
			if tc.useModTime {
				modTime = tc.modTime
			}

			req1 := httptest.NewRequest(tc.method, "/x", nil)
			for k, v := range tc.headers {
				req1.Header.Set(k, v)
			}
			out := EvaluatePreconditions(req1, testPreEtag, modTime)
			wantStatus := out.Status
			if wantStatus == 0 {
				wantStatus = http.StatusOK
			}

			req2 := httptest.NewRequest(tc.method, "/x", nil)
			for k, v := range tc.headers {
				req2.Header.Set(k, v)
			}
			rr := httptest.NewRecorder()
			// Mirrors exactly how claim_range.go prepares a response before
			// calling http.ServeContent: Content-Type set explicitly (so it
			// never sniffs), ETag set from the same value passed to
			// EvaluatePreconditions.
			rr.Header().Set("Content-Type", "text/plain")
			rr.Header().Set("ETag", testPreEtag)
			content := strings.NewReader("hello world")
			http.ServeContent(rr, req2, "test.txt", modTime, content)

			if rr.Code != wantStatus {
				t.Errorf("%s %v (modTime=%v): EvaluatePreconditions wants status %d, http.ServeContent produced %d", tc.method, tc.headers, modTime, wantStatus, rr.Code)
			}
		})
	}
}
