package handlers

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/fjmerc/safeshare/internal/audit"
	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/utils"
)

func appendAuditEntries(t *testing.T, env *auditEnv, n int, username string) {
	t.Helper()
	for i := 0; i < n; i++ {
		if _, err := env.logger.Append(context.Background(), audit.Entry{
			Type: models.AuditEventAuth, Action: "login", Outcome: models.AuditOutcomeFailure, Username: username,
		}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestAdminAuditLogs_ListPagination(t *testing.T) {
	env := newAuditEnv(t)
	appendAuditEntries(t, env, 120, "pager")
	h := AdminAuditLogsHandler(env.repos, env.cfg)

	var seen []int64
	beforeID := ""
	for pages := 0; pages < 5; pages++ {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/admin/api/audit-logs?limit=50"+beforeID, nil))
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d: %s", rr.Code, rr.Body)
		}
		var resp struct {
			Entries      []models.AuditLog `json:"entries"`
			NextBeforeID int64             `json:"next_before_id"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		for _, e := range resp.Entries {
			seen = append(seen, e.ID)
		}
		if resp.NextBeforeID == 0 {
			break
		}
		beforeID = "&before_id=" + strconv.FormatInt(resp.NextBeforeID, 10)
	}
	if len(seen) != 120 || seen[0] != 120 || seen[119] != 1 {
		t.Fatalf("paged through %d entries (%v ... %v), want 120..1", len(seen), seen[0], seen[len(seen)-1])
	}

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/admin/api/audit-logs?since=yesterday", nil))
	if rr.Code != http.StatusBadRequest {
		t.Errorf("bad since: status = %d, want 400", rr.Code)
	}
}

func TestAdminAuditLogs_Retention(t *testing.T) {
	env := newAuditEnv(t)
	h := AdminAuditLogsRetentionHandler(env.repos, env.cfg)
	put := func(body string) int {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPut, "/admin/api/audit-logs/retention", strings.NewReader(body))
		h.ServeHTTP(rr, req)
		return rr.Code
	}
	for body, want := range map[string]int{
		`{"retention_days":0}`:     http.StatusOK,
		`{"retention_days":30}`:    http.StatusOK,
		`{"retention_days":36500}`: http.StatusOK,
		`{"retention_days":29}`:    http.StatusBadRequest,
		`{"retention_days":36501}`: http.StatusBadRequest,
		`{"retention_days":-1}`:    http.StatusBadRequest,
		`{}`:                       http.StatusBadRequest,
		`not json`:                 http.StatusBadRequest,
	} {
		if got := put(body); got != want {
			t.Errorf("PUT %s = %d, want %d", body, got, want)
		}
	}
	days, _ := env.repos.AuditLogs.RetentionDays(context.Background())
	if days != 36500 && days != 30 && days != 0 {
		t.Errorf("stored retention = %d", days)
	}
	if got := len(env.find(t, "audit_log_retention_update", models.AuditOutcomeSuccess)); got != 3 {
		t.Errorf("retention changes recorded = %d, want 3", got)
	}
}

func TestAdminAuditLogs_ExportCSV(t *testing.T) {
	env := newAuditEnv(t)
	appendAuditEntries(t, env, 3, "=HYPERLINK(\"http://evil\")")
	old := maxAuditExport
	defer func() { maxAuditExport = old }()

	export := func() [][]string {
		rr := httptest.NewRecorder()
		AdminAuditLogsExportHandler(env.repos, env.cfg).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/admin/api/audit-logs/export?format=csv&action=login", nil))
		if rr.Code != http.StatusOK || !strings.Contains(rr.Header().Get("Content-Disposition"), "attachment") {
			t.Fatalf("export status = %d, disposition %q", rr.Code, rr.Header().Get("Content-Disposition"))
		}
		r := csv.NewReader(bytes.NewReader(rr.Body.Bytes()))
		r.FieldsPerRecord = -1
		rows, err := r.ReadAll()
		if err != nil {
			t.Fatal(err)
		}
		return rows
	}

	rows := export()
	if len(rows) != 4 {
		t.Fatalf("rows = %d, want header + 3", len(rows))
	}
	if rows[1][6] != `'=HYPERLINK("http://evil")` {
		t.Errorf("username exported as %q, want formula neutralised", rows[1][6])
	}
	if strings.HasPrefix(rows[len(rows)-1][0], "#") {
		t.Error("complete export ends with an incomplete marker")
	}

	maxAuditExport = 1
	rows = export()
	if last := rows[len(rows)-1][0]; !strings.HasPrefix(last, "# export incomplete") {
		t.Errorf("capped export's last row = %q, want an incomplete marker", last)
	}
}

// In anonymous mode no entry may name or number a person - not just in the
// requester columns, but in resource ids and details too.
func TestAuditHooks_AnonymousModeLeavesNoIdentity(t *testing.T) {
	t.Setenv("ANONYMOUS_MODE", "true")
	env := newAuditEnv(t)
	if !env.cfg.IsAnonymousMode() {
		t.Fatal("ANONYMOUS_MODE not picked up")
	}
	ctx := context.Background()
	hash, _ := utils.HashPassword("Anon-Passw0rd-123")
	alice, err := env.repos.Users.Create(ctx, "alice-anon", "alice@example.com", hash, "user", false)
	if err != nil {
		t.Fatal(err)
	}
	login := UserLoginHandler(env.repos, env.cfg)
	postJSON(t, login, "/api/auth/login", models.UserLoginRequest{Username: "alice-anon", Password: "wrong-wrong-wrong"})
	postJSON(t, login, "/api/auth/login", models.UserLoginRequest{Username: "alice-anon", Password: "Anon-Passw0rd-123"})

	body, _ := json.Marshal(models.CreateUserRequest{Username: "dave-anon", Email: "dave@example.com", Password: "Dave-Passw0rd-123"})
	req := httptest.NewRequest(http.MethodPost, "/admin/api/users/create", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if rr := adminRequest(t, env, AdminCreateUserHandler(env.repos, env.cfg), req); rr.Code != http.StatusCreated {
		t.Fatalf("create status = %d", rr.Code)
	}

	entries := env.entries(t)
	if len(entries) < 3 {
		t.Fatalf("only %d entries recorded", len(entries))
	}
	for _, e := range entries {
		if e.UserID != "" || e.Username != "" || e.IPAddress != "" || e.UserAgent != "" {
			t.Errorf("entry %d (%s) has requester identity: %+v", e.ID, e.Action, e)
		}
		if e.ResourceType == "user" && e.ResourceID != "" {
			t.Errorf("entry %d (%s) names user %q", e.ID, e.Action, e.ResourceID)
		}
		for _, needle := range []string{"alice-anon", "dave-anon", fmt.Sprintf(`"%d"`, alice.ID), env.cfg.AdminUsername} {
			if strings.Contains(e.Details, needle) {
				t.Errorf("entry %d (%s) details %q contain %q", e.ID, e.Action, e.Details, needle)
			}
		}
	}
}
