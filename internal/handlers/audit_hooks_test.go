package handlers

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/fjmerc/safeshare/internal/audit"
	"github.com/fjmerc/safeshare/internal/config"
	"github.com/fjmerc/safeshare/internal/middleware"
	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/repository"
	"github.com/fjmerc/safeshare/internal/repository/sqlite"
	"github.com/fjmerc/safeshare/internal/testutil"
	"github.com/fjmerc/safeshare/internal/utils"
	"github.com/pquerna/otp/totp"
)

type auditEnv struct {
	db     *sql.DB
	cfg    *config.Config
	repos  *repository.Repositories
	logger *audit.Logger
	repo   *sqlite.AuditLogRepository
}

// newAuditEnv installs a real audit logger as the process default for the
// duration of the test.
func newAuditEnv(t *testing.T) *auditEnv {
	t.Helper()
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	key, err := audit.LoadKey(strings.Repeat("ab", 32), "")
	if err != nil {
		t.Fatal(err)
	}
	repo := sqlite.NewAuditLogRepository(db)
	l := audit.NewLogger(repo, key)
	audit.SetDefault(l)
	t.Cleanup(func() { audit.SetDefault(nil) })
	return &auditEnv{db: db, cfg: cfg, repos: repos, logger: l, repo: repo}
}

func (e *auditEnv) entries(t *testing.T) []models.AuditLog {
	t.Helper()
	out, err := e.repo.Range(context.Background(), 0, 10000)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// find returns the entries with the given action and outcome, oldest first.
func (e *auditEnv) find(t *testing.T, action string, outcome models.AuditOutcome) []models.AuditLog {
	t.Helper()
	var out []models.AuditLog
	for _, en := range e.entries(t) {
		if en.Action == action && en.Outcome == outcome {
			out = append(out, en)
		}
	}
	return out
}

func (e *auditEnv) one(t *testing.T, action string, outcome models.AuditOutcome) models.AuditLog {
	t.Helper()
	got := e.find(t, action, outcome)
	if len(got) != 1 {
		t.Fatalf("want exactly 1 %s/%s entry, got %d (all: %+v)", action, outcome, len(got), e.entries(t))
	}
	return got[0]
}

// assertChainValid checks the signed chain and that none of the secrets
// appear anywhere in the stored entries.
func (e *auditEnv) assertChainValid(t *testing.T, secrets ...string) {
	t.Helper()
	v, err := e.logger.Verify(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !v.Valid {
		t.Fatalf("audit chain invalid: %s (at %d)", v.Problem, v.ProblemID)
	}
	// Hashes are random hex and could contain a short secret by chance.
	all := e.entries(t)
	for i := range all {
		all[i].PrevHash, all[i].EntryHash = "", ""
	}
	raw, _ := json.Marshal(all)
	for _, s := range secrets {
		if s != "" && strings.Contains(string(raw), s) {
			t.Errorf("audit log contains secret %q: %s", s, raw)
		}
	}
}

func postJSON(t *testing.T, h http.Handler, path string, body any, mod ...func(*http.Request)) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "audit-test/1.0")
	for _, m := range mod {
		m(req)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func TestAuditHooks_UserLogin(t *testing.T) {
	env := newAuditEnv(t)
	ctx := context.Background()
	const goodPw = "CorrectHorse-Battery9"
	const badPw = "WrongPassword-Guess1"
	hash, _ := utils.HashPassword(goodPw)
	user, err := env.repos.Users.Create(ctx, "alice", "alice@example.com", hash, "user", false)
	if err != nil {
		t.Fatal(err)
	}
	disabled, err := env.repos.Users.Create(ctx, "bob", "bob@example.com", hash, "user", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := env.repos.Users.SetActive(ctx, disabled.ID, false); err != nil {
		t.Fatal(err)
	}
	h := UserLoginHandler(env.repos, env.cfg)

	postJSON(t, h, "/api/auth/login", models.UserLoginRequest{Username: "alice", Password: badPw})
	postJSON(t, h, "/api/auth/login", models.UserLoginRequest{Username: "nobody", Password: badPw})
	postJSON(t, h, "/api/auth/login", models.UserLoginRequest{Username: "bob", Password: goodPw})
	rr := postJSON(t, h, "/api/auth/login", models.UserLoginRequest{Username: "alice", Password: goodPw})
	if rr.Code != http.StatusOK {
		t.Fatalf("login status = %d", rr.Code)
	}

	fails := env.find(t, "login", models.AuditOutcomeFailure)
	if len(fails) != 2 {
		t.Fatalf("want 2 failed logins, got %d", len(fails))
	}
	if fails[0].Username != "alice" || fails[1].Username != "nobody" {
		t.Errorf("attempted usernames = %q, %q", fails[0].Username, fails[1].Username)
	}
	if fails[0].EventType != models.AuditEventAuth {
		t.Errorf("event type = %s", fails[0].EventType)
	}
	if fails[0].UserAgent != "audit-test/1.0" || fails[0].IPAddress == "" {
		t.Errorf("client details missing: %+v", fails[0])
	}

	den := env.one(t, "login", models.AuditOutcomeDenied)
	if den.Username != "bob" || den.ResourceID != strconv.FormatInt(disabled.ID, 10) {
		t.Errorf("denied entry = %+v", den)
	}

	ok := env.one(t, "login", models.AuditOutcomeSuccess)
	if ok.Username != "alice" || ok.UserID != strconv.FormatInt(user.ID, 10) {
		t.Errorf("success entry = %+v", ok)
	}
	env.assertChainValid(t, goodPw, badPw, hash)
}

func TestAuditHooks_UserLogout(t *testing.T) {
	env := newAuditEnv(t)
	hash, _ := utils.HashPassword("pw-for-logout-1")
	user, _ := env.repos.Users.Create(context.Background(), "carol", "carol@example.com", hash, "user", false)

	req := httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)
	req.AddCookie(&http.Cookie{Name: "user_session", Value: "session-secret-value"})
	req = req.WithContext(context.WithValue(req.Context(), middleware.ContextKeyUser, user))
	rr := httptest.NewRecorder()
	UserLogoutHandler(env.repos, env.cfg).ServeHTTP(rr, req)

	en := env.one(t, "logout", models.AuditOutcomeSuccess)
	if en.Username != "carol" {
		t.Errorf("username = %q", en.Username)
	}
	env.assertChainValid(t, "session-secret-value")
}

// adminRequest sends r through the real AdminAuth middleware using a
// built-in admin session.
func adminRequest(t *testing.T, env *auditEnv, h http.Handler, req *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	token := "admin-session-token-secret-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	if err := env.repos.Admin.CreateSession(context.Background(), token, time.Now().Add(time.Hour), "127.0.0.1", "ua"); err != nil {
		t.Fatal(err)
	}
	req.AddCookie(&http.Cookie{Name: "admin_session", Value: token})
	rr := httptest.NewRecorder()
	middleware.AdminAuth(env.repos, false)(h).ServeHTTP(rr, req)
	return rr
}

func TestAuditHooks_AdminActions(t *testing.T) {
	env := newAuditEnv(t)
	const tempPw = "Temp-Password-For-New-User-77"

	body, _ := json.Marshal(models.CreateUserRequest{Username: "dave", Email: "dave@example.com", Password: tempPw})
	req := httptest.NewRequest(http.MethodPost, "/admin/api/users/create", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := adminRequest(t, env, AdminCreateUserHandler(env.repos, env.cfg), req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("create status = %d: %s", rr.Code, rr.Body.String())
	}
	var created models.CreateUserResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &created)

	en := env.one(t, "user_create", models.AuditOutcomeSuccess)
	if en.EventType != models.AuditEventAdmin {
		t.Errorf("event type = %s, want admin", en.EventType)
	}
	if en.Username != env.cfg.AdminUsername {
		t.Errorf("acting admin = %q, want %q", en.Username, env.cfg.AdminUsername)
	}
	if en.ResourceType != "user" || en.ResourceID != strconv.FormatInt(created.ID, 10) {
		t.Errorf("resource = %s/%s", en.ResourceType, en.ResourceID)
	}

	// Reset password: the generated temporary password is returned to the
	// admin but must not reach the log.
	req = httptest.NewRequest(http.MethodPost, "/admin/api/users/"+strconv.FormatInt(created.ID, 10)+"/reset-password", nil)
	rr = adminRequest(t, env, AdminResetUserPasswordHandler(env.repos, env.cfg), req)
	if rr.Code != http.StatusOK {
		t.Fatalf("reset status = %d: %s", rr.Code, rr.Body.String())
	}
	var reset map[string]string
	_ = json.Unmarshal(rr.Body.Bytes(), &reset)
	env.one(t, "user_reset_password", models.AuditOutcomeSuccess)

	// Block / unblock an IP.
	form := url.Values{"ip_address": {"203.0.113.9"}, "reason": {"abuse"}}
	req = httptest.NewRequest(http.MethodPost, "/admin/api/block-ip", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = adminRequest(t, env, AdminBlockIPHandler(env.repos, env.cfg), req)
	if rr.Code != http.StatusOK {
		t.Fatalf("block status = %d: %s", rr.Code, rr.Body.String())
	}
	blk := env.one(t, "ip_block", models.AuditOutcomeSuccess)
	if blk.ResourceType != "ip" || blk.ResourceID != "203.0.113.9" {
		t.Errorf("block resource = %s/%s", blk.ResourceType, blk.ResourceID)
	}

	// Settings update is a CONFIG event listing what changed.
	form = url.Values{"quota_gb": {"7"}}
	req = httptest.NewRequest(http.MethodPost, "/admin/api/settings/storage", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = adminRequest(t, env, AdminUpdateStorageSettingsHandler(env.repos, env.cfg), req)
	if rr.Code != http.StatusOK {
		t.Fatalf("storage status = %d: %s", rr.Code, rr.Body.String())
	}
	cfgEv := env.one(t, "storage_settings_update", models.AuditOutcomeSuccess)
	if cfgEv.EventType != models.AuditEventConfig || !strings.Contains(cfgEv.Details, "quota_gb") {
		t.Errorf("config entry = %+v", cfgEv)
	}

	// Delete the user.
	req = httptest.NewRequest(http.MethodDelete, "/admin/api/users/"+strconv.FormatInt(created.ID, 10), nil)
	rr = adminRequest(t, env, AdminDeleteUserHandler(env.repos, env.cfg), req)
	if rr.Code != http.StatusOK {
		t.Fatalf("delete status = %d: %s", rr.Code, rr.Body.String())
	}
	env.one(t, "user_delete", models.AuditOutcomeSuccess)

	env.assertChainValid(t, tempPw, reset["temporary_password"], "admin-session-token-secret")
}

func TestAuditHooks_AdminLoginAndPassword(t *testing.T) {
	env := newAuditEnv(t)
	if err := env.cfg.SetAdminPassword("current-admin-password"); err != nil {
		t.Fatal(err)
	}

	// Wrong password for an unknown admin name.
	postJSON(t, AdminLoginHandler(env.repos, env.cfg), "/admin/api/login", map[string]string{"username": "root", "password": "guess-guess-guess"})
	f := env.one(t, "admin_login", models.AuditOutcomeFailure)
	if f.Username != "root" {
		t.Errorf("attempted username = %q", f.Username)
	}

	pw := func(cur, next string) *httptest.ResponseRecorder {
		form := url.Values{"current_password": {cur}, "new_password": {next}, "confirm_password": {next}}
		req := httptest.NewRequest(http.MethodPost, "/admin/api/settings/password", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return adminRequest(t, env, AdminChangePasswordHandler(env.cfg), req)
	}
	if rr := pw("not-the-password", "brand-new-password-1"); rr.Code != http.StatusUnauthorized {
		t.Fatalf("bad change status = %d", rr.Code)
	}
	env.one(t, "admin_password_change", models.AuditOutcomeFailure)
	if rr := pw("current-admin-password", "brand-new-password-1"); rr.Code != http.StatusOK {
		t.Fatalf("change status = %d: %s", rr.Code, rr.Body.String())
	}
	ok := env.one(t, "admin_password_change", models.AuditOutcomeSuccess)
	if ok.Username != env.cfg.AdminUsername || ok.EventType != models.AuditEventAuth {
		t.Errorf("entry = %+v", ok)
	}
	env.assertChainValid(t, "current-admin-password", "brand-new-password-1", "not-the-password", "guess-guess-guess")
}

func TestAuditHooks_UploadAndDownload(t *testing.T) {
	env := newAuditEnv(t)

	body, ct := testutil.CreateMultipartForm(t, []byte("hello audit"), "note.txt", nil)
	req := httptest.NewRequest(http.MethodPost, "/api/upload", body)
	req.Header.Set("Content-Type", ct)
	rr := httptest.NewRecorder()
	UploadHandler(env.repos, env.cfg).ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("upload status = %d: %s", rr.Code, rr.Body.String())
	}
	var up models.UploadResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &up)
	file, err := env.repos.Files.GetByClaimCode(context.Background(), up.ClaimCode)
	if err != nil || file == nil {
		t.Fatalf("file lookup: %v", err)
	}

	u := env.one(t, "file_upload", models.AuditOutcomeSuccess)
	if u.EventType != models.AuditEventFile || u.ResourceType != "file" || u.ResourceID != strconv.FormatInt(file.ID, 10) {
		t.Errorf("upload entry = %+v", u)
	}

	dl := func() *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		ClaimHandler(env.repos, env.cfg).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/claim/"+up.ClaimCode, nil))
		return rr
	}
	if rr := dl(); rr.Code != http.StatusOK {
		t.Fatalf("download status = %d", rr.Code)
	}
	if got := env.find(t, "file_download", models.AuditOutcomeSuccess); len(got) != 1 || got[0].ResourceID != strconv.FormatInt(file.ID, 10) {
		t.Errorf("download entries = %+v", got)
	}
	// HEAD never counts as a download.
	head := httptest.NewRecorder()
	ClaimHandler(env.repos, env.cfg).ServeHTTP(head, httptest.NewRequest(http.MethodHead, "/api/claim/"+up.ClaimCode, nil))
	if got := env.find(t, "file_download", models.AuditOutcomeSuccess); len(got) != 1 {
		t.Errorf("HEAD recorded a download: %d entries", len(got))
	}
	env.assertChainValid(t, up.ClaimCode)
}

func TestAuditHooks_CappedDownloadCountedOnce(t *testing.T) {
	env := newAuditEnv(t)
	ctx := context.Background()
	content := []byte("capped content")
	stored := "capped-uuid.txt"
	if err := os.WriteFile(filepath.Join(env.cfg.UploadDir, stored), content, 0644); err != nil {
		t.Fatal(err)
	}
	max := 3
	f := &models.File{ClaimCode: "cappedclaim", OriginalFilename: "c.txt", StoredFilename: stored, FileSize: int64(len(content)),
		MimeType: "text/plain", ExpiresAt: time.Now().Add(time.Hour), UploaderIP: "127.0.0.1", MaxDownloads: &max}
	if err := env.repos.Files.Create(ctx, f); err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	ClaimHandler(env.repos, env.cfg).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/claim/cappedclaim", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	if got := env.find(t, "file_download", models.AuditOutcomeSuccess); len(got) != 1 {
		t.Fatalf("want 1 download entry, got %d", len(got))
	}
	env.assertChainValid(t, "cappedclaim")
}

func TestAuditHooks_DownloadWrongPassword(t *testing.T) {
	env := newAuditEnv(t)
	ctx := context.Background()
	stored := "pw-uuid.txt"
	if err := os.WriteFile(filepath.Join(env.cfg.UploadDir, stored), []byte("secret"), 0644); err != nil {
		t.Fatal(err)
	}
	hash, _ := utils.HashPassword("FilePassword-Right-1")
	f := &models.File{ClaimCode: "pwclaim", OriginalFilename: "s.txt", StoredFilename: stored, FileSize: 6, MimeType: "text/plain",
		ExpiresAt: time.Now().Add(time.Hour), UploaderIP: "127.0.0.1", PasswordHash: hash}
	if err := env.repos.Files.Create(ctx, f); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/claim/pwclaim", nil)
	req.Header.Set("X-File-Password", "FilePassword-Wrong-2")
	rr := httptest.NewRecorder()
	ClaimHandler(env.repos, env.cfg).ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", rr.Code)
	}
	en := env.one(t, "download_denied", models.AuditOutcomeFailure)
	if en.EventType != models.AuditEventSecurity || en.ResourceID != strconv.FormatInt(f.ID, 10) {
		t.Errorf("entry = %+v", en)
	}

	// The web UI's HEAD pre-check is not recorded.
	req = httptest.NewRequest(http.MethodHead, "/api/claim/pwclaim", nil)
	req.Header.Set("X-File-Password", "FilePassword-Wrong-2")
	ClaimHandler(env.repos, env.cfg).ServeHTTP(httptest.NewRecorder(), req)
	if got := env.find(t, "download_denied", models.AuditOutcomeFailure); len(got) != 1 {
		t.Errorf("HEAD recorded: %d entries", len(got))
	}
	env.assertChainValid(t, "FilePassword-Wrong-2", "FilePassword-Right-1", "pwclaim")
}

func TestAuditHooks_RecordAssemblyEvent(t *testing.T) {
	ctx := context.Background()
	hash, _ := utils.HashPassword("pw-assembly-1")

	tests := []struct {
		name      string
		anonymous bool
		wantUser  string
		wantIP    string
	}{
		{"identified", false, "erin", "198.51.100.4"},
		{"anonymous", true, "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.anonymous {
				t.Setenv("ANONYMOUS_MODE", "true")
			}
			e := newAuditEnv(t)
			if tt.anonymous != e.cfg.IsAnonymousMode() {
				t.Fatalf("anonymous mode = %v", e.cfg.IsAnonymousMode())
			}
			u, _ := e.repos.Users.Create(ctx, "erin", "erin@example.com", hash, "user", false)
			p := models.PartialUpload{UserID: &u.ID, UploaderIP: "198.51.100.4", Filename: "big.bin"}
			recordAssemblyEvent(ctx, e.cfg, e.repos, &p, audit.Event{Type: models.AuditEventFile, Action: "file_upload",
				Outcome: models.AuditOutcomeSuccess, ResourceType: "file", ResourceID: "42"})
			en := e.one(t, "file_upload", models.AuditOutcomeSuccess)
			if en.Username != tt.wantUser || en.IPAddress != tt.wantIP {
				t.Errorf("username=%q ip=%q, want %q %q", en.Username, en.IPAddress, tt.wantUser, tt.wantIP)
			}
			if tt.anonymous && en.UserID != "" {
				t.Errorf("user id recorded in anonymous mode: %q", en.UserID)
			}
			e.assertChainValid(t)
		})
	}
}

func TestCapIDs(t *testing.T) {
	ids := make([]int64, 250)
	if got := len(capIDs(ids, auditMaxIDs)); got != auditMaxIDs {
		t.Errorf("capped length = %d", got)
	}
	if got := len(capIDs(ids[:5], auditMaxIDs)); got != 5 {
		t.Errorf("short length = %d", got)
	}
}

func TestAuditHooks_MFALoginFlow(t *testing.T) {
	env := newAuditEnv(t)
	ctx := context.Background()
	env.cfg.MFA = &config.MFAConfig{Enabled: true, TOTPEnabled: true, RecoveryCodesCount: 10, Issuer: "T", ChallengeExpiryMinutes: 5}
	mfaUserFailureLimiter.Reset()
	t.Cleanup(mfaUserFailureLimiter.Reset)

	const pw = "Password-For-MFA-User-5"
	hash, _ := utils.HashPassword(pw)
	user, err := env.repos.Users.Create(ctx, "frank", "frank@example.com", hash, "user", false)
	if err != nil {
		t.Fatal(err)
	}
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "T", AccountName: "frank@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if err := env.repos.MFA.SetupTOTP(ctx, user.ID, key.Secret()); err != nil {
		t.Fatal(err)
	}
	if err := env.repos.MFA.EnableTOTP(ctx, user.ID); err != nil {
		t.Fatal(err)
	}
	codes, hashes, err := generateRecoveryCodes(10)
	if err != nil {
		t.Fatal(err)
	}
	if err := env.repos.MFA.CreateRecoveryCodes(ctx, user.ID, hashes); err != nil {
		t.Fatal(err)
	}

	challenge := func() string {
		rr := postJSON(t, UserLoginWithMFAHandler(env.repos, env.cfg), "/api/auth/login", models.UserLoginRequest{Username: "frank", Password: pw})
		var resp MFALoginResponse
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil || !resp.MFARequired {
			t.Fatalf("expected MFA challenge, got %d %s", rr.Code, rr.Body.String())
		}
		t.Cleanup(func() { mfaLoginStore.Delete(resp.ChallengeID) })
		return resp.ChallengeID
	}
	verify := func(id, code string, recovery bool) int {
		return postJSON(t, MFAVerifyLoginHandler(env.repos, env.cfg), "/api/auth/mfa/verify",
			MFAVerifyLoginRequest{ChallengeID: id, Code: code, IsRecovery: recovery}).Code
	}

	id := challenge()
	// Password accepted is not a login yet: no session exists.
	if got := env.find(t, "login_mfa_challenge", models.AuditOutcomeSuccess); len(got) != 1 {
		t.Fatalf("login_mfa_challenge entries = %+v", got)
	}
	if got := env.find(t, "login", models.AuditOutcomeSuccess); len(got) != 0 {
		t.Fatalf("login success recorded before MFA: %+v", got)
	}

	wrong := "000000"
	if good, _ := totp.GenerateCode(key.Secret(), time.Now()); good == wrong {
		wrong = "111111"
	}
	if code := verify(id, wrong, false); code != http.StatusUnauthorized {
		t.Fatalf("wrong code status = %d", code)
	}
	f := env.one(t, "mfa_verify", models.AuditOutcomeFailure)
	if f.Username != "frank" || !strings.Contains(f.Details, "totp") {
		t.Errorf("failure entry = %+v", f)
	}

	good, _ := totp.GenerateCode(key.Secret(), time.Now())
	if code := verify(id, good, false); code != http.StatusOK {
		t.Fatalf("good code status = %d", code)
	}
	if got := env.find(t, "login", models.AuditOutcomeSuccess); len(got) != 1 || !strings.Contains(got[0].Details, `"totp"`) {
		t.Fatalf("totp login entries = %+v", got)
	}

	id = challenge()
	if code := verify(id, codes[0], true); code != http.StatusOK {
		t.Fatalf("recovery status = %d", code)
	}
	got := env.find(t, "login", models.AuditOutcomeSuccess)
	if len(got) != 2 || !strings.Contains(got[1].Details, "recovery_code") {
		t.Fatalf("recovery login entries = %+v", got)
	}
	env.assertChainValid(t, pw, good, wrong, codes[0], key.Secret())
}

func TestAuditHooks_APITokens(t *testing.T) {
	env := newAuditEnv(t)
	user, ctx := setupTestUserWithSession(t, env.db)

	req := httptest.NewRequest(http.MethodPost, "/api/tokens", bytes.NewBufferString(`{"name": "ci", "scopes": ["upload", "download"]}`)).WithContext(ctx)
	rr := httptest.NewRecorder()
	CreateAPITokenHandler(env.repos, env.cfg).ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("create status = %d: %s", rr.Code, rr.Body.String())
	}
	var created models.CreateAPITokenResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &created)

	en := env.one(t, "token_create", models.AuditOutcomeSuccess)
	if en.Username != user.Username || en.ResourceType != "token" || en.ResourceID != strconv.FormatInt(created.ID, 10) {
		t.Errorf("create entry = %+v", en)
	}
	if !strings.Contains(en.Details, "ci") || !strings.Contains(en.Details, "upload") {
		t.Errorf("details = %s", en.Details)
	}

	req = httptest.NewRequest(http.MethodDelete, "/api/tokens/"+strconv.FormatInt(created.ID, 10), nil).WithContext(ctx)
	rr = httptest.NewRecorder()
	RevokeAPITokenHandler(env.db, env.cfg).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("revoke status = %d: %s", rr.Code, rr.Body.String())
	}
	env.one(t, "token_revoke", models.AuditOutcomeSuccess)

	env.assertChainValid(t, created.Token, utils.HashAPIToken(created.Token))
}
