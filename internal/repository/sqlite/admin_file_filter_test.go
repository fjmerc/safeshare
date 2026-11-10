package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/repository"
)

const (
	kib = int64(1024)
	mib = 1024 * kib
	gib = 1024 * mib
)

// adminFilterFixture is one row of the shared admin-filter data set.
type adminFilterFixture struct {
	code       string
	owner      string // "" = anonymous
	size       int64
	createdAgo time.Duration
	expiresIn  time.Duration // ignored when expiresRaw is set
	expiresRaw string        // stored verbatim, for never-expire sentinels
	scan       *string       // nil = NULL
	maxDL      *int
	downloads  int
}

func strPtr(s string) *string { return &s }

// adminFilterFixtures: alice and Bob upload; carol has no files. Codes are
// listed in insertion order, which is also id order.
var adminFilterFixtures = []adminFilterFixture{
	{code: "fAnonSmall", size: 500, createdAgo: time.Hour, expiresIn: 48 * time.Hour, scan: strPtr("clean")},
	{code: "fAlice1MiB", owner: "alice", size: mib, createdAgo: 48 * time.Hour, expiresIn: 12 * time.Hour, scan: strPtr("pending"), maxDL: intPtr(5), downloads: 1},
	{code: "fAliceBig", owner: "alice", size: 2 * gib, createdAgo: 40 * 24 * time.Hour, expiresRaw: "9999-12-31T23:59:59Z", scan: strPtr("infected"), maxDL: intPtr(3), downloads: 3},
	{code: "fBobMid", owner: "Bob", size: 50 * mib, createdAgo: 10 * 24 * time.Hour, expiresIn: 5 * 24 * time.Hour, scan: strPtr("error"), maxDL: intPtr(0), downloads: 7},
	{code: "fBobNull", owner: "Bob", size: 200 * mib, createdAgo: 20 * time.Hour, expiresIn: 2 * time.Hour},
	{code: "fAnonEmpty", size: 10*mib - 1, createdAgo: 31 * 24 * time.Hour, expiresIn: 30 * 24 * time.Hour, scan: strPtr(""), maxDL: intPtr(2), downloads: 1},
	{code: "fAnonSkip", size: 100 * mib, createdAgo: 3 * 24 * time.Hour, expiresIn: 3 * 24 * time.Hour, scan: strPtr("skipped")},
	{code: "fAnonNever", size: 999, createdAgo: 5 * 24 * time.Hour, expiresRaw: "9999-12-31T23:59:59+01:00", scan: strPtr("not_scanned")},
	{code: "fExpired", size: 2048, createdAgo: 50 * time.Hour, expiresIn: -30 * time.Minute, scan: strPtr("clean")},
}

// seedAdminFilterFixtures inserts the fixtures and returns the user ids by name.
func seedAdminFilterFixtures(t *testing.T, db *sql.DB) map[string]int64 {
	t.Helper()
	ctx := context.Background()
	users := NewUserRepository(db)
	files := NewFileRepository(db)
	ids := map[string]int64{}
	for _, name := range []string{"alice", "Bob", "carol"} {
		u, err := users.Create(ctx, name, name+"@example.com", "hash", "user", false)
		if err != nil {
			t.Fatalf("create user %s: %v", name, err)
		}
		ids[name] = u.ID
	}
	now := time.Now()
	for _, fx := range adminFilterFixtures {
		f := &models.File{
			ClaimCode:        fx.code,
			OriginalFilename: fx.code + ".bin",
			StoredFilename:   fx.code + ".stored",
			FileSize:         fx.size,
			MimeType:         "application/octet-stream",
			CreatedAt:        now.Add(-fx.createdAgo),
			ExpiresAt:        now.Add(fx.expiresIn),
			MaxDownloads:     fx.maxDL,
			UploaderIP:       "10.0.0.1",
		}
		if fx.owner != "" {
			uid := ids[fx.owner]
			f.UserID = &uid
		}
		if err := files.Create(ctx, f); err != nil {
			t.Fatalf("create %s: %v", fx.code, err)
		}
		// Raw updates: Create stores '' scan_status as NULL and always starts
		// download_count at 0.
		if _, err := db.Exec(`UPDATE files SET scan_status = ?, download_count = ? WHERE id = ?`, fx.scan, fx.downloads, f.ID); err != nil {
			t.Fatalf("update %s: %v", fx.code, err)
		}
		if fx.expiresRaw != "" {
			if _, err := db.Exec(`UPDATE files SET expires_at = ? WHERE id = ?`, fx.expiresRaw, f.ID); err != nil {
				t.Fatalf("update %s expiry: %v", fx.code, err)
			}
		}
	}
	return ids
}

func listCodes(t *testing.T, repo *FileRepository, filter repository.AdminFileFilter) ([]string, int) {
	t.Helper()
	files, total, err := repo.ListForAdmin(context.Background(), filter, 100, 0)
	if err != nil {
		t.Fatalf("ListForAdmin(%+v): %v", filter, err)
	}
	codes := []string{}
	for _, f := range files {
		codes = append(codes, f.ClaimCode)
	}
	if total != len(codes) {
		t.Errorf("ListForAdmin(%+v) total = %d, page has %d rows", filter, total, len(codes))
	}
	return codes, total
}

func i64(v int64) *int64 { return &v }

func TestListForAdmin_Filters(t *testing.T) {
	db := setupTestDB(t)
	ids := seedAdminFilterFixtures(t, db)
	repo := NewFileRepository(db)
	alice, carol := ids["alice"], ids["carol"]
	day := 24 * time.Hour

	tests := []struct {
		name   string
		filter repository.AdminFileFilter
		want   []string // newest first
	}{
		{"no filter", repository.AdminFileFilter{},
			[]string{"fAnonSmall", "fBobNull", "fAlice1MiB", "fExpired", "fAnonSkip", "fAnonNever", "fBobMid", "fAnonEmpty", "fAliceBig"}},
		{"user alice", repository.AdminFileFilter{UserID: &alice}, []string{"fAlice1MiB", "fAliceBig"}},
		{"user without files", repository.AdminFileFilter{UserID: &carol}, []string{}},
		{"anonymous", repository.AdminFileFilter{Anonymous: true},
			[]string{"fAnonSmall", "fExpired", "fAnonSkip", "fAnonNever", "fAnonEmpty"}},
		{"under 1 MiB", repository.AdminFileFilter{MaxSize: i64(mib)}, []string{"fAnonSmall", "fExpired", "fAnonNever"}},
		{"1-10 MiB (min inclusive)", repository.AdminFileFilter{MinSize: i64(mib), MaxSize: i64(10 * mib)}, []string{"fAlice1MiB", "fAnonEmpty"}},
		{"10-100 MiB (max exclusive)", repository.AdminFileFilter{MinSize: i64(10 * mib), MaxSize: i64(100 * mib)}, []string{"fBobMid"}},
		{"100 MiB-1 GiB", repository.AdminFileFilter{MinSize: i64(100 * mib), MaxSize: i64(gib)}, []string{"fBobNull", "fAnonSkip"}},
		{"over 1 GiB", repository.AdminFileFilter{MinSize: i64(gib)}, []string{"fAliceBig"}},
		{"limit reached (max 0 is unlimited)", repository.AdminFileFilter{Status: repository.AdminFileStatusLimitReached}, []string{"fAliceBig"}},
		{"active", repository.AdminFileFilter{Status: repository.AdminFileStatusActive},
			[]string{"fAnonSmall", "fBobNull", "fAlice1MiB", "fAnonSkip", "fAnonNever", "fBobMid", "fAnonEmpty"}},
		{"never expires (any offset)", repository.AdminFileFilter{Status: repository.AdminFileStatusNeverExpires}, []string{"fAnonNever", "fAliceBig"}},
		{"expiring soon", repository.AdminFileFilter{Status: repository.AdminFileStatusExpiringSoon}, []string{"fBobNull", "fAlice1MiB", "fExpired"}},
		{"scan clean", repository.AdminFileFilter{Scan: repository.AdminFileScanClean}, []string{"fAnonSmall", "fExpired"}},
		{"scan pending", repository.AdminFileFilter{Scan: repository.AdminFileScanPending}, []string{"fAlice1MiB"}},
		{"scan infected", repository.AdminFileFilter{Scan: repository.AdminFileScanInfected}, []string{"fAliceBig"}},
		{"scan error", repository.AdminFileFilter{Scan: repository.AdminFileScanError}, []string{"fBobMid"}},
		{"not scanned (NULL, '', skipped, not_scanned)", repository.AdminFileFilter{Scan: repository.AdminFileScanNotScanned},
			[]string{"fBobNull", "fAnonSkip", "fAnonNever", "fAnonEmpty"}},
		{"uploaded last 24h", repository.AdminFileFilter{UploadedWithin: day}, []string{"fAnonSmall", "fBobNull"}},
		{"uploaded last 7d", repository.AdminFileFilter{UploadedWithin: 7 * day},
			[]string{"fAnonSmall", "fBobNull", "fAlice1MiB", "fExpired", "fAnonSkip", "fAnonNever"}},
		{"uploaded last 30d", repository.AdminFileFilter{UploadedWithin: 30 * day},
			[]string{"fAnonSmall", "fBobNull", "fAlice1MiB", "fExpired", "fAnonSkip", "fAnonNever", "fBobMid"}},
		{"uploaded over 30d ago", repository.AdminFileFilter{UploadedBefore: 30 * day}, []string{"fAnonEmpty", "fAliceBig"}},
		{"search alone", repository.AdminFileFilter{Search: "fbob"}, []string{"fBobNull", "fBobMid"}},
		{"search matches username", repository.AdminFileFilter{Search: "alic"}, []string{"fAlice1MiB", "fAliceBig"}},
		{"search + anonymous + not scanned", repository.AdminFileFilter{Search: "skip", Anonymous: true, Scan: repository.AdminFileScanNotScanned}, []string{"fAnonSkip"}},
		{"search OR stays grouped under AND", repository.AdminFileFilter{Search: "alice", Anonymous: true}, []string{}},
		{"user + size + status", repository.AdminFileFilter{UserID: &alice, MinSize: i64(gib), Status: repository.AdminFileStatusNeverExpires}, []string{"fAliceBig"}},
		{"search wildcard is literal", repository.AdminFileFilter{Search: "%"}, []string{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := listCodes(t, repo, tt.filter)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %v\nwant %v", got, tt.want)
			}
		})
	}
}

func TestListForAdmin_Sort(t *testing.T) {
	db := setupTestDB(t)
	seedAdminFilterFixtures(t, db)
	repo := NewFileRepository(db)

	tests := []struct {
		sort string
		want []string
	}{
		{repository.AdminFileSortNewest, []string{"fAnonSmall", "fBobNull", "fAlice1MiB", "fExpired", "fAnonSkip", "fAnonNever", "fBobMid", "fAnonEmpty", "fAliceBig"}},
		{repository.AdminFileSortOldest, []string{"fAliceBig", "fAnonEmpty", "fBobMid", "fAnonNever", "fAnonSkip", "fExpired", "fAlice1MiB", "fBobNull", "fAnonSmall"}},
		{repository.AdminFileSortLargest, []string{"fAliceBig", "fBobNull", "fAnonSkip", "fBobMid", "fAnonEmpty", "fAlice1MiB", "fExpired", "fAnonNever", "fAnonSmall"}},
		{repository.AdminFileSortSmallest, []string{"fAnonSmall", "fAnonNever", "fExpired", "fAlice1MiB", "fAnonEmpty", "fBobMid", "fAnonSkip", "fBobNull", "fAliceBig"}},
		{repository.AdminFileSortExpiring, []string{"fExpired", "fBobNull", "fAlice1MiB", "fAnonSmall", "fAnonSkip", "fBobMid", "fAnonEmpty", "fAnonNever", "fAliceBig"}},
	}
	for _, tt := range tests {
		t.Run(tt.sort, func(t *testing.T) {
			got, _ := listCodes(t, repo, repository.AdminFileFilter{Sort: tt.sort})
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %v\nwant %v", got, tt.want)
			}
		})
	}
}

func TestListForAdmin_TiesBreakOnID(t *testing.T) {
	db := setupTestDB(t)
	repo := NewFileRepository(db)
	ctx := context.Background()
	created := time.Now().Add(-time.Hour)
	for _, code := range []string{"tieA", "tieB", "tieC"} {
		f := newColumnsTestFile(code, nil, nil, nil)
		f.CreatedAt = created
		if err := repo.Create(ctx, f); err != nil {
			t.Fatalf("create: %v", err)
		}
	}
	for sort, want := range map[string][]string{
		repository.AdminFileSortNewest:   {"tieC", "tieB", "tieA"},
		repository.AdminFileSortOldest:   {"tieA", "tieB", "tieC"},
		repository.AdminFileSortLargest:  {"tieC", "tieB", "tieA"},
		repository.AdminFileSortSmallest: {"tieA", "tieB", "tieC"},
	} {
		got, _ := listCodes(t, repo, repository.AdminFileFilter{Sort: sort})
		if !reflect.DeepEqual(got, want) {
			t.Errorf("sort %s: got %v, want %v", sort, got, want)
		}
	}
}

func TestListForAdmin_PaginationCountsWholeMatch(t *testing.T) {
	db := setupTestDB(t)
	seedAdminFilterFixtures(t, db)
	repo := NewFileRepository(db)

	filter := repository.AdminFileFilter{Anonymous: true, Sort: repository.AdminFileSortSmallest}
	files, total, err := repo.ListForAdmin(context.Background(), filter, 2, 2)
	if err != nil {
		t.Fatalf("ListForAdmin: %v", err)
	}
	if total != 5 {
		t.Errorf("total = %d, want 5", total)
	}
	if len(files) != 2 || files[0].ClaimCode != "fExpired" || files[1].ClaimCode != "fAnonEmpty" {
		t.Errorf("page = %+v, want fExpired, fAnonEmpty", files)
	}
	if files[0].UserID != nil || files[0].Username != nil {
		t.Errorf("anonymous row has user %v/%v", files[0].UserID, files[0].Username)
	}
}

func TestListForAdmin_InvalidFilter(t *testing.T) {
	db := setupTestDB(t)
	repo := NewFileRepository(db)
	for _, f := range []repository.AdminFileFilter{
		{Status: "expired"},
		{Scan: "bogus"},
		{Sort: "created_at; DROP TABLE files"},
		{UserID: i64(1), Anonymous: true},
		{MinSize: i64(10), MaxSize: i64(10)},
	} {
		if _, _, err := repo.ListForAdmin(context.Background(), f, 10, 0); !errors.Is(err, repository.ErrInvalidInput) {
			t.Errorf("ListForAdmin(%+v) err = %v, want ErrInvalidInput", f, err)
		}
	}
}

func TestGetAdminUploaders(t *testing.T) {
	db := setupTestDB(t)
	ids := seedAdminFilterFixtures(t, db)
	repo := NewFileRepository(db)

	got, err := repo.GetAdminUploaders(context.Background())
	if err != nil {
		t.Fatalf("GetAdminUploaders: %v", err)
	}
	want := &repository.AdminUploaders{
		AnonymousCount: 5,
		Users: []repository.AdminUploader{
			{UserID: ids["alice"], Username: "alice", FileCount: 2},
			{UserID: ids["Bob"], Username: "Bob", FileCount: 2},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v\nwant %+v", got, want)
	}
}

func TestGetAdminUploaders_Empty(t *testing.T) {
	db := setupTestDB(t)
	got, err := NewFileRepository(db).GetAdminUploaders(context.Background())
	if err != nil {
		t.Fatalf("GetAdminUploaders: %v", err)
	}
	if got.AnonymousCount != 0 || got.Users == nil || len(got.Users) != 0 {
		t.Errorf("got %+v, want zero count and empty non-nil users", got)
	}
}
