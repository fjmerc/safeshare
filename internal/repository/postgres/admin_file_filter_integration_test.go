//go:build integration
// +build integration

package postgres

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/repository"
)

// Same data set and expectations as the sqlite package's admin_file_filter_test.go.

const (
	pgKiB = int64(1024)
	pgMiB = 1024 * pgKiB
	pgGiB = 1024 * pgMiB
)

type pgAdminFilterFixture struct {
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

func pgStr(s string) *string { return &s }
func pgInt(i int) *int       { return &i }
func pgI64(v int64) *int64   { return &v }

var pgAdminFilterFixtures = []pgAdminFilterFixture{
	{code: "fAnonSmall", size: 500, createdAgo: time.Hour, expiresIn: 48 * time.Hour, scan: pgStr("clean")},
	{code: "fAlice1MiB", owner: "alice", size: pgMiB, createdAgo: 48 * time.Hour, expiresIn: 12 * time.Hour, scan: pgStr("pending"), maxDL: pgInt(5), downloads: 1},
	{code: "fAliceBig", owner: "alice", size: 2 * pgGiB, createdAgo: 40 * 24 * time.Hour, expiresRaw: "9999-12-31T23:59:59Z", scan: pgStr("infected"), maxDL: pgInt(3), downloads: 3},
	{code: "fBobMid", owner: "Bob", size: 50 * pgMiB, createdAgo: 10 * 24 * time.Hour, expiresIn: 5 * 24 * time.Hour, scan: pgStr("error"), maxDL: pgInt(0), downloads: 7},
	{code: "fBobNull", owner: "Bob", size: 200 * pgMiB, createdAgo: 20 * time.Hour, expiresIn: 2 * time.Hour},
	{code: "fAnonEmpty", size: 10*pgMiB - 1, createdAgo: 31 * 24 * time.Hour, expiresIn: 30 * 24 * time.Hour, scan: pgStr(""), maxDL: pgInt(2), downloads: 1},
	{code: "fAnonSkip", size: 100 * pgMiB, createdAgo: 3 * 24 * time.Hour, expiresIn: 3 * 24 * time.Hour, scan: pgStr("skipped")},
	{code: "fAnonNever", size: 999, createdAgo: 5 * 24 * time.Hour, expiresRaw: "9999-12-31T23:59:59+01:00", scan: pgStr("not_scanned")},
	{code: "fExpired", size: 2048, createdAgo: 50 * time.Hour, expiresIn: -30 * time.Minute, scan: pgStr("clean")},
}

func pgSeedAdminFilterFixtures(t *testing.T, repos *repository.Repositories) map[string]int64 {
	t.Helper()
	ctx := context.Background()
	ids := map[string]int64{}
	for _, name := range []string{"alice", "Bob", "carol"} {
		u, err := repos.Users.Create(ctx, name, name+"@example.com", "hash", "user", false)
		if err != nil {
			t.Fatalf("create user %s: %v", name, err)
		}
		ids[name] = u.ID
	}
	now := time.Now()
	for _, fx := range pgAdminFilterFixtures {
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
		if err := repos.Files.Create(ctx, f); err != nil {
			t.Fatalf("create %s: %v", fx.code, err)
		}
		if _, err := testPool.Exec(ctx, `UPDATE files SET scan_status = $1, download_count = $2 WHERE id = $3`, fx.scan, fx.downloads, f.ID); err != nil {
			t.Fatalf("update %s: %v", fx.code, err)
		}
		if fx.expiresRaw != "" {
			if _, err := testPool.Exec(ctx, `UPDATE files SET expires_at = $1::timestamptz WHERE id = $2`, fx.expiresRaw, f.ID); err != nil {
				t.Fatalf("update %s expiry: %v", fx.code, err)
			}
		}
	}
	return ids
}

func pgListCodes(t *testing.T, repos *repository.Repositories, filter repository.AdminFileFilter) []string {
	t.Helper()
	files, total, err := repos.Files.ListForAdmin(context.Background(), filter, 100, 0)
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
	return codes
}

func TestFileRepository_ListForAdmin_Filters(t *testing.T) {
	repos := setupTestRepos(t)
	ids := pgSeedAdminFilterFixtures(t, repos)
	alice, carol := ids["alice"], ids["carol"]
	day := 24 * time.Hour

	tests := []struct {
		name   string
		filter repository.AdminFileFilter
		want   []string
	}{
		{"no filter", repository.AdminFileFilter{},
			[]string{"fAnonSmall", "fBobNull", "fAlice1MiB", "fExpired", "fAnonSkip", "fAnonNever", "fBobMid", "fAnonEmpty", "fAliceBig"}},
		{"user alice", repository.AdminFileFilter{UserID: &alice}, []string{"fAlice1MiB", "fAliceBig"}},
		{"user without files", repository.AdminFileFilter{UserID: &carol}, []string{}},
		{"anonymous", repository.AdminFileFilter{Anonymous: true},
			[]string{"fAnonSmall", "fExpired", "fAnonSkip", "fAnonNever", "fAnonEmpty"}},
		{"under 1 MiB", repository.AdminFileFilter{MaxSize: pgI64(pgMiB)}, []string{"fAnonSmall", "fExpired", "fAnonNever"}},
		{"1-10 MiB", repository.AdminFileFilter{MinSize: pgI64(pgMiB), MaxSize: pgI64(10 * pgMiB)}, []string{"fAlice1MiB", "fAnonEmpty"}},
		{"10-100 MiB", repository.AdminFileFilter{MinSize: pgI64(10 * pgMiB), MaxSize: pgI64(100 * pgMiB)}, []string{"fBobMid"}},
		{"100 MiB-1 GiB", repository.AdminFileFilter{MinSize: pgI64(100 * pgMiB), MaxSize: pgI64(pgGiB)}, []string{"fBobNull", "fAnonSkip"}},
		{"over 1 GiB", repository.AdminFileFilter{MinSize: pgI64(pgGiB)}, []string{"fAliceBig"}},
		{"limit reached", repository.AdminFileFilter{Status: repository.AdminFileStatusLimitReached}, []string{"fAliceBig"}},
		{"active", repository.AdminFileFilter{Status: repository.AdminFileStatusActive},
			[]string{"fAnonSmall", "fBobNull", "fAlice1MiB", "fAnonSkip", "fAnonNever", "fBobMid", "fAnonEmpty"}},
		{"never expires", repository.AdminFileFilter{Status: repository.AdminFileStatusNeverExpires}, []string{"fAnonNever", "fAliceBig"}},
		{"expiring soon", repository.AdminFileFilter{Status: repository.AdminFileStatusExpiringSoon}, []string{"fBobNull", "fAlice1MiB"}},
		{"scan clean", repository.AdminFileFilter{Scan: repository.AdminFileScanClean}, []string{"fAnonSmall", "fExpired"}},
		{"scan pending", repository.AdminFileFilter{Scan: repository.AdminFileScanPending}, []string{"fAlice1MiB"}},
		{"scan infected", repository.AdminFileFilter{Scan: repository.AdminFileScanInfected}, []string{"fAliceBig"}},
		{"scan error", repository.AdminFileFilter{Scan: repository.AdminFileScanError}, []string{"fBobMid"}},
		{"not scanned", repository.AdminFileFilter{Scan: repository.AdminFileScanNotScanned},
			[]string{"fBobNull", "fAnonSkip", "fAnonNever", "fAnonEmpty"}},
		{"uploaded last 24h", repository.AdminFileFilter{UploadedWithin: day}, []string{"fAnonSmall", "fBobNull"}},
		{"uploaded last 7d", repository.AdminFileFilter{UploadedWithin: 7 * day},
			[]string{"fAnonSmall", "fBobNull", "fAlice1MiB", "fExpired", "fAnonSkip", "fAnonNever"}},
		{"uploaded over 30d ago", repository.AdminFileFilter{UploadedBefore: 30 * day}, []string{"fAnonEmpty", "fAliceBig"}},
		{"search alone", repository.AdminFileFilter{Search: "fbob"}, []string{"fBobNull", "fBobMid"}},
		{"search matches username", repository.AdminFileFilter{Search: "alic"}, []string{"fAlice1MiB", "fAliceBig"}},
		{"search + anonymous + not scanned", repository.AdminFileFilter{Search: "skip", Anonymous: true, Scan: repository.AdminFileScanNotScanned}, []string{"fAnonSkip"}},
		{"search OR stays grouped under AND", repository.AdminFileFilter{Search: "alice", Anonymous: true}, []string{}},
		{"user + size + status", repository.AdminFileFilter{UserID: &alice, MinSize: pgI64(pgGiB), Status: repository.AdminFileStatusNeverExpires}, []string{"fAliceBig"}},
		{"search wildcard is literal", repository.AdminFileFilter{Search: "%"}, []string{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := pgListCodes(t, repos, tt.filter); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %v\nwant %v", got, tt.want)
			}
		})
	}
}

func TestFileRepository_ListForAdmin_Sort(t *testing.T) {
	repos := setupTestRepos(t)
	pgSeedAdminFilterFixtures(t, repos)

	for sort, want := range map[string][]string{
		repository.AdminFileSortOldest:   {"fAliceBig", "fAnonEmpty", "fBobMid", "fAnonNever", "fAnonSkip", "fExpired", "fAlice1MiB", "fBobNull", "fAnonSmall"},
		repository.AdminFileSortLargest:  {"fAliceBig", "fBobNull", "fAnonSkip", "fBobMid", "fAnonEmpty", "fAlice1MiB", "fExpired", "fAnonNever", "fAnonSmall"},
		repository.AdminFileSortSmallest: {"fAnonSmall", "fAnonNever", "fExpired", "fAlice1MiB", "fAnonEmpty", "fBobMid", "fAnonSkip", "fBobNull", "fAliceBig"},
		repository.AdminFileSortExpiring: {"fExpired", "fBobNull", "fAlice1MiB", "fAnonSmall", "fAnonSkip", "fBobMid", "fAnonEmpty", "fAnonNever", "fAliceBig"},
	} {
		t.Run(sort, func(t *testing.T) {
			if got := pgListCodes(t, repos, repository.AdminFileFilter{Sort: sort}); !reflect.DeepEqual(got, want) {
				t.Errorf("got %v\nwant %v", got, want)
			}
		})
	}
}

func TestFileRepository_ListForAdmin_Pagination(t *testing.T) {
	repos := setupTestRepos(t)
	pgSeedAdminFilterFixtures(t, repos)

	filter := repository.AdminFileFilter{Anonymous: true, Sort: repository.AdminFileSortSmallest}
	files, total, err := repos.Files.ListForAdmin(context.Background(), filter, 2, 2)
	if err != nil {
		t.Fatalf("ListForAdmin: %v", err)
	}
	if total != 5 || len(files) != 2 || files[0].ClaimCode != "fExpired" || files[1].ClaimCode != "fAnonEmpty" {
		t.Errorf("page = %+v (total %d), want fExpired, fAnonEmpty of 5", files, total)
	}
}

func TestFileRepository_ListForAdmin_InvalidFilter(t *testing.T) {
	repos := setupTestRepos(t)
	for _, f := range []repository.AdminFileFilter{
		{Status: "expired"},
		{Sort: "created_at; DROP TABLE files"},
		{UserID: pgI64(1), Anonymous: true},
	} {
		if _, _, err := repos.Files.ListForAdmin(context.Background(), f, 10, 0); !errors.Is(err, repository.ErrInvalidInput) {
			t.Errorf("ListForAdmin(%+v) err = %v, want ErrInvalidInput", f, err)
		}
	}
}

func TestFileRepository_GetAdminUploaders(t *testing.T) {
	repos := setupTestRepos(t)
	ctx := context.Background()

	empty, err := repos.Files.GetAdminUploaders(ctx)
	if err != nil {
		t.Fatalf("GetAdminUploaders (empty): %v", err)
	}
	if empty.AnonymousCount != 0 || empty.Users == nil || len(empty.Users) != 0 {
		t.Errorf("empty = %+v, want zero count and empty non-nil users", empty)
	}

	ids := pgSeedAdminFilterFixtures(t, repos)
	got, err := repos.Files.GetAdminUploaders(ctx)
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
