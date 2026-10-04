package handlers

import (
	"context"
	"strconv"

	"github.com/fjmerc/safeshare/internal/audit"
	"github.com/fjmerc/safeshare/internal/config"
	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/repository"
)

// auditMaxIDs caps how many ids a bulk-action audit entry lists.
const auditMaxIDs = 100

// capIDs returns at most max of ids, so one bulk action can't write an
// unbounded audit entry.
func capIDs(ids []int64, max int) []int64 {
	if len(ids) > max {
		return ids[:max]
	}
	return ids
}

// idStr formats a numeric id for an audit entry's ResourceID.
func idStr(id int64) string { return strconv.FormatInt(id, 10) }

// tokenOwnerDetails describes whose token an admin acted on. token may be nil
// when it couldn't be read before the change.
func tokenOwnerDetails(token *models.APIToken) map[string]any {
	if token == nil {
		return nil
	}
	return map[string]any{"owner_id": token.UserID, "name": token.Name}
}

// recordAssemblyEvent writes an audit entry from the chunked-upload assembly
// worker, which has no HTTP request. Who uploaded comes from what the upload
// session stored when it was created: the uploader's address and account.
// audit.RecordFor strips all of it in anonymous mode.
func recordAssemblyEvent(ctx context.Context, cfg *config.Config, repos *repository.Repositories, up *models.PartialUpload, ev audit.Event) {
	if audit.Default() == nil {
		return
	}
	if up.UserID != nil && (cfg != nil && !cfg.IsAnonymousMode()) {
		ev.UserID = *up.UserID
		if u, err := repos.Users.GetByID(ctx, *up.UserID); err == nil && u != nil {
			ev.Username = u.Username
		}
	}
	audit.RecordFor(ctx, cfg, up.UploaderIP, "", ev)
}
