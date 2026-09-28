package handlers

import (
	"testing"

	"github.com/fjmerc/safeshare/internal/utils"
)

// TestSetDecryptAdmission_NilAndNonNil covers the setter installed from
// main.go: it must accept both a nil budget (explicitly disabling the cap)
// and a real one, installing exactly what was passed.
func TestSetDecryptAdmission_NilAndNonNil(t *testing.T) {
	original := decryptAdmission
	t.Cleanup(func() { decryptAdmission = original })

	SetDecryptAdmission(nil)
	if decryptAdmission != nil {
		t.Errorf("SetDecryptAdmission(nil): decryptAdmission = %v, want nil", decryptAdmission)
	}

	budget := utils.NewDecryptAdmission(4096)
	SetDecryptAdmission(budget)
	if decryptAdmission != budget {
		t.Errorf("SetDecryptAdmission(budget): decryptAdmission = %p, want %p", decryptAdmission, budget)
	}
	if got := decryptAdmission.Capacity(); got != 4096 {
		t.Errorf("Capacity() = %d, want 4096", got)
	}

	// Re-installing nil after a non-nil budget must also work (not just on
	// the zero-value initial state).
	SetDecryptAdmission(nil)
	if decryptAdmission != nil {
		t.Errorf("SetDecryptAdmission(nil) after a non-nil install: decryptAdmission = %v, want nil", decryptAdmission)
	}
}
