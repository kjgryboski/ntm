package cli

import (
	"github.com/Dicklesworthstone/ntm/internal/state"
	"path/filepath"
	"testing"
	"time"
)

func TestProviderMigrationPreservesSignedBytesUnknownRowsAndRejectsConflicts(t *testing.T) {
	source, err := state.Open(filepath.Join(t.TempDir(), "source.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	if err = source.Migrate(); err != nil {
		t.Fatal(err)
	}
	dest, err := state.Open(filepath.Join(t.TempDir(), "dest.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer dest.Close()
	if err = dest.Migrate(); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"a-complete", "z-unknown"} {
		if _, _, err = source.ClaimSendOperation(&state.SendOperation{OperationID: id, SessionName: primaryAssignmentScope, BindingHash: "exact", PayloadSHA256: "target"}); err != nil {
			t.Fatal(err)
		}
	}
	const signedBytes = "{\"signature\":\"fixture-only\", \"state\":\"completed\"}\n"
	if err = source.CompleteSendOperation("a-complete", primaryAssignmentScope, signedBytes, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if count, err := importProviderOperations(source, dest); err != nil || count != 2 {
		t.Fatalf("count=%d err=%v", count, err)
	}
	row, _ := dest.GetSendOperation("a-complete", primaryAssignmentScope)
	if row.OutcomeJSON != signedBytes {
		t.Fatal("signed bytes changed")
	}
	row, _ = dest.GetSendOperation("z-unknown", primaryAssignmentScope)
	if row.Status != state.SendOperationInProgress {
		t.Fatal("unknown operation promoted")
	}
	if count, err := importProviderOperations(source, dest); err != nil || count != 0 {
		t.Fatal("migration replay not idempotent")
	}
	if _, err = source.DB().Exec("UPDATE send_operations SET binding_hash='conflict' WHERE operation_id='z-unknown'"); err != nil {
		t.Fatal(err)
	}
	if _, err = importProviderOperations(source, dest); err == nil {
		t.Fatal("conflicting identity overwritten")
	}
	row, _ = dest.GetSendOperation("z-unknown", primaryAssignmentScope)
	if row.BindingHash != "exact" {
		t.Fatal("collision altered destination")
	}
}
