package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/Dicklesworthstone/ntm/internal/config"
	"github.com/Dicklesworthstone/ntm/internal/state"
)

func TestProviderMigrationAppendsToExistingProfileTables(t *testing.T) {
	profile := config.ProviderProfileConfig{Provider: "openai", AccountAlias: "explicit-account", Model: "gpt-6-astra", Endpoint: "https://chatgpt.com/backend-api/codex", Runtime: "codex", CredentialClass: "oauth", BillingClass: "subscription", Entitlement: "primary_cli", Command: "/bin/codex", RuntimeHome: "/isolated/account", RuntimeVersion: "0.153.0", RuntimeSHA256: strings.Repeat("a", 64), ConfigSHA256: strings.Repeat("b", 64), AutomationPolicy: primaryComparisonPolicy, ExactTargetOnly: true}
	source := filepath.Join(t.TempDir(), "config.toml")
	destination := filepath.Join(t.TempDir(), "config.toml")
	writeConfig := func(path, name string) []byte {
		t.Helper()
		var data bytes.Buffer
		if err := toml.NewEncoder(&data).Encode(map[string]any{"provider_profiles": map[string]config.ProviderProfileConfig{name: profile}}); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data.Bytes(), 0600); err != nil {
			t.Fatal(err)
		}
		return append([]byte(nil), data.Bytes()...)
	}
	writeConfig(source, "new.account")
	before := writeConfig(destination, "existing")
	run := func() error {
		cmd := newProviderMigrateCmd()
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetArgs([]string{"--from-config", source, "--to-config", destination, "--profiles", "new.account", "--apply"})
		return cmd.Execute()
	}
	if err := run(); err != nil {
		t.Fatal(err)
	}
	loaded, err := config.Load(destination)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.ProviderProfiles) != 2 || !reflect.DeepEqual(loaded.ProviderProfiles["new.account"], profile) || !reflect.DeepEqual(loaded.ProviderProfiles["existing"], profile) {
		t.Fatal("migration changed or nested an exact profile")
	}
	after, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(after, before) {
		t.Fatal("existing configuration bytes changed")
	}
	if err := run(); err != nil {
		t.Fatal(err)
	}
	replayed, err := os.ReadFile(destination)
	if err != nil || !bytes.Equal(after, replayed) {
		t.Fatal("replay changed configuration")
	}
	profile.Model = "different-model"
	writeConfig(source, "new.account")
	if err := run(); err == nil {
		t.Fatal("conflicting profile accepted")
	}
	rejected, err := os.ReadFile(destination)
	if err != nil || !bytes.Equal(after, rejected) {
		t.Fatal("failed migration changed active configuration")
	}
}

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
