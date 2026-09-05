package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/Dicklesworthstone/ntm/internal/config"
	"github.com/Dicklesworthstone/ntm/internal/provider"
	"github.com/Dicklesworthstone/ntm/internal/providercredential"
)

func TestPrimarySnapshotRefreshPreservesAccountAndRejectsSwitchExpiryAndBilling(t *testing.T) {
	now := time.Now().UTC()
	claude := func(token, refresh string, expiry time.Time) []byte {
		data, _ := json.Marshal(map[string]any{"claudeAiOauth": map[string]any{"accessToken": token, "refreshToken": refresh, "expiresAt": expiry.UnixMilli(), "subscriptionType": "max"}})
		return data
	}
	old := claude("old-fixture", "same-lineage", now.Add(-time.Hour))
	fresh := claude("new-fixture", "same-lineage", now.Add(time.Hour))
	if _, err := primaryCredentialRefreshContinuity(old, fresh, "claude", now); err != nil {
		t.Fatal(err)
	}
	for _, next := range [][]byte{claude("new-fixture", "changed-account-or-rotation", now.Add(time.Hour)), claude("new-fixture", "same-lineage", now), []byte(`{"OPENAI_API_KEY":"fixture"}`)} {
		if _, err := primaryCredentialRefreshContinuity(old, next, "claude", now); err == nil {
			t.Fatal("unsafe credential replacement accepted")
		}
	}
	codex := func(account, token string) []byte {
		data, _ := json.Marshal(map[string]any{"auth_mode": "chatgpt", "tokens": map[string]string{"account_id": account, "access_token": token}})
		return data
	}
	if _, err := primaryCredentialRefreshContinuity(codex("one", "old"), codex("one", "new"), "codex", now); err != nil {
		t.Fatal(err)
	}
	if _, err := primaryCredentialRefreshContinuity(codex("one", "old"), codex("two", "new"), "codex", now); err == nil {
		t.Fatal("Codex account switch inherited qualification")
	}
	path := filepath.Join(t.TempDir(), "snapshot.json")
	if err := os.WriteFile(path, old, 0600); err != nil {
		t.Fatal(err)
	}
	backup, err := applyPrimaryCredentialSnapshot(path, old, fresh)
	if err != nil {
		t.Fatal(err)
	}
	retained, _ := os.ReadFile(backup)
	current, _ := os.ReadFile(path)
	if !bytes.Equal(retained, old) || !bytes.Equal(current, fresh) {
		t.Fatal("refresh lost backup or failed activation")
	}
	if _, err := applyPrimaryCredentialSnapshot(path, old, fresh); err == nil {
		t.Fatal("stale compare-and-swap accepted")
	}
}

type providerCredentialStoreFake struct {
	secret  []byte
	status  providercredential.Status
	getID   string
	putID   string
	deleted string
}

func TestProviderCredentialCodingPlanUsesConfiguredBrokerIDOnly(t *testing.T) {
	profile := config.ProviderProfileConfig{
		Provider: "zai", AccountAlias: "kevin", Model: "glm-5.3", Endpoint: "https://api.z.ai/api/v1", Runtime: "codex",
		CredentialClass: provider.CredentialClassCodingPlan, BillingClass: provider.BillingClassCodingPlan, Entitlement: provider.EntitlementCodexResponses,
		ConfigSHA256: strings.Repeat("a", 64), Command: "/usr/bin/codex", RuntimeHome: "/tmp/zai-codex", RuntimeVersion: "0.149.0", AutomationPolicy: provider.DefaultZAICodexAutomationPolicyName,
		ExactTargetOnly: true, ProbeRequired: true, BrokerCredentialID: "ntm.zai.coding_plan.kevin",
		RuntimeSHA256: strings.Repeat("b", 64), BrokerCommand: "/usr/bin/caam", BrokerCommandSHA256: strings.Repeat("c", 64),
		CredentialBridgeCommand: "/usr/bin/ntm-provider-bridge", CredentialBridgeCommandSHA256: strings.Repeat("d", 64),
	}
	identity, err := profile.Identity()
	if err != nil {
		t.Fatal(err)
	}
	id, err := providerCredentialIDForProfile(profile, identity)
	if err != nil || id != profile.BrokerCredentialID {
		t.Fatalf("id=%q err=%v", id, err)
	}
	profile.BrokerCredentialID = ""
	if _, err := providerCredentialIDForProfile(profile, identity); err == nil {
		t.Fatal("missing broker id accepted")
	}
	// Native profiles retain the canonical identity-derived namespace.
	native := providerNativeProfile()
	nativeID, err := providerCredentialIDForProfile(native, mustIdentity(t, native))
	if err != nil || !strings.HasPrefix(nativeID, "ntm.zai.native_api.") {
		t.Fatalf("native id=%q err=%v", nativeID, err)
	}
}

func mustIdentity(t *testing.T, profile config.ProviderProfileConfig) provider.Identity {
	t.Helper()
	id, err := profile.Identity()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func (f *providerCredentialStoreFake) Get(_ context.Context, id string) ([]byte, error) {
	f.getID = id
	if len(f.secret) == 0 {
		return nil, providercredential.ErrNotFound
	}
	return append([]byte(nil), f.secret...), nil
}
func (f *providerCredentialStoreFake) Put(_ context.Context, id string, secret []byte) error {
	f.putID, f.secret = id, append([]byte(nil), secret...)
	f.status = providercredential.Status{Backend: providercredential.BackendLinuxSecretTool, Available: true, Present: true, Evidence: providercredential.EvidenceOSProtectedProcessReadable}
	return nil
}
func (f *providerCredentialStoreFake) Delete(_ context.Context, id string) error {
	f.deleted, f.secret = id, nil
	f.status.Present = false
	return nil
}
func (f *providerCredentialStoreFake) Status(context.Context, string) (providercredential.Status, error) {
	return f.status, nil
}

func providerCredentialTestDeps(store providerCredentialStore) providerCredentialDependencies {
	return providerCredentialDependencies{loadConfig: func() *config.Config {
		return &config.Config{ProviderProfiles: map[string]config.ProviderProfileConfig{"zai-native": providerNativeProfile()}}
	}, store: store}
}

func TestProviderCredentialSetReadsOnlyStdinAndRedactsSecret(t *testing.T) {
	store := &providerCredentialStoreFake{}
	cmd := &cobra.Command{}
	cmd.SetIn(strings.NewReader("super-secret-key\n"))
	var output bytes.Buffer
	cmd.SetOut(&output)
	err := runProviderCredential(cmd, "set", providerCredentialOptions{profile: "zai-native", stdin: true}, providerCredentialTestDeps(store))
	if err != nil || string(store.secret) != "super-secret-key" || !strings.HasPrefix(store.putID, "ntm.zai.native_api.") || strings.Contains(output.String(), "super-secret") {
		t.Fatalf("err=%v id=%q secret=%q output=%q", err, store.putID, store.secret, output.String())
	}
}

func TestProviderCredentialSetRequiresExplicitStdinAndRejectsMultiline(t *testing.T) {
	store := &providerCredentialStoreFake{}
	deps := providerCredentialTestDeps(store)
	if err := runProviderCredential(&cobra.Command{}, "set", providerCredentialOptions{profile: "zai-native"}, deps); err == nil {
		t.Fatal("set without --stdin succeeded")
	}
	cmd := &cobra.Command{}
	cmd.SetIn(strings.NewReader("one\ntwo\n"))
	if err := runProviderCredential(cmd, "set", providerCredentialOptions{profile: "zai-native", stdin: true}, deps); err == nil || len(store.secret) != 0 {
		t.Fatalf("err=%v secret=%q", err, store.secret)
	}
}

func TestProviderCredentialRemoveRequiresConfirmation(t *testing.T) {
	store := &providerCredentialStoreFake{secret: []byte("secret"), status: providercredential.Status{Available: true, Present: true}}
	deps := providerCredentialTestDeps(store)
	if err := runProviderCredential(&cobra.Command{}, "remove", providerCredentialOptions{profile: "zai-native"}, deps); err == nil || store.deleted != "" {
		t.Fatalf("err=%v deleted=%q", err, store.deleted)
	}
	if err := runProviderCredential(&cobra.Command{}, "remove", providerCredentialOptions{profile: "zai-native", yes: true}, deps); err != nil || store.deleted == "" {
		t.Fatalf("err=%v deleted=%q", err, store.deleted)
	}
}

func TestProviderCredentialStatusFailureDoesNotExposeBackendError(t *testing.T) {
	store := providerCredentialErrorStore{err: errors.New("backend diagnostic secret")}
	cmd := &cobra.Command{}
	var output bytes.Buffer
	cmd.SetOut(&output)
	if err := runProviderCredential(cmd, "status", providerCredentialOptions{profile: "zai-native"}, providerCredentialTestDeps(store)); err == nil || strings.Contains(output.String(), "diagnostic") {
		t.Fatalf("err=%v output=%q", err, output.String())
	}
}

type providerCredentialErrorStore struct{ err error }

func (s providerCredentialErrorStore) Get(context.Context, string) ([]byte, error) { return nil, s.err }
func (s providerCredentialErrorStore) Put(context.Context, string, []byte) error   { return s.err }
func (s providerCredentialErrorStore) Delete(context.Context, string) error        { return s.err }
func (s providerCredentialErrorStore) Status(context.Context, string) (providercredential.Status, error) {
	return providercredential.Status{}, s.err
}
