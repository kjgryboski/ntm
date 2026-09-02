package cli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/Dicklesworthstone/ntm/internal/config"
	"github.com/Dicklesworthstone/ntm/internal/providercredential"
)

type providerCredentialStoreFake struct {
	secret  []byte
	status  providercredential.Status
	getID   string
	putID   string
	deleted string
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
