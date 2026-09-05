package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/Dicklesworthstone/ntm/internal/config"
	"github.com/Dicklesworthstone/ntm/internal/provider"
	"github.com/Dicklesworthstone/ntm/internal/providercredential"
)

const providerCredentialOutputSchema = "ntm.provider-credential.v1"

type providerCredentialStore interface {
	Get(context.Context, string) ([]byte, error)
	Put(context.Context, string, []byte) error
	Delete(context.Context, string) error
	Status(context.Context, string) (providercredential.Status, error)
}

type providerCredentialDependencies struct {
	loadConfig func() *config.Config
	store      providerCredentialStore
}

var providerCredentialDeps = providerCredentialDependencies{
	loadConfig: loadSelectedConfigOrDefault,
	store:      providercredential.New(),
}

type providerCredentialOptions struct {
	profile string
	stdin   bool
	yes     bool
}

type providerCredentialOutput struct {
	SchemaVersion   string                    `json:"schema_version"`
	Success         bool                      `json:"success"`
	Profile         string                    `json:"profile"`
	IdentitySHA256  string                    `json:"identity_sha256"`
	CredentialID    string                    `json:"credential_id_sha256"`
	Action          string                    `json:"action"`
	Status          providercredential.Status `json:"status"`
	CredentialClass string                    `json:"credential_class"`
	Entitlement     string                    `json:"entitlement"`
	ErrorSHA256     string                    `json:"error_sha256,omitempty"`
}

func newProviderCredentialCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "credential", Short: "Manage exact provider credentials in native OS secure storage"}
	cmd.AddCommand(newProviderCredentialStatusCmd(), newProviderCredentialSetCmd(), newProviderCredentialRemoveCmd(), newProviderCredentialRefreshSnapshotCmd())
	return cmd
}

// Refresh uses an already refreshed account-owner snapshot. It does not rotate
// OAuth tokens from a disposable home or switch the user's active account.
func newProviderCredentialRefreshSnapshotCmd() *cobra.Command {
	var name, sourceHome string
	var apply bool
	cmd := &cobra.Command{Use: "refresh-snapshot", Short: "Preview or copy a fresh primary OAuth snapshot with unchanged local account binding", Args: cobra.NoArgs}
	cmd.Flags().StringVar(&name, "profile", "", "Exact primary provider profile")
	cmd.Flags().StringVar(&sourceHome, "source-home", "", "Absolute account-owner runtime home containing an already refreshed snapshot")
	cmd.Flags().BoolVar(&apply, "apply", false, "Apply after continuity and freshness checks, preserving a private backup")
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		cfg := loadSelectedConfigOrDefault()
		if cfg == nil {
			return errors.New("configuration unavailable")
		}
		p, err := cfg.ProviderProfile(name)
		if err != nil {
			return err
		}
		id, _, err := validatePrimaryComparisonProfile(p)
		if err != nil {
			return err
		}
		if !filepath.IsAbs(sourceHome) || filepath.Clean(sourceHome) == filepath.Clean(p.RuntimeHome) {
			return errors.New("source must be a distinct absolute account-owner home")
		}
		filename := "auth.json"
		if id.Runtime() == "claude" {
			filename = ".credentials.json"
		}
		destination, source := filepath.Join(p.RuntimeHome, filename), filepath.Join(sourceHome, filename)
		old, err := readPrimaryCredentialSnapshot(destination)
		if err != nil {
			return err
		}
		defer zeroProviderSecret(old)
		next, err := readPrimaryCredentialSnapshot(source)
		if err != nil {
			return err
		}
		defer zeroProviderSecret(next)
		scope, err := primaryCredentialRefreshContinuity(old, next, id.Runtime(), time.Now())
		if err != nil {
			return err
		}
		out := map[string]any{"profile": name, "identity_sha256": id.Hash(), "continuity_scope": scope, "applied": false, "generation_calls": 0, "qualification_rewritten": false}
		if apply {
			backup, err := applyPrimaryCredentialSnapshot(destination, old, next)
			if err != nil {
				return err
			}
			out["applied"], out["backup_path_sha256"] = true, sha256StringCLI(backup)
		}
		return encodeIndentedJSON(cmd.OutOrStdout(), out)
	}
	return cmd
}

func readPrimaryCredentialSnapshot(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 1<<20 {
		return nil, errors.New("credential snapshot must be a bounded regular file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("credential snapshot could not be read")
	}
	return data, nil
}

func primaryCredentialRefreshContinuity(old, next []byte, runtime string, now time.Time) (string, error) {
	if !primaryComparisonCredentialValid(old, runtime) || !primaryComparisonCredentialValid(next, runtime) || !primaryCredentialSnapshotFresh(next, runtime, now) {
		return "", errors.New("fresh subscription OAuth snapshot required; API credentials and expired snapshots are rejected")
	}
	var before, after struct {
		Tokens struct {
			AccountID string `json:"account_id"`
		} `json:"tokens"`
		OAuth struct {
			RefreshToken     string `json:"refreshToken"`
			SubscriptionType string `json:"subscriptionType"`
		} `json:"claudeAiOauth"`
	}
	if json.Unmarshal(old, &before) != nil || json.Unmarshal(next, &after) != nil {
		return "", errors.New("invalid credential snapshots")
	}
	if runtime == "codex" && before.Tokens.AccountID != "" && before.Tokens.AccountID == after.Tokens.AccountID {
		return "local_account_id_match_profile_attested", nil
	}
	beforeHash, afterHash := sha256.Sum256([]byte(before.OAuth.RefreshToken)), sha256.Sum256([]byte(after.OAuth.RefreshToken))
	if runtime == "claude" && before.OAuth.RefreshToken != "" && subtle.ConstantTimeCompare(beforeHash[:], afterHash[:]) == 1 && before.OAuth.SubscriptionType == after.OAuth.SubscriptionType {
		return "local_refresh_lineage_match_profile_attested", nil
	}
	return "", errors.New("account continuity is not established; changed account IDs or rotated opaque Claude refresh tokens require fresh identity binding, not automatic qualification reuse")
}

func applyPrimaryCredentialSnapshot(destination string, old, next []byte) (string, error) {
	current, err := readPrimaryCredentialSnapshot(destination)
	if err != nil {
		return "", err
	}
	defer zeroProviderSecret(current)
	if !bytes.Equal(current, old) {
		return "", errors.New("credential changed during refresh; no snapshot replaced")
	}
	backup := destination + ".before-refresh-" + time.Now().UTC().Format("20060102T150405.000000000")
	f, err := os.OpenFile(backup, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return "", err
	}
	_, writeErr := f.Write(old)
	closeErr := f.Close()
	if err = errors.Join(writeErr, closeErr); err != nil {
		return "", err
	}
	candidate := backup + ".candidate"
	f, err = os.OpenFile(candidate, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return "", err
	}
	_, writeErr = f.Write(next)
	syncErr := f.Sync()
	closeErr = f.Close()
	if err = errors.Join(writeErr, syncErr, closeErr); err != nil {
		return "", err
	}
	current, err = readPrimaryCredentialSnapshot(destination)
	if err != nil {
		return "", err
	}
	defer zeroProviderSecret(current)
	if !bytes.Equal(current, old) {
		return "", errors.New("credential changed before activation; private backup retained")
	}
	if err = os.Rename(candidate, destination); err != nil {
		return "", err
	}
	return backup, nil
}

func newProviderCredentialStatusCmd() *cobra.Command {
	opts := providerCredentialOptions{}
	cmd := &cobra.Command{Use: "status", Short: "Inspect secret-free native credential status", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		return runProviderCredential(cmd, "status", opts, providerCredentialDeps)
	}}
	cmd.Flags().StringVar(&opts.profile, "profile", "", "Exact configured provider profile (required)")
	return cmd
}

func newProviderCredentialSetCmd() *cobra.Command {
	opts := providerCredentialOptions{}
	cmd := &cobra.Command{Use: "set", Short: "Read one credential from stdin into native OS secure storage", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		return runProviderCredential(cmd, "set", opts, providerCredentialDeps)
	}}
	cmd.Flags().StringVar(&opts.profile, "profile", "", "Exact configured provider profile (required)")
	cmd.Flags().BoolVar(&opts.stdin, "stdin", false, "Confirm that the credential is supplied on stdin, never as an argument")
	return cmd
}

func newProviderCredentialRemoveCmd() *cobra.Command {
	opts := providerCredentialOptions{}
	cmd := &cobra.Command{Use: "remove", Short: "Remove one exact provider credential from native OS secure storage", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		return runProviderCredential(cmd, "remove", opts, providerCredentialDeps)
	}}
	cmd.Flags().StringVar(&opts.profile, "profile", "", "Exact configured provider profile (required)")
	cmd.Flags().BoolVar(&opts.yes, "yes", false, "Confirm removal of this exact profile credential")
	return cmd
}

func runProviderCredential(cmd *cobra.Command, action string, opts providerCredentialOptions, deps providerCredentialDependencies) error {
	if strings.TrimSpace(opts.profile) == "" {
		return errors.New("provider credential requires an exact --profile")
	}
	if deps.loadConfig == nil || deps.store == nil {
		return errors.New("provider credential dependencies are incomplete")
	}
	cfg := deps.loadConfig()
	if cfg == nil {
		return errors.New("provider credential requires loaded configuration")
	}
	profile, err := cfg.ProviderProfile(opts.profile)
	if err != nil {
		return err
	}
	identity, err := profile.Identity()
	if err != nil {
		return err
	}
	id, err := providerCredentialIDForProfile(profile, identity)
	if err != nil {
		return err
	}
	ctx := providerCommandContext(cmd)
	output := providerCredentialOutput{
		SchemaVersion: providerCredentialOutputSchema, Profile: opts.profile, IdentitySHA256: identity.Hash(),
		CredentialID: sha256StringCLI(id), Action: action, CredentialClass: identity.CredentialClass(), Entitlement: identity.Entitlement(),
	}
	switch action {
	case "status":
		output.Status, err = deps.store.Status(ctx, id)
		output.Success = err == nil
	case "set":
		if !opts.stdin {
			return errors.New("provider credential set requires --stdin; secrets in command arguments are prohibited")
		}
		secret, readErr := io.ReadAll(io.LimitReader(cmd.InOrStdin(), (64<<10)+1))
		if readErr != nil {
			err = errors.New("read provider credential from stdin")
			break
		}
		secret = trimOneLineEnding(secret)
		if len(secret) == 0 || len(secret) > 64<<10 || hasCredentialWhitespace(secret) {
			zeroProviderSecret(secret)
			return errors.New("provider credential must be one non-empty line of at most 64 KiB")
		}
		err = deps.store.Put(ctx, id, secret)
		zeroProviderSecret(secret)
		if err == nil {
			output.Status, err = deps.store.Status(ctx, id)
		}
		output.Success = err == nil && output.Status.Available && output.Status.Present
	case "remove":
		if !opts.yes {
			return errors.New("provider credential remove requires --yes for the exact profile")
		}
		err = deps.store.Delete(ctx, id)
		if err == nil {
			output.Status, err = deps.store.Status(ctx, id)
		}
		output.Success = err == nil && output.Status.Available && !output.Status.Present
	default:
		return errors.New("unknown provider credential action")
	}
	if err != nil {
		output.ErrorSHA256 = safeErrorDigest(err)
	}
	if IsJSONOutput() {
		if encodeErr := encodeIndentedJSON(cmd.OutOrStdout(), output); encodeErr != nil {
			return encodeErr
		}
		if err != nil || !output.Success {
			return errJSONFailure
		}
		return nil
	}
	if _, writeErr := fmt.Fprintf(cmd.OutOrStdout(), "Provider credential %s: backend=%s available=%t present=%t evidence=%s\n", action, output.Status.Backend, output.Status.Available, output.Status.Present, output.Status.Evidence); writeErr != nil {
		return writeErr
	}
	return err
}

func providerCredentialID(identity provider.Identity) string {
	return providercredential.CanonicalID(identity)
}

// providerCredentialIDForProfile preserves the canonical native-API key
// namespace while requiring the explicitly configured opaque broker ID for
// Coding Plan Codex. This prevents a plan token from being written to, or read
// from, a native API identity slot.
func providerCredentialIDForProfile(profile config.ProviderProfileConfig, identity provider.Identity) (string, error) {
	if identity.Provider() == "zai" && identity.Entitlement() == provider.EntitlementCodexResponses {
		id := strings.TrimSpace(profile.BrokerCredentialID)
		if id == "" {
			return "", errors.New("Z.ai Coding Plan Codex profile requires broker_credential_id")
		}
		return id, nil
	}
	return providerCredentialID(identity), nil
}

func trimOneLineEnding(value []byte) []byte {
	if len(value) > 0 && value[len(value)-1] == '\n' {
		value = value[:len(value)-1]
		if len(value) > 0 && value[len(value)-1] == '\r' {
			value = value[:len(value)-1]
		}
	}
	return value
}

func hasCredentialWhitespace(value []byte) bool {
	for _, char := range value {
		if char <= ' ' || char == 0x7f {
			return true
		}
	}
	return false
}

func zeroProviderSecret(value []byte) {
	for i := range value {
		value[i] = 0
	}
}

func providerCredentialIDDigest(identity provider.Identity) string {
	sum := sha256.Sum256([]byte(providerCredentialID(identity)))
	return hex.EncodeToString(sum[:])
}
