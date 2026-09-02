package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"

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
	cmd.AddCommand(newProviderCredentialStatusCmd(), newProviderCredentialSetCmd(), newProviderCredentialRemoveCmd())
	return cmd
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
	id := providerCredentialID(identity)
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
	return "ntm." + identity.Provider() + "." + identity.Entitlement() + "." + identity.Hash()
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
