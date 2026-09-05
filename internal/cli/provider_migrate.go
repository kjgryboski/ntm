package cli

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/Dicklesworthstone/ntm/internal/config"
	"github.com/Dicklesworthstone/ntm/internal/providerqualification"
	"github.com/Dicklesworthstone/ntm/internal/state"
	"github.com/spf13/cobra"
)

// A migration copies immutable provider operation rows first and activates the
// profiles last. Unknown rows remain unknown; collisions never overwrite data.
func importProviderOperations(source, destination *state.Store) (int, error) {
	if source.Path() == destination.Path() {
		return 0, nil
	}
	if err := source.Migrate(); err != nil {
		return 0, err
	}
	if err := destination.Migrate(); err != nil {
		return 0, err
	}
	rows, err := source.DB().Query(`SELECT operation_id,session_name,binding_hash,payload_sha256,payload_bytes,status,outcome_json,created_at,completed_at FROM send_operations WHERE session_name LIKE 'provider:%' ORDER BY session_name,operation_id`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	tx, err := destination.DB().Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	count := 0
	for rows.Next() {
		var id, scope, binding, payload, status, outcome string
		var size int64
		var created time.Time
		var completed sql.NullTime
		if err = rows.Scan(&id, &scope, &binding, &payload, &size, &status, &outcome, &created, &completed); err != nil {
			return 0, err
		}
		var oldBinding, oldPayload, oldStatus, oldOutcome string
		var oldSize int64
		var oldCreated time.Time
		var oldCompleted sql.NullTime
		err = tx.QueryRow(`SELECT binding_hash,payload_sha256,payload_bytes,status,outcome_json,created_at,completed_at FROM send_operations WHERE operation_id=? AND session_name=?`, id, scope).Scan(&oldBinding, &oldPayload, &oldSize, &oldStatus, &oldOutcome, &oldCreated, &oldCompleted)
		if err == nil {
			if oldBinding != binding || oldPayload != payload || oldSize != size || oldStatus != status || oldOutcome != outcome || !oldCreated.Equal(created) || oldCompleted.Valid != completed.Valid || (completed.Valid && !oldCompleted.Time.Equal(completed.Time)) {
				return 0, errors.New("provider ledger collision; destination was not changed")
			}
			continue
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return 0, err
		}
		if _, err = tx.Exec(`INSERT INTO send_operations VALUES(?,?,?,?,?,?,?,?,?)`, id, scope, binding, payload, size, status, outcome, created, completed); err != nil {
			return 0, err
		}
		count++
	}
	if err = rows.Err(); err != nil {
		return 0, err
	}
	return count, tx.Commit()
}

func newProviderMigrateCmd() *cobra.Command {
	var sourcePath, destinationPath string
	var profiles []string
	var apply bool
	cmd := &cobra.Command{Use: "migrate", Short: "Copy exact provider profiles and their operation history into the normal configuration", Args: cobra.NoArgs}
	cmd.Flags().StringVar(&sourcePath, "from-config", "", "Existing source configuration")
	cmd.Flags().StringVar(&destinationPath, "to-config", "", "Existing destination configuration")
	cmd.Flags().StringSliceVar(&profiles, "profiles", nil, "Exact profile names to copy unchanged")
	cmd.Flags().BoolVar(&apply, "apply", false, "Copy history, back up configuration, and activate the reviewed profiles")
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		if !filepath.IsAbs(sourcePath) || !filepath.IsAbs(destinationPath) || sourcePath == destinationPath || len(profiles) == 0 {
			return errors.New("migration requires distinct absolute configurations and exact profiles")
		}
		source, err := config.Load(sourcePath)
		if err != nil {
			return err
		}
		destination, err := config.Load(destinationPath)
		if err != nil {
			return err
		}
		add := map[string]config.ProviderProfileConfig{}
		identities := map[string]string{}
		for _, name := range profiles {
			p, err := source.ProviderProfile(name)
			if err != nil {
				return err
			}
			id, err := p.Identity()
			if err != nil {
				return err
			}
			identities[name] = id.Hash()
			if existing, ok := destination.ProviderProfiles[name]; ok {
				if digestSafeJSON(existing) != digestSafeJSON(p) {
					return fmt.Errorf("destination profile %s differs; choose a new profile name", name)
				}
				continue
			}
			add[name] = p
		}
		result := map[string]any{"source_config": sourcePath, "destination_config": destinationPath, "identities": identities, "applied": false, "generation_calls": 0}
		if !apply {
			return encodeIndentedJSON(cmd.OutOrStdout(), result)
		}
		before, err := os.ReadFile(destinationPath)
		if err != nil {
			return err
		}
		sourceBefore, err := os.ReadFile(sourcePath)
		if err != nil {
			return err
		}
		var appendix bytes.Buffer
		if len(add) > 0 {
			if err = toml.NewEncoder(&appendix).Encode(map[string]any{"provider_profiles": add}); err != nil {
				return err
			}
		}
		src, err := state.Open(filepath.Join(filepath.Dir(sourcePath), "state.db"))
		if err != nil {
			return err
		}
		defer src.Close()
		dst, err := state.Open(filepath.Join(filepath.Dir(destinationPath), "state.db"))
		if err != nil {
			return err
		}
		defer dst.Close()
		count, err := importProviderOperations(src, dst)
		if err != nil {
			return err
		}
		current, err := os.ReadFile(destinationPath)
		if err != nil || !bytes.Equal(current, before) {
			return errors.New("destination configuration changed during migration; copied history is retained, profiles were not activated")
		}
		current, err = os.ReadFile(sourcePath)
		if err != nil || !bytes.Equal(current, sourceBefore) {
			return errors.New("source configuration changed during migration; profiles were not activated")
		}
		if len(add) > 0 {
			backup := destinationPath + ".before-provider-migration-" + time.Now().UTC().Format("20060102T150405.000000000")
			f, err := os.OpenFile(backup, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if err != nil {
				return err
			}
			_, err = f.Write(before)
			closeErr := f.Close()
			if err != nil {
				return err
			}
			if closeErr != nil {
				return closeErr
			}
			candidate := backup + ".candidate"
			data := append(append(append([]byte{}, before...), '\n'), appendix.Bytes()...)
			if err = os.WriteFile(candidate, data, 0600); err != nil {
				return err
			}
			if _, err = config.Load(candidate); err != nil {
				return err
			}
			if err = os.Rename(candidate, destinationPath); err != nil {
				return err
			}
			result["config_backup"] = backup
		}
		result["applied"] = true
		result["operation_rows_copied"] = count
		result["source_config_sha256"] = sha256TextCLI(sourceBefore)
		return encodeIndentedJSON(cmd.OutOrStdout(), result)
	}
	return cmd
}

func newProviderReadinessCmd() *cobra.Command {
	var name string
	cmd := &cobra.Command{Use: "readiness", Short: "Show exact primary profile, credential freshness and workspace admission before assignment", Args: cobra.NoArgs}
	cmd.Flags().StringVar(&name, "profile", "", "Exact primary provider profile")
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		loaded := loadSelectedConfigOrDefault()
		if loaded == nil {
			return errors.New("configuration unavailable")
		}
		p, err := loaded.ProviderProfile(name)
		if err != nil {
			return err
		}
		id, transport, err := validatePrimaryComparisonProfile(p)
		if err != nil {
			return err
		}
		out := map[string]any{"profile": name, "provider": id.Provider(), "runtime": id.Runtime(), "requested_model": id.Model(), "identity_sha256": id.Hash(), "billing_class": id.BillingClass(), "workspace_admission": false, "generation_calls": 0}
		credential := "auth.json"
		if id.Runtime() == "claude" {
			credential = ".credentials.json"
		}
		credentialPath := filepath.Join(p.RuntimeHome, credential)
		info, readErr := os.Lstat(credentialPath)
		var data []byte
		if readErr == nil && info.Mode().IsRegular() && info.Size() > 0 && info.Size() <= 1<<20 {
			data, readErr = os.ReadFile(credentialPath)
		}
		fresh := readErr == nil && primaryComparisonCredentialValid(data, id.Runtime()) && primaryCredentialSnapshotFresh(data, id.Runtime(), time.Now())
		if id.Runtime() == "claude" {
			var snapshot struct {
				OAuth struct {
					ExpiresAt int64 `json:"expiresAt"`
				} `json:"claudeAiOauth"`
			}
			if json.Unmarshal(data, &snapshot) == nil && snapshot.OAuth.ExpiresAt > 0 {
				out["credential_expires_at"] = time.UnixMilli(snapshot.OAuth.ExpiresAt).UTC()
			}
		} else {
			out["credential_freshness_scope"] = "OAuth snapshot present; runtime owns token refresh"
		}
		for i := range data {
			data[i] = 0
		}
		out["credential_fresh"] = fresh
		digest, hashErr := hashProviderSessionExecutable(p.Command)
		ctx, cancel := context.WithTimeout(providerCommandContext(cmd), 5*time.Second)
		defer cancel()
		version, versionErr := primaryPinnedRuntimeVersion(ctx, p)
		if hashErr != nil || versionErr != nil || digest != p.RuntimeSHA256 || !versionMatches(version, p.RuntimeVersion) {
			out["reason"] = "runtime_pin_mismatch"
			return encodeIndentedJSON(cmd.OutOrStdout(), out)
		}
		companion := ""
		if id.Runtime() == "codex" {
			companion, err = hashProviderSessionExecutable(filepath.Join(filepath.Dir(p.Command), "codex-code-mode-host"))
			if err != nil {
				out["reason"] = "companion_unavailable"
				return encodeIndentedJSON(cmd.OutOrStdout(), out)
			}
		}
		sign, err := providerProfilePinnedSigner(p)
		if err != nil {
			out["reason"] = "signer_unavailable"
			return encodeIndentedJSON(cmd.OutOrStdout(), out)
		}
		trusted, err := preflightProviderReceiptSignerMetadata(providerCommandContext(cmd), sign)
		if err != nil {
			out["reason"] = "signer_preflight_failed"
			return encodeIndentedJSON(cmd.OutOrStdout(), out)
		}
		_, err = authorizeProviderOperation(providerOperationAuthorization{Identity: id, Transport: transport, PolicySHA256: primaryWorkspacePolicySHA(transport, companion), RuntimeVersion: p.RuntimeVersion, RuntimeSHA256: p.RuntimeSHA256, Operation: providerOperationWorkspaceWrite, MaxQualificationAge: 24 * time.Hour, TrustedSigner: trusted.KeyMetadata})
		out["qualification_max_age_hours"] = 24
		if receipt, _, loadErr := providerqualification.LoadLatestForTransport("", id.Hash(), transport); loadErr == nil {
			out["qualification_expires_at"] = receipt.CompletedAt.Add(24 * time.Hour)
		}
		out["workspace_admission"] = err == nil && fresh
		if err != nil {
			out["reason"] = "qualification_missing_stale_or_mismatched"
		} else if !fresh {
			out["reason"] = "credential_snapshot_requires_refresh"
		} else {
			out["reason"] = "ready"
		}
		return encodeIndentedJSON(cmd.OutOrStdout(), out)
	}
	return cmd
}
