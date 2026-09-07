package state

import (
	"database/sql"
	"errors"
	"time"
)

// ProviderCampaign is an operator-set ceiling, independent of configuration
// directories and individual operation ledgers. Attempts are never refunded.
type ProviderCampaign struct {
	ID                  string                      `json:"id"`
	Limit               int                         `json:"limit"`
	Used                int                         `json:"used"`
	AuthorizationSHA256 string                      `json:"authorization_sha256"`
	Conditions          []ProviderCampaignCondition `json:"conditions"`
}

type ProviderCampaignCondition struct {
	Ordinal             int    `json:"ordinal"`
	Purpose             string `json:"purpose"`
	IdentitySHA256      string `json:"identity_sha256"`
	AuthorizationSHA256 string `json:"authorization_sha256"`
}

func (s *Store) ensureProviderCampaigns() error {
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS provider_campaigns (id TEXT PRIMARY KEY, attempt_limit INTEGER NOT NULL, authorization_sha256 TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS provider_campaign_authorizations (campaign TEXT NOT NULL, attempt_limit INTEGER NOT NULL, evidence TEXT NOT NULL, occurred_at TEXT NOT NULL, PRIMARY KEY(campaign, attempt_limit));
CREATE TABLE IF NOT EXISTS provider_campaign_attempts (campaign TEXT NOT NULL, attempt TEXT NOT NULL, identity_sha256 TEXT NOT NULL, evidence_sha256 TEXT NOT NULL, occurred_at TEXT NOT NULL, PRIMARY KEY(campaign, attempt));`)
	if err == nil {
		_, err = s.db.Exec(`CREATE TABLE IF NOT EXISTS provider_campaign_conditions (campaign TEXT NOT NULL, ordinal INTEGER NOT NULL, purpose TEXT NOT NULL, identity_sha256 TEXT NOT NULL, authorization_sha256 TEXT NOT NULL, PRIMARY KEY(campaign, ordinal));`)
	}
	return err
}

// BindProviderCampaignCondition narrows an unspent slot permanently. Workspace
// purposes are emitted only by controller routes after qualification admission.
func (s *Store) BindProviderCampaignCondition(id string, ordinal int, purpose, identity, authorization string) error {
	if ordinal < 1 || (purpose != "workspace" && purpose != "resume" && purpose != "qualification") || len(identity) != 64 || len(authorization) != 64 {
		return errors.New("invalid campaign condition")
	}
	if err := s.ensureProviderCampaigns(); err != nil {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var limit, used int
	if err = tx.QueryRow(`SELECT attempt_limit,(SELECT count(*) FROM provider_campaign_attempts WHERE campaign=?) FROM provider_campaigns WHERE id=?`, id, id).Scan(&limit, &used); err != nil {
		return err
	}
	if ordinal <= used || ordinal > limit {
		return errors.New("condition must bind an unspent authorized slot")
	}
	if _, err = tx.Exec("INSERT INTO provider_campaign_conditions VALUES(?,?,?,?,?)", id, ordinal, purpose, identity, authorization); err != nil {
		return errors.New("campaign condition already bound or could not be persisted")
	}
	return tx.Commit()
}

// ConfigureProviderCampaign requires compare-and-swap authorization for an
// increase. A repeated create never silently increases a campaign's ceiling.
func (s *Store) ConfigureProviderCampaign(id string, limit, expected int, evidence string) error {
	if id == "" || limit < 1 || limit > 100 || expected < 0 || len(evidence) != 64 {
		return errors.New("invalid campaign authorization")
	}
	if err := s.ensureProviderCampaigns(); err != nil {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var current int
	err = tx.QueryRow("SELECT attempt_limit FROM provider_campaigns WHERE id=?", id).Scan(&current)
	if errors.Is(err, sql.ErrNoRows) {
		if expected != 0 {
			return errors.New("campaign does not exist")
		}
		_, err = tx.Exec("INSERT INTO provider_campaigns VALUES(?,?,?)", id, limit, evidence)
	} else if err == nil {
		if expected != current || limit <= current {
			return errors.New("campaign exists; increasing the ceiling requires its current limit and new authorization")
		}
		_, err = tx.Exec("UPDATE provider_campaigns SET attempt_limit=?, authorization_sha256=? WHERE id=?", limit, evidence, id)
	}
	if err != nil {
		return err
	}
	if _, err = tx.Exec("INSERT INTO provider_campaign_authorizations VALUES(?,?,?,?)", id, limit, evidence, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) ProviderCampaign(id string) (ProviderCampaign, error) {
	out := ProviderCampaign{ID: id}
	if err := s.ensureProviderCampaigns(); err != nil {
		return out, err
	}
	err := s.db.QueryRow(`SELECT attempt_limit,authorization_sha256,(SELECT count(*) FROM provider_campaign_attempts WHERE campaign=?) FROM provider_campaigns WHERE id=?`, id, id).Scan(&out.Limit, &out.AuthorizationSHA256, &out.Used)
	if err != nil {
		return out, err
	}
	rows, err := s.db.Query("SELECT ordinal,purpose,identity_sha256,authorization_sha256 FROM provider_campaign_conditions WHERE campaign=? ORDER BY ordinal", id)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	out.Conditions = []ProviderCampaignCondition{}
	for rows.Next() {
		var c ProviderCampaignCondition
		if err = rows.Scan(&c.Ordinal, &c.Purpose, &c.IdentitySHA256, &c.AuthorizationSHA256); err != nil {
			return out, err
		}
		out.Conditions = append(out.Conditions, c)
	}
	return out, rows.Err()
}

// ReserveProviderCampaignAttempt commits before provider dispatch. A process
// crash, signing failure, or retry cannot erase this charge or replay its ID.
func (s *Store) ReserveProviderCampaignAttempt(id, attempt, identity, evidence string) error {
	return s.ReserveProviderCampaignPurpose(id, attempt, identity, evidence, "experiment")
}

func (s *Store) ReserveProviderCampaignPurpose(id, attempt, identity, evidence, purpose string) error {
	if id == "" || attempt == "" || len(identity) != 64 || len(evidence) != 64 {
		return errors.New("campaign attempt binding is incomplete")
	}
	if err := s.ensureProviderCampaigns(); err != nil {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var limit, used int
	if err = tx.QueryRow("SELECT attempt_limit FROM provider_campaigns WHERE id=?", id).Scan(&limit); err != nil {
		return err
	}
	if err = tx.QueryRow("SELECT count(*) FROM provider_campaign_attempts WHERE campaign=?", id).Scan(&used); err != nil {
		return err
	}
	if used >= limit {
		return errors.New("campaign attempt budget exhausted; an explicit ceiling increase is required")
	}
	var requiredPurpose, requiredIdentity string
	err = tx.QueryRow("SELECT purpose,identity_sha256 FROM provider_campaign_conditions WHERE campaign=? AND ordinal=?", id, used+1).Scan(&requiredPurpose, &requiredIdentity)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if err == nil && (purpose != requiredPurpose || identity != requiredIdentity) {
		return errors.New("campaign slot condition denied: operation purpose or identity differs; unused slot is not retry authorization")
	}
	if _, err = tx.Exec("INSERT INTO provider_campaign_attempts VALUES(?,?,?,?,?)", id, attempt, identity, evidence, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		return errors.New("campaign attempt already reserved or could not be persisted; do not replay")
	}
	return tx.Commit()
}
