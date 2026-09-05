package state

import (
	"database/sql"
	"errors"
	"time"
)

// ProviderCampaign is an operator-set ceiling, independent of configuration
// directories and individual operation ledgers. Attempts are never refunded.
type ProviderCampaign struct {
	ID                  string `json:"id"`
	Limit               int    `json:"limit"`
	Used                int    `json:"used"`
	AuthorizationSHA256 string `json:"authorization_sha256"`
}

func (s *Store) ensureProviderCampaigns() error {
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS provider_campaigns (id TEXT PRIMARY KEY, attempt_limit INTEGER NOT NULL, authorization_sha256 TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS provider_campaign_authorizations (campaign TEXT NOT NULL, attempt_limit INTEGER NOT NULL, evidence TEXT NOT NULL, occurred_at TEXT NOT NULL, PRIMARY KEY(campaign, attempt_limit));
CREATE TABLE IF NOT EXISTS provider_campaign_attempts (campaign TEXT NOT NULL, attempt TEXT NOT NULL, identity_sha256 TEXT NOT NULL, evidence_sha256 TEXT NOT NULL, occurred_at TEXT NOT NULL, PRIMARY KEY(campaign, attempt));`)
	return err
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
	return out, err
}

// ReserveProviderCampaignAttempt commits before provider dispatch. A process
// crash, signing failure, or retry cannot erase this charge or replay its ID.
func (s *Store) ReserveProviderCampaignAttempt(id, attempt, identity, evidence string) error {
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
	if _, err = tx.Exec("INSERT INTO provider_campaign_attempts VALUES(?,?,?,?,?)", id, attempt, identity, evidence, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		return errors.New("campaign attempt already reserved or could not be persisted; do not replay")
	}
	return tx.Commit()
}
