// Package providertelemetry persists redaction-safe provider observations.
// Its record schema deliberately has no prompt, output, path, credential, or
// free-form diagnostic field.
package providertelemetry

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const SchemaVersion = "ntm.provider-telemetry.v1"

const (
	defaultMaxObservations = 1024
	maxObservations        = 4096
	maxLoadLimit           = 256
	maxObservationBytes    = 16 << 10
)

var (
	ErrInvalidObservation = errors.New("provider telemetry observation is invalid")
	ErrStateCapacity      = errors.New("provider telemetry state capacity reached")
	ErrRecordCollision    = errors.New("provider telemetry observation identifier collision")
	ErrStateUnavailable   = errors.New("provider telemetry state is unavailable")
)

var safePart = regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]{0,127}$`)
var sha256Hex = regexp.MustCompile(`^[a-f0-9]{64}$`)
var observationName = regexp.MustCompile(`^obs-([a-f0-9]{32})\.json$`)

// Observation is a versioned, receipt-safe measurement. Every string field is
// constrained to a low-entropy identifier grammar; provider error detail must
// be classified before it reaches this boundary.
type Observation struct {
	SchemaVersion               string      `json:"schema_version"`
	ID                          string      `json:"id"`
	ObservedAt                  time.Time   `json:"observed_at"`
	IdentitySHA256              string      `json:"identity_sha256"`
	Model                       string      `json:"model"`
	Transport                   string      `json:"transport"`
	Adapter                     string      `json:"adapter"`
	Runtime                     string      `json:"runtime"`
	PolicySHA256                string      `json:"policy_sha256"`
	CompatibilityFixtureVersion string      `json:"compatibility_fixture_version"`
	LatencyMicros               int64       `json:"latency_micros"`
	InputTokens                 int64       `json:"input_tokens"`
	OutputTokens                int64       `json:"output_tokens"`
	CachedTokens                int64       `json:"cached_tokens"`
	CostMicros                  *int64      `json:"cost_micros,omitempty"`
	ProviderErrorClass          string      `json:"provider_error_class,omitempty"`
	Quota                       QuotaFact   `json:"quota"`
	Circuit                     CircuitFact `json:"circuit"`
	NoFailover                  bool        `json:"no_failover"`
}

// QuotaFact carries only normalized quota state and scalar facts. It never
// retains a provider response or account/billing identifier.
type QuotaFact struct {
	State     string     `json:"state"`
	Remaining *int64     `json:"remaining,omitempty"`
	ResetAt   *time.Time `json:"reset_at,omitempty"`
}

// CircuitFact is a local admission-control observation, not a claim about the
// provider's internal circuit state.
type CircuitFact struct {
	State        string     `json:"state"`
	FailureCount uint32     `json:"failure_count"`
	OpenUntil    *time.Time `json:"open_until,omitempty"`
}

type Options struct {
	MaxObservations int
}

// Store writes one immutable JSON file per observation. root is intentionally
// never serialized into a record or returned by the API.
type Store struct {
	root string
	max  int
}

// DefaultStoreDir returns the per-user create-only telemetry directory. It is
// shared by execution writers and the read-only CLI, but opening it read-only
// never creates the directory.
func DefaultStoreDir() string {
	base := strings.TrimSpace(os.Getenv("XDG_STATE_HOME"))
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil || strings.TrimSpace(home) == "" {
			base = os.TempDir()
		} else {
			base = filepath.Join(home, ".local", "state")
		}
	}
	return filepath.Join(base, "ntm", "provider-telemetry")
}

// Open creates the bounded state directory if necessary. It does not inspect
// or export unrelated files in that directory.
func Open(root string, options Options) (*Store, error) {
	return open(root, options, true)
}

// OpenReadOnly opens an existing telemetry directory without creating it or
// changing its contents. Use it for inspection commands and dashboards.
func OpenReadOnly(root string, options Options) (*Store, error) {
	return open(root, options, false)
}

func open(root string, options Options, create bool) (*Store, error) {
	if strings.TrimSpace(root) == "" {
		return nil, ErrStateUnavailable
	}
	max := options.MaxObservations
	if max == 0 {
		max = defaultMaxObservations
	}
	if max < 1 || max > maxObservations {
		return nil, ErrStateCapacity
	}
	if create {
		if err := os.MkdirAll(root, 0o700); err != nil {
			return nil, ErrStateUnavailable
		}
	}
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		return nil, ErrStateUnavailable
	}
	return &Store{root: filepath.Clean(root), max: max}, nil
}

// Record validates and writes an observation with O_EXCL. Existing observation
// files are never replaced, updated, or removed.
func (s *Store) Record(ctx context.Context, observation Observation) (Observation, error) {
	if s == nil || s.root == "" {
		return Observation{}, ErrStateUnavailable
	}
	if ctx == nil || ctx.Err() != nil {
		return Observation{}, ErrStateUnavailable
	}
	if observation.SchemaVersion == "" {
		observation.SchemaVersion = SchemaVersion
	}
	if observation.ObservedAt.IsZero() {
		observation.ObservedAt = time.Now().UTC()
	}
	if observation.ID == "" {
		id, err := newID()
		if err != nil {
			return Observation{}, ErrStateUnavailable
		}
		observation.ID = id
	}
	if err := Validate(observation); err != nil {
		return Observation{}, err
	}
	count, err := s.observationCount()
	if err != nil {
		return Observation{}, err
	}
	if count >= s.max {
		return Observation{}, ErrStateCapacity
	}
	encoded, err := json.Marshal(observation)
	if err != nil || len(encoded) > maxObservationBytes {
		return Observation{}, ErrInvalidObservation
	}
	file, err := os.OpenFile(filepath.Join(s.root, observationFilename(observation.ID)), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return Observation{}, ErrRecordCollision
		}
		return Observation{}, ErrStateUnavailable
	}
	defer file.Close()
	if _, err := file.Write(encoded); err != nil {
		return Observation{}, ErrStateUnavailable
	}
	if err := file.Sync(); err != nil {
		return Observation{}, ErrStateUnavailable
	}
	return observation, nil
}

// LoadLatest returns at most limit validated observations, newest first. A
// malformed or unexpected observation is a fail-closed state error, not data
// to be silently skipped.
func (s *Store) LoadLatest(ctx context.Context, limit int) ([]Observation, error) {
	if s == nil || s.root == "" || ctx == nil || ctx.Err() != nil {
		return nil, ErrStateUnavailable
	}
	if limit < 1 || limit > maxLoadLimit {
		return nil, ErrInvalidObservation
	}
	names, err := s.observationNames()
	if err != nil {
		return nil, err
	}
	observations := make([]Observation, 0, min(limit, len(names)))
	for i := len(names) - 1; i >= 0 && len(observations) < limit; i-- {
		if err := ctx.Err(); err != nil {
			return nil, ErrStateUnavailable
		}
		observation, err := s.load(names[i])
		if err != nil {
			return nil, err
		}
		observations = append(observations, observation)
	}
	sort.SliceStable(observations, func(i, j int) bool { return observations[i].ObservedAt.After(observations[j].ObservedAt) })
	return observations, nil
}

type SummaryOptions struct {
	Now                    time.Time
	ExpectedFixtureVersion string
	CompatibilityMaxAge    time.Duration
}

type CompatibilitySummary struct {
	FixtureVersion string        `json:"fixture_version,omitempty"`
	Age            time.Duration `json:"age,omitempty"`
	Drifted        bool          `json:"drifted"`
	Stale          bool          `json:"stale"`
}

type Summary struct {
	SchemaVersion    string               `json:"schema_version"`
	ObservationCount int                  `json:"observation_count"`
	Latest           *Observation         `json:"latest,omitempty"`
	Compatibility    CompatibilitySummary `json:"compatibility"`
}

// Summarize provides a bounded health read without returning raw provider
// traffic. Drift compares the latest fixture version to an exact expected
// version; stale is evaluated only when CompatibilityMaxAge is positive.
func (s *Store) Summarize(ctx context.Context, options SummaryOptions) (Summary, error) {
	if s == nil || s.root == "" || ctx == nil || ctx.Err() != nil {
		return Summary{}, ErrStateUnavailable
	}
	if options.ExpectedFixtureVersion != "" && !safePart.MatchString(options.ExpectedFixtureVersion) {
		return Summary{}, ErrInvalidObservation
	}
	if options.CompatibilityMaxAge < 0 {
		return Summary{}, ErrInvalidObservation
	}
	names, err := s.observationNames()
	if err != nil {
		return Summary{}, err
	}
	result := Summary{SchemaVersion: SchemaVersion, ObservationCount: len(names)}
	if len(names) == 0 {
		return result, nil
	}
	latest, err := s.LoadLatest(ctx, 1)
	if err != nil {
		return Summary{}, err
	}
	result.Latest = &latest[0]
	now := options.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	age := now.Sub(latest[0].ObservedAt)
	if age < 0 {
		return Summary{}, ErrInvalidObservation
	}
	result.Compatibility = CompatibilitySummary{
		FixtureVersion: latest[0].CompatibilityFixtureVersion,
		Age:            age,
		Drifted:        options.ExpectedFixtureVersion != "" && latest[0].CompatibilityFixtureVersion != options.ExpectedFixtureVersion,
		Stale:          options.CompatibilityMaxAge > 0 && age > options.CompatibilityMaxAge,
	}
	return result, nil
}

// Validate rejects any malformed record before it reaches disk or a caller.
func Validate(observation Observation) error {
	if observation.SchemaVersion != SchemaVersion || !observationName.MatchString(observationFilename(observation.ID)) || observation.ObservedAt.IsZero() || observation.ObservedAt.Location() != time.UTC {
		return ErrInvalidObservation
	}
	for _, value := range []string{observation.Model, observation.Transport, observation.Adapter, observation.Runtime, observation.CompatibilityFixtureVersion, observation.Quota.State, observation.Circuit.State} {
		if !safePart.MatchString(value) {
			return ErrInvalidObservation
		}
	}
	if observation.ProviderErrorClass != "" && !safePart.MatchString(observation.ProviderErrorClass) {
		return ErrInvalidObservation
	}
	if !sha256Hex.MatchString(observation.IdentitySHA256) || !sha256Hex.MatchString(observation.PolicySHA256) {
		return ErrInvalidObservation
	}
	if observation.LatencyMicros < 0 || observation.InputTokens < 0 || observation.OutputTokens < 0 || observation.CachedTokens < 0 || observation.CachedTokens > observation.InputTokens {
		return ErrInvalidObservation
	}
	if observation.CostMicros != nil && *observation.CostMicros < 0 {
		return ErrInvalidObservation
	}
	if observation.Quota.Remaining != nil && *observation.Quota.Remaining < 0 {
		return ErrInvalidObservation
	}
	for _, timestamp := range []*time.Time{observation.Quota.ResetAt, observation.Circuit.OpenUntil} {
		if timestamp != nil && (timestamp.IsZero() || timestamp.Location() != time.UTC) {
			return ErrInvalidObservation
		}
	}
	return nil
}

func (s *Store) observationCount() (int, error) {
	names, err := s.observationNames()
	if err != nil {
		return 0, err
	}
	return len(names), nil
}

func (s *Store) observationNames() ([]string, error) {
	if s == nil || s.root == "" {
		return nil, ErrStateUnavailable
	}
	entries, err := os.ReadDir(s.root)
	if err != nil {
		return nil, ErrStateUnavailable
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if observationName.MatchString(entry.Name()) {
			names = append(names, entry.Name())
		}
	}
	if len(names) > s.max {
		return nil, ErrStateCapacity
	}
	sort.Strings(names)
	return names, nil
}

func (s *Store) load(name string) (Observation, error) {
	if !observationName.MatchString(name) {
		return Observation{}, ErrInvalidObservation
	}
	file, err := os.Open(filepath.Join(s.root, name))
	if err != nil {
		return Observation{}, ErrStateUnavailable
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, maxObservationBytes+1))
	decoder.DisallowUnknownFields()
	var observation Observation
	if err := decoder.Decode(&observation); err != nil {
		return Observation{}, ErrInvalidObservation
	}
	if decoder.Decode(&struct{}{}) != io.EOF || Validate(observation) != nil || name != observationFilename(observation.ID) {
		return Observation{}, ErrInvalidObservation
	}
	return observation, nil
}

func observationFilename(id string) string { return "obs-" + id + ".json" }

func newID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func min(left, right int) int {
	if left < right {
		return left
	}
	return right
}
