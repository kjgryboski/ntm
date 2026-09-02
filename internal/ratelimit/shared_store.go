package ratelimit

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Dicklesworthstone/ntm/internal/provider"
	"github.com/shirou/gopsutil/v4/process"
)

// LocalSharedStore coordinates provider admission state between NTM processes
// on the same machine. The mkdir lock is atomic on the supported local file
// systems and is held only for the read-modify-write transaction. If this
// store cannot be used, AdmissionController deliberately reports its explicit
// process-local fallback rather than claiming shared quota control.
type LocalSharedStore struct {
	path           string
	lockTimeout    time.Duration
	lockStaleAfter time.Duration
	processExists  func(int32) (bool, error)
}

// admissionLease is stored under a random operation ID.  Owner PID is only a
// reclamation hint: expiry is the final safety bound when PID inspection is
// unavailable or a PID has been recycled.
type admissionLease struct {
	OwnerPID    int32     `json:"owner_pid"`
	OwnerID     string    `json:"owner_id"`
	OperationID string    `json:"operation_id"`
	ExpiresAt   time.Time `json:"expires_at"`
}

type admissionLockMetadata struct {
	OwnerPID  int32     `json:"owner_pid"`
	OwnerID   string    `json:"owner_id"`
	CreatedAt time.Time `json:"created_at"`
}

type persistedAdmissionState struct {
	// Running remains for backward-compatible on-disk decoding. It is always
	// recomputed from active leases before a state is used or written.
	Running             int                       `json:"running"`
	Leases              map[string]admissionLease `json:"leases,omitempty"`
	Tokens              float64                   `json:"tokens"`
	LastRefill          time.Time                 `json:"last_refill"`
	ConsecutiveFailures int                       `json:"consecutive_failures"`
	NextRetry           time.Time                 `json:"next_retry"`
	CircuitOpenUntil    time.Time                 `json:"circuit_open_until"`
	HalfOpenInFlight    bool                      `json:"half_open_in_flight"`
	TerminalReason      ErrorClass                `json:"terminal_reason"`
}

type persistedAdmissionFile struct {
	Version int                                `json:"version"`
	States  map[string]persistedAdmissionState `json:"states"`
}

func NewLocalSharedStore(path string) (*LocalSharedStore, error) {
	if path == "" || !filepath.IsAbs(path) {
		return nil, fmt.Errorf("shared admission store path must be absolute")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create shared admission store directory: %w", err)
	}
	return &LocalSharedStore{path: path, lockTimeout: 2 * time.Second, lockStaleAfter: 30 * time.Second, processExists: process.PidExists}, nil
}

func (s *LocalSharedStore) withState(scope provider.CapacityScope, now time.Time, capacity float64, leaseTTL time.Duration, fn func(*admissionState)) error {
	unlock, err := s.lock()
	if err != nil {
		return err
	}
	defer unlock()

	file, err := s.read()
	if err != nil {
		return err
	}
	stored, ok := file.States[scope.String()]
	state := admissionState{tokens: capacity, lastRefill: now}
	if ok {
		state = fromPersisted(stored)
	}
	s.reclaimLeases(&state, now, leaseTTL)
	fn(&state)
	if file.States == nil {
		file.States = make(map[string]persistedAdmissionState)
	}
	file.Version = 1
	file.States[scope.String()] = toPersisted(state)
	return s.write(file)
}

func (s *LocalSharedStore) snapshot(scope provider.CapacityScope, now time.Time) (admissionState, bool, error) {
	unlock, err := s.lock()
	if err != nil {
		return admissionState{}, false, err
	}
	defer unlock()
	file, err := s.read()
	if err != nil {
		return admissionState{}, false, err
	}
	stored, ok := file.States[scope.String()]
	if !ok {
		return admissionState{}, false, nil
	}
	state := fromPersisted(stored)
	// Snapshots participate in recovery too. Persisting the reclaimed state
	// makes a dead owner visible to every later controller, not just this one.
	before := len(state.leases)
	s.reclaimLeases(&state, now, 0)
	if len(state.leases) != before {
		file.States[scope.String()] = toPersisted(state)
		if err := s.write(file); err != nil {
			return admissionState{}, false, err
		}
	}
	return state, true, nil
}

func (s *LocalSharedStore) read() (persistedAdmissionFile, error) {
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return persistedAdmissionFile{Version: 1, States: make(map[string]persistedAdmissionState)}, nil
	}
	if err != nil {
		return persistedAdmissionFile{}, fmt.Errorf("read shared admission store: %w", err)
	}
	var file persistedAdmissionFile
	if err := json.Unmarshal(data, &file); err != nil || file.Version != 1 {
		if err == nil {
			err = fmt.Errorf("unsupported version %d", file.Version)
		}
		return persistedAdmissionFile{}, fmt.Errorf("decode shared admission store: %w", err)
	}
	if file.States == nil {
		file.States = make(map[string]persistedAdmissionState)
	}
	return file, nil
}

func (s *LocalSharedStore) write(file persistedAdmissionFile) error {
	data, err := json.Marshal(file)
	if err != nil {
		return fmt.Errorf("encode shared admission store: %w", err)
	}
	temp, err := os.CreateTemp(filepath.Dir(s.path), ".ntm-provider-capacity-*.tmp")
	if err != nil {
		return fmt.Errorf("create shared admission temp file: %w", err)
	}
	tempName := temp.Name()
	defer os.Remove(tempName)
	if err := temp.Chmod(0o600); err != nil {
		temp.Close()
		return fmt.Errorf("protect shared admission temp file: %w", err)
	}
	if _, err := temp.Write(data); err != nil {
		temp.Close()
		return fmt.Errorf("write shared admission temp file: %w", err)
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return fmt.Errorf("sync shared admission temp file: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close shared admission temp file: %w", err)
	}
	if err := replaceAdmissionFile(tempName, s.path); err != nil {
		return fmt.Errorf("atomically replace shared admission store: %w", err)
	}
	return nil
}

func (s *LocalSharedStore) lock() (func(), error) {
	lockPath := s.path + ".lock"
	deadline := time.Now().Add(s.lockTimeout)
	for {
		if err := os.Mkdir(lockPath, 0o700); err == nil {
			ownerID, ownerErr := newLockOwnerID()
			if ownerErr != nil {
				_ = os.Remove(lockPath)
				return nil, ownerErr
			}
			metadata := admissionLockMetadata{OwnerPID: int32(os.Getpid()), OwnerID: ownerID, CreatedAt: time.Now().UTC()}
			encoded, marshalErr := json.Marshal(metadata)
			if marshalErr != nil {
				_ = os.Remove(lockPath)
				return nil, fmt.Errorf("encode shared admission lock metadata: %w", marshalErr)
			}
			if writeErr := os.WriteFile(filepath.Join(lockPath, "owner.json"), encoded, 0o600); writeErr != nil {
				_ = os.Remove(lockPath)
				return nil, fmt.Errorf("write shared admission lock metadata: %w", writeErr)
			}
			return func() { _ = s.releaseLock(lockPath, ownerID) }, nil
		} else if !errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("acquire shared admission lock: %w", err)
		}
		if reclaimed, reclaimErr := s.reclaimStaleLock(lockPath, time.Now().UTC()); reclaimErr != nil {
			return nil, reclaimErr
		} else if reclaimed {
			continue
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("shared admission lock timed out")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func newLockOwnerID() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate shared admission lock owner id: %w", err)
	}
	return hex.EncodeToString(raw), nil
}

// releaseLock removes only the exact directory this owner created. If a
// contender replaced the path after an external deletion, metadata mismatch
// leaves that new lock untouched.
func (s *LocalSharedStore) releaseLock(lockPath, ownerID string) error {
	data, err := os.ReadFile(filepath.Join(lockPath, "owner.json"))
	if err != nil {
		return nil
	}
	var metadata admissionLockMetadata
	if json.Unmarshal(data, &metadata) != nil || metadata.OwnerID != ownerID || metadata.OwnerPID != int32(os.Getpid()) {
		return nil
	}
	quarantine := fmt.Sprintf("%s.release-%d-%d", lockPath, os.Getpid(), time.Now().UnixNano())
	if err := os.Rename(lockPath, quarantine); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("quarantine owned shared admission lock: %w", err)
	}
	if err := os.RemoveAll(quarantine); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove owned shared admission lock: %w", err)
	}
	return nil
}

func toPersisted(state admissionState) persistedAdmissionState {
	state.running = len(state.leases)
	return persistedAdmissionState{Running: state.running, Leases: state.leases, Tokens: state.tokens, LastRefill: state.lastRefill, ConsecutiveFailures: state.consecutiveFailures, NextRetry: state.nextRetry, CircuitOpenUntil: state.circuitOpenUntil, HalfOpenInFlight: state.halfOpenInFlight, TerminalReason: state.terminalReason}
}

func fromPersisted(state persistedAdmissionState) admissionState {
	leases := state.Leases
	if leases == nil {
		leases = make(map[string]admissionLease)
	}
	return admissionState{running: len(leases), leases: leases, tokens: state.Tokens, lastRefill: state.LastRefill, consecutiveFailures: state.ConsecutiveFailures, nextRetry: state.NextRetry, circuitOpenUntil: state.CircuitOpenUntil, halfOpenInFlight: state.HalfOpenInFlight, terminalReason: state.TerminalReason}
}

func (s *LocalSharedStore) reclaimLeases(state *admissionState, now time.Time, _ time.Duration) {
	if state.leases == nil {
		state.leases = make(map[string]admissionLease)
	}
	for id, lease := range state.leases {
		// An expired lease is never retained. Before expiry, reclaim only when
		// the recorded PID is demonstrably absent; inspection errors fail closed
		// until the lease expiry rather than accidentally oversubscribing.
		expired := !lease.ExpiresAt.After(now)
		dead := false
		if !expired && lease.OwnerPID > 0 && s.processExists != nil {
			exists, err := s.processExists(lease.OwnerPID)
			dead = err == nil && !exists
		}
		if expired || dead {
			delete(state.leases, id)
		}
	}
	state.running = len(state.leases)
}

func (s *LocalSharedStore) reclaimStaleLock(lockPath string, now time.Time) (bool, error) {
	info, err := os.Stat(lockPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("inspect shared admission lock: %w", err)
	}
	metadataData, readErr := os.ReadFile(filepath.Join(lockPath, "owner.json"))
	var metadata admissionLockMetadata
	metadataOK := readErr == nil && json.Unmarshal(metadataData, &metadata) == nil && metadata.OwnerID != "" && !metadata.CreatedAt.IsZero()
	created := info.ModTime().UTC()
	if metadataOK {
		created = metadata.CreatedAt.UTC()
	}
	if now.Sub(created) < s.lockStaleAfter {
		return false, nil
	}
	// A lock without valid owner metadata is never reclaimed automatically:
	// deleting it could race a live legacy writer. It remains an explicit
	// shared-store failure/fallback rather than a false coordination claim.
	if !metadataOK || metadata.OwnerPID <= 0 || s.processExists == nil {
		return false, nil
	}
	if metadata.OwnerPID > 0 && s.processExists != nil {
		exists, existsErr := s.processExists(metadata.OwnerPID)
		if existsErr != nil || exists {
			return false, nil
		}
	}
	// Atomically move the specific stale directory aside before removal. This
	// avoids deleting a lock another contender created after our inspection.
	quarantine := fmt.Sprintf("%s.stale-%d-%d", lockPath, os.Getpid(), time.Now().UnixNano())
	if err := os.Rename(lockPath, quarantine); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("quarantine stale shared admission lock: %w", err)
	}
	if err := os.RemoveAll(quarantine); err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("reclaim stale shared admission lock: %w", err)
	}
	return true, nil
}
