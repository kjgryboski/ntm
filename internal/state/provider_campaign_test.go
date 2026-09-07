package state

import (
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func TestCampaignConditionalWorkspaceSlotCannotBecomeRetry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "campaign.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	d := strings.Repeat("a", 64)
	if err = s.ConfigureProviderCampaign("conditional", 2, 0, d); err != nil {
		t.Fatal(err)
	}
	if err = s.ReserveProviderCampaignPurpose("conditional", "qualification-failed", d, d, "qualification"); err != nil {
		t.Fatal(err)
	}
	if err = s.BindProviderCampaignCondition("conditional", 2, "workspace", d, d); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.ReserveProviderCampaignPurpose("conditional", "retry", d, d, "qualification") == nil {
		t.Fatal("conditional slot spent as qualification retry")
	}
	if s.ReserveProviderCampaignAttempt("conditional", "bypass", d, d) == nil {
		t.Fatal("generic route bypassed condition")
	}
	if s.ReserveProviderCampaignPurpose("conditional", "other-account", strings.Repeat("b", 64), d, "workspace") == nil {
		t.Fatal("different identity admitted")
	}
	status, err := s.ProviderCampaign("conditional")
	if err != nil || status.Used != 1 {
		t.Fatalf("denials spent slot: %+v %v", status, err)
	}
	if s.BindProviderCampaignCondition("conditional", 2, "qualification", d, d) == nil {
		t.Fatal("condition overwritten")
	}
	if err = s.ReserveProviderCampaignPurpose("conditional", "qualified-task", d, d, "workspace"); err != nil {
		t.Fatal(err)
	}
}

func TestProviderCampaignCeilingSurvivesConcurrentReservationsAndReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "budget.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	digest := strings.Repeat("a", 64)
	if err = s.ConfigureProviderCampaign("parity", 4, 0, digest); err != nil {
		t.Fatal(err)
	}
	if err = s.ConfigureProviderCampaign("parity", 9, 0, digest); err == nil {
		t.Fatal("implicit budget increase accepted")
	}
	var won atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			other, e := Open(path)
			if e != nil {
				t.Error(e)
				return
			}
			defer other.Close()
			if other.ReserveProviderCampaignAttempt("parity", fmt.Sprint(i), digest, digest) == nil {
				won.Add(1)
			}
		}(i)
	}
	wg.Wait()
	if won.Load() != 4 {
		t.Fatalf("reserved %d, want hard ceiling 4", won.Load())
	}
	other, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	status, err := other.ProviderCampaign("parity")
	if err != nil || status.Used != 4 {
		t.Fatalf("reopened status=%+v %v", status, err)
	}
	if err = other.ConfigureProviderCampaign("parity", 5, 4, strings.Repeat("b", 64)); err != nil {
		t.Fatal(err)
	}
	if err = other.ReserveProviderCampaignAttempt("parity", "after-increase", digest, digest); err != nil {
		t.Fatal(err)
	}
	if err = other.ReserveProviderCampaignAttempt("parity", "after-increase", digest, digest); err == nil {
		t.Fatal("duplicate attempt replayed")
	}
}
