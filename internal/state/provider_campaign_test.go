package state

import (
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

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
