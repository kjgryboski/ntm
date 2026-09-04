package provider

import (
	"context"
	"time"
)

// CapacityReleaseObservation is local controller evidence, not a provider
// acknowledgement or proof that remote inference/billing stopped.
type CapacityReleaseObservation struct {
	IdentitySHA256    string               `json:"identity_sha256"`
	LeaseSHA256       string               `json:"lease_sha256"`
	PlanLeaseSHA256   string               `json:"plan_lease_sha256,omitempty"`
	Scope             CapacityControlScope `json:"scope"`
	LocalSlotReleased bool                 `json:"local_slot_released"`
	PlanSlotReleased  bool                 `json:"plan_slot_released"`
	UsageState        string               `json:"usage_state"`
	ObservedAt        time.Time            `json:"observed_at"`
}

type capacityObserverKey struct{}

func WithCapacityObserver(ctx context.Context, observer func(CapacityReleaseObservation) error) context.Context {
	return context.WithValue(ctx, capacityObserverKey{}, observer)
}

func ObserveCapacityRelease(ctx context.Context, observation CapacityReleaseObservation) error {
	if observer, ok := ctx.Value(capacityObserverKey{}).(func(CapacityReleaseObservation) error); ok && observer != nil {
		return observer(observation)
	}
	return nil
}
