//go:build !linux && !windows && !darwin

package providercredential

func newNativeBackend() backend { return unavailableBackend{snapshot: unavailableStatus()} }
