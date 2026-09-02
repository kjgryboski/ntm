//go:build darwin

package providercredential

// macOS's security CLI accepts a generic-password value as a command-line
// argument, which would expose it to process inspection. Until a native Go
// Keychain binding is available, fail closed rather than weakening the broker's
// noninteractive secret-handling guarantee.
func newNativeBackend() backend {
	return unavailableBackend{snapshot: Status{
		Backend: BackendMacOSKeychain, Available: false, Present: false, Evidence: EvidenceUnavailable,
	}}
}
