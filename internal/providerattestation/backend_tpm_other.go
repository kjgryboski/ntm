//go:build !windows && !linux

package providerattestation

// Platforms other than Windows and Linux preserve the OS credential-broker
// Ed25519 path. The Linux backend may use the explicitly configured Windows
// bridge for WSL; other platforms do not proxy TPM operations.
func newNativeHardwareSigner() hardwareSigner { return nil }
