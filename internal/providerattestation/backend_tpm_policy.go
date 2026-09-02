package providerattestation

const (
	msPlatformCryptoProvider = "Microsoft Platform Crypto Provider"
	ncryptECDSAP256Algorithm = "ECDSA_P256"
	ncryptECDSAAlgorithm     = "ECDSA"
	ncryptAllowSigning       = uint32(0x00000002)
)

// tpmKeyProperties is intentionally small and receipt-free. Windows reads
// these values from CNG every time a persisted TPM key is opened, then this
// platform-neutral validator enforces the exact local-controller policy.
type tpmKeyProperties struct {
	Algorithm    string
	ExportPolicy uint32
	KeyUsage     uint32
}

func validateTPMKeyProperties(properties tpmKeyProperties) error {
	// Microsoft Platform Crypto Provider reports finalized P-256 keys as the
	// generic ECDSA family on this host. Curve size is independently and
	// authoritatively checked from the exported public ECC blob before use.
	if properties.Algorithm != ncryptECDSAP256Algorithm && properties.Algorithm != ncryptECDSAAlgorithm || properties.ExportPolicy != 0 || properties.KeyUsage != ncryptAllowSigning {
		return ErrProtectionPolicy
	}
	return nil
}

func validateTPMProviderName(name string) error {
	if name != msPlatformCryptoProvider {
		return ErrProtectionPolicy
	}
	return nil
}
