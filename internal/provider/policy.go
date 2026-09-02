package provider

// DefaultZAIAutomationPolicyName is the policy identifier accepted for the
// unattended Claude-compatible Coding Plan lane. NTM binds this name to the
// immutable, reviewed config manifest hash and rejects known bypass flags. It
// does not claim to introspect an opaque wrapper after launch.
const DefaultZAIAutomationPolicyName = "zai-readonly-ci"

// NativeZAINoToolsPolicyName identifies the separately billed native API lane.
// The current adapter implements one nonce-bound completion and rejects every
// provider tool call; this stable name prevents a profile from implying a
// broader policy than the compiled transport actually supports.
const NativeZAINoToolsPolicyName = "zai-native-no-tools-v1"

// NativeZAIToolsPolicyName identifies the controller-owned function-calling
// lane. The provider may propose only compiled tool schemas; NTM performs all
// filesystem and verification effects through its bounded brokers.
const NativeZAIToolsPolicyName = "zai-native-tools-v1"
