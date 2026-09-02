//go:build !windows && !aix && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris

package cli

import "os"

// Unsupported platforms have no audited ownership/ACL probe. Fail closed
// instead of treating a locally writable requirements file as administrator
// authority.
func providerRequirementsRootOwned(os.FileInfo) bool { return false }
func providerRequirementsCanInstall() bool           { return false }
func providerSystemAuthoritativeExecutable(string) (string, error) {
	return "", os.ErrPermission
}
func providerSecureRootPath(string) error { return os.ErrPermission }
func providerRequirementsOpenExisting(string) (*os.File, error) {
	return nil, os.ErrPermission
}
func providerRequirementsReadForDoctor(string) ([]byte, os.FileInfo, error) {
	return nil, nil, os.ErrPermission
}
func providerRequirementsPrepareParent(string) error { return os.ErrPermission }
func providerRequirementsOpenCreate(string) (*os.File, error) {
	return nil, os.ErrPermission
}
