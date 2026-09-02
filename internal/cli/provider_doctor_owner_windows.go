//go:build windows

package cli

import "os"

// Windows ownership/ACL authority needs an explicit security-descriptor probe.
// Until that is implemented, the doctor refuses to claim an administrator
// managed bypass lock from file presence alone.
func providerRequirementsRootOwned(info os.FileInfo) bool { return false }

func providerRequirementsCanInstall() bool { return false }

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
