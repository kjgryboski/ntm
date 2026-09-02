//go:build !windows

package ratelimit

import "os"

func replaceAdmissionFile(source, destination string) error {
	return os.Rename(source, destination)
}
