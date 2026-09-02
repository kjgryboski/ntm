//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

func providerRequirementsRootOwned(info os.FileInfo) bool {
	if info == nil {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == 0 && info.Mode().IsRegular() && info.Mode().Perm()&0o022 == 0
}

func providerRequirementsCanInstall() bool { return os.Geteuid() == 0 }

func providerRequirementsOpenExisting(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	file := os.NewFile(uintptr(fd), path)
	info, statErr := file.Stat()
	if statErr != nil || !providerRequirementsRootOwned(info) {
		_ = file.Close()
		return nil, errors.New("Grok requirements file is not a root-owned, non-writable regular file")
	}
	return file, nil
}

// providerRequirementsReadForDoctor reads and stats the exact no-follow file
// descriptor, eliminating the path-swap and symlink ambiguity of separate
// ReadFile/Stat calls. Ownership is evaluated by the caller so the doctor can
// distinguish a digest match from an authority failure.
func providerRequirementsReadForDoctor(path string) ([]byte, os.FileInfo, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, info, errors.New("Grok requirements path is not a regular no-follow file")
	}
	data, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	if err != nil {
		return nil, info, err
	}
	if len(data) > 1<<20 {
		return nil, info, errors.New("Grok requirements file exceeds the inspection limit")
	}
	return data, info, nil
}

func providerRequirementsPrepareParent(path string) error {
	dir := filepath.Dir(path)
	parent := filepath.Dir(dir)
	if err := providerSecureRootDirectory(parent); err != nil {
		return fmt.Errorf("Grok requirements parent is not system-authoritative: %w", err)
	}
	if err := unix.Mkdir(dir, 0o755); err != nil && !errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("create Grok system policy directory: %w", err)
	}
	if err := providerSecureRootDirectory(dir); err != nil {
		return fmt.Errorf("Grok system policy directory is not system-authoritative: %w", err)
	}
	return nil
}

func providerSecureRootDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
		return errors.New("path must be a root-owned, non-writable directory without symlinks")
	}
	return nil
}

func providerRequirementsOpenCreate(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o644)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	file := os.NewFile(uintptr(fd), path)
	info, statErr := file.Stat()
	if statErr != nil || !providerRequirementsRootOwned(info) {
		_ = file.Close()
		return nil, errors.New("created Grok requirements file is not system-authoritative")
	}
	return file, nil
}
