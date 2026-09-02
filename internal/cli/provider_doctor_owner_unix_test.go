//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package cli

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

type providerAuthorityFileInfo struct {
	mode os.FileMode
	uid  uint32
}

func (i providerAuthorityFileInfo) Name() string       { return "runtime" }
func (i providerAuthorityFileInfo) Size() int64        { return 1 }
func (i providerAuthorityFileInfo) Mode() os.FileMode  { return i.mode }
func (i providerAuthorityFileInfo) ModTime() time.Time { return time.Time{} }
func (i providerAuthorityFileInfo) IsDir() bool        { return i.mode.IsDir() }
func (i providerAuthorityFileInfo) Sys() any           { return &syscall.Stat_t{Uid: i.uid} }

func TestProviderRequirementsReadForDoctorRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.toml")
	if err := os.WriteFile(target, []byte("[permissions]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "requirements.toml")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, _, err := providerRequirementsReadForDoctor(link); err == nil {
		t.Fatal("doctor accepted a symlinked requirements document")
	}
}

func TestProviderRequirementsReadForDoctorRejectsUserOwnedParent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "requirements.toml")
	if err := os.WriteFile(path, []byte("[permissions]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := providerRequirementsReadForDoctor(path); err == nil {
		t.Fatal("doctor accepted a requirements file beneath a user-owned parent")
	}
}

func TestProviderExecutableAuthorityRejectsWritableOrNonRootFiles(t *testing.T) {
	for name, info := range map[string]os.FileInfo{
		"owner_writable_by_group": providerAuthorityFileInfo{mode: 0o775, uid: 0},
		"non_root_read_only":      providerAuthorityFileInfo{mode: 0o555, uid: 1000},
	} {
		t.Run(name, func(t *testing.T) {
			if providerRequirementsRootOwned(info) {
				t.Fatal("unsafe executable metadata was accepted as system-authoritative")
			}
		})
	}
	if !providerRequirementsRootOwned(providerAuthorityFileInfo{mode: 0o755, uid: 0}) {
		t.Fatal("root-owned non-writable executable metadata was rejected")
	}
}

func TestProviderSystemAuthoritativeExecutableRejectsUserOwnedPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "grok")
	if err := os.WriteFile(path, []byte("not a real runtime"), 0o555); err != nil {
		t.Fatal(err)
	}
	if _, err := providerSystemAuthoritativeExecutable(path); err == nil {
		t.Fatal("user-owned runtime path was accepted")
	}
}

func TestProviderSecureRootPathRejectsUserOwnedParent(t *testing.T) {
	if err := providerSecureRootPath(t.TempDir()); err == nil {
		t.Fatal("user-owned executable parent path was accepted")
	}
}
