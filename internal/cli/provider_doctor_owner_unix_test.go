//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package cli

import (
	"os"
	"path/filepath"
	"testing"
)

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

func TestProviderRequirementsReadForDoctorBindsContentAndMetadata(t *testing.T) {
	path := filepath.Join(t.TempDir(), "requirements.toml")
	want := []byte("[permissions]\n")
	if err := os.WriteFile(path, want, 0o600); err != nil {
		t.Fatal(err)
	}
	got, info, err := providerRequirementsReadForDoctor(path)
	if err != nil || string(got) != string(want) || info == nil || !info.Mode().IsRegular() {
		t.Fatalf("data=%q info=%v err=%v", got, info, err)
	}
}
