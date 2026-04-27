package scanner

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/user/ssync/internal"
)

func TestScan_DiscoversAllFileTypes(t *testing.T) {
	dir := t.TempDir()

	// Private key (no extension, mode 0600)
	writeFile(t, filepath.Join(dir, "id_ed25519"), 0600)
	// Private key (.pem, mode 0600)
	writeFile(t, filepath.Join(dir, "id_rsa.pem"), 0600)
	// Public key
	writeFile(t, filepath.Join(dir, "id_ed25519.pub"), 0644)
	// Config
	writeFile(t, filepath.Join(dir, "config"), 0644)
	// Known hosts
	writeFile(t, filepath.Join(dir, "known_hosts"), 0644)

	s := New()
	artifacts, err := s.Scan(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	names := artifactNames(artifacts)
	expected := []string{"id_ed25519", "id_rsa.pem", "id_ed25519.pub", "config", "known_hosts"}
	for _, want := range expected {
		if !contains(names, want) {
			t.Errorf("expected artifact %q not found; got %v", want, names)
		}
	}
	if len(artifacts) != len(expected) {
		t.Errorf("expected %d artifacts, got %d: %v", len(expected), len(artifacts), names)
	}
}

func TestScan_IgnoresUnrecognizedFiles(t *testing.T) {
	dir := t.TempDir()

	// Recognized
	writeFile(t, filepath.Join(dir, "id_ed25519"), 0600)
	writeFile(t, filepath.Join(dir, "id_ed25519.pub"), 0644)

	// Unrecognized
	writeFile(t, filepath.Join(dir, ".DS_Store"), 0644)
	writeFile(t, filepath.Join(dir, "authorized_keys"), 0644)
	writeFile(t, filepath.Join(dir, "environment"), 0644)

	// Private key with wrong permissions (0644 instead of 0600) — should be ignored
	writeFile(t, filepath.Join(dir, "id_rsa"), 0644)

	s := New()
	artifacts, err := s.Scan(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	names := artifactNames(artifacts)
	for _, unwanted := range []string{".DS_Store", "authorized_keys", "environment", "id_rsa"} {
		if contains(names, unwanted) {
			t.Errorf("unexpected artifact %q found in results", unwanted)
		}
	}
	if len(artifacts) != 2 {
		t.Errorf("expected 2 artifacts, got %d: %v", len(artifacts), names)
	}
}

func TestScan_ErrorForMissingDirectory(t *testing.T) {
	s := New()
	_, err := s.Scan("/nonexistent/path/that/does/not/exist")
	if err == nil {
		t.Fatal("expected error for missing directory, got nil")
	}
}

func TestScan_ErrorForEmptyDirectory(t *testing.T) {
	dir := t.TempDir()

	s := New()
	_, err := s.Scan(dir)
	if err == nil {
		t.Fatal("expected error for empty directory, got nil")
	}
}

func TestScan_ArtifactFieldsPopulated(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "id_ed25519"), 0600)

	s := New()
	artifacts, err := s.Scan(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(artifacts) != 1 {
		t.Fatalf("expected 1 artifact, got %d", len(artifacts))
	}

	a := artifacts[0]
	if a.Name != "id_ed25519" {
		t.Errorf("Name = %q, want %q", a.Name, "id_ed25519")
	}
	if a.RelativePath != "id_ed25519" {
		t.Errorf("RelativePath = %q, want %q", a.RelativePath, "id_ed25519")
	}
	if a.AbsolutePath != filepath.Join(dir, "id_ed25519") {
		t.Errorf("AbsolutePath = %q, want %q", a.AbsolutePath, filepath.Join(dir, "id_ed25519"))
	}
	if a.ModifiedAt.IsZero() {
		t.Error("ModifiedAt should not be zero")
	}
}

// helpers

func writeFile(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte("test"), mode); err != nil {
		t.Fatalf("writeFile %s: %v", path, err)
	}
}

func artifactNames(artifacts []internal.SSHArtifact) []string {
	names := make([]string, len(artifacts))
	for i, a := range artifacts {
		names[i] = a.Name
	}
	return names
}

func contains(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}
