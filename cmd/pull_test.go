package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/user/ssync/internal"
	"github.com/user/ssync/internal/crypto"
	"github.com/user/ssync/internal/r2"
)

// sentinel errors for mock decrypter
var (
	errAuthFailed   = fmt.Errorf("decryption failed: authentication tag mismatch")
	errTamperFailed = fmt.Errorf("decryption failed: authentication tag mismatch")
)

// mockDecrypter simulates DecryptWithMetadata.
// - If the key is in authErrKeys, return an auth error.
// - If the key is in contentMap, return the content as a DecryptResult.
// - Otherwise return not-found error.
type mockDecrypter struct {
	// contentMap maps artifact R2Key → plaintext content
	contentMap map[string]string
	// authErrKeys is a set of R2Keys that should return auth errors
	authErrKeys map[string]bool
	// password that succeeds; empty means any password works
	correctPassword string
}

func (m *mockDecrypter) DecryptWithMetadata(blob []byte, password string) (crypto.DecryptResult, error) {
	// The blob encodes the R2 key as "blob:<key>"
	key := strings.TrimPrefix(string(blob), "blob:")

	if m.authErrKeys[key] {
		return crypto.DecryptResult{}, errAuthFailed
	}

	if m.correctPassword != "" && password != m.correctPassword {
		return crypto.DecryptResult{}, errAuthFailed
	}

	content, ok := m.contentMap[key]
	if !ok {
		return crypto.DecryptResult{}, fmt.Errorf("unknown key: %s", key)
	}

	// Derive name and relativePath from key: "artifacts/<name>.enc" → name
	name := strings.TrimSuffix(strings.TrimPrefix(key, "artifacts/"), ".enc")
	return crypto.DecryptResult{
		Content:      []byte(content),
		Name:         name,
		RelativePath: name,
	}, nil
}

// mockR2ForPull returns blobs encoded as "blob:<key>" so the mock decrypter can identify them.
type mockR2ForPull struct {
	keys        map[string]bool // keys that exist
	downloadErr error
}

func (m *mockR2ForPull) Upload(key string, data []byte) error  { return nil }
func (m *mockR2ForPull) List() ([]string, error)               { return nil, nil }
func (m *mockR2ForPull) Delete(key string) error               { return nil }

func (m *mockR2ForPull) Download(key string) ([]byte, error) {
	if m.downloadErr != nil {
		return nil, m.downloadErr
	}
	if m.keys[key] {
		return []byte("blob:" + key), nil
	}
	return nil, r2.ErrNotFound
}

func newPullRunner(input string, r2c r2.R2Client, dec artifactDecrypter, mm *mockManifestManager, sshDir string) (*pullRunner, *bytes.Buffer) {
	out := &bytes.Buffer{}
	return &pullRunner{
		in:       strings.NewReader(input),
		out:      out,
		store:    &mockCredStore{},
		r2:       r2c,
		engine:   dec,
		manifest: mm,
		sshDir:   sshDir,
	}, out
}

// TestPull_SuccessfulPull verifies the happy path: artifacts are downloaded, decrypted, and written.
func TestPull_SuccessfulPull(t *testing.T) {
	sshDir := t.TempDir()

	mm := &mockManifestManager{
		manifest: internal.Manifest{
			Artifacts: []internal.ManifestArtifact{
				{Name: "id_ed25519", R2Key: "artifacts/id_ed25519.enc"},
				{Name: "config", R2Key: "artifacts/config.enc"},
			},
		},
	}

	r2c := &mockR2ForPull{
		keys: map[string]bool{
			"artifacts/id_ed25519.enc": true,
			"artifacts/config.enc":     true,
		},
	}

	dec := &mockDecrypter{
		contentMap: map[string]string{
			"artifacts/id_ed25519.enc": "private-key-content",
			"artifacts/config.enc":     "Host *\n  ServerAliveInterval 60\n",
		},
	}

	// Input: password
	runner, out := newPullRunner("strongpassword123\n", r2c, dec, mm, sshDir)

	err := runner.run()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Files should be written.
	keyPath := filepath.Join(sshDir, "id_ed25519")
	data, readErr := os.ReadFile(keyPath)
	if readErr != nil {
		t.Fatalf("expected id_ed25519 to be written, got: %v", readErr)
	}
	if string(data) != "private-key-content" {
		t.Errorf("id_ed25519 content = %q, want %q", string(data), "private-key-content")
	}

	configPath := filepath.Join(sshDir, "config")
	if _, err := os.Stat(configPath); err != nil {
		t.Errorf("expected config to be written: %v", err)
	}

	// Output should contain success markers.
	if !strings.Contains(out.String(), "✓") {
		t.Errorf("expected success marker in output, got: %q", out.String())
	}
}

// TestPull_WrongPassword_ShowsErrorAndPromptsRetry verifies wrong password triggers retry prompt.
func TestPull_WrongPassword_ShowsErrorAndPromptsRetry(t *testing.T) {
	sshDir := t.TempDir()

	mm := &mockManifestManager{
		manifest: internal.Manifest{
			Artifacts: []internal.ManifestArtifact{
				{Name: "id_ed25519", R2Key: "artifacts/id_ed25519.enc"},
			},
		},
	}

	r2c := &mockR2ForPull{
		keys: map[string]bool{
			"artifacts/id_ed25519.enc": true,
		},
	}

	dec := &mockDecrypter{
		contentMap: map[string]string{
			"artifacts/id_ed25519.enc": "private-key-content",
		},
		correctPassword: "correctpassword123",
	}

	// First password wrong, then retry with correct password.
	input := "wrongpassword123\nr\ncorrectpassword123\n"
	runner, out := newPullRunner(input, r2c, dec, mm, sshDir)

	err := runner.run()
	if err != nil {
		t.Fatalf("expected no error after retry, got: %v", err)
	}

	outStr := out.String()
	if !strings.Contains(outStr, "wrong password") {
		t.Errorf("expected wrong password error in output, got: %q", outStr)
	}

	// File should be written after successful retry.
	keyPath := filepath.Join(sshDir, "id_ed25519")
	if _, err := os.Stat(keyPath); err != nil {
		t.Errorf("expected id_ed25519 to be written after retry: %v", err)
	}
}

// TestPull_WrongPassword_QuitAborts verifies quitting on wrong password returns exit code 1.
func TestPull_WrongPassword_QuitAborts(t *testing.T) {
	sshDir := t.TempDir()

	mm := &mockManifestManager{
		manifest: internal.Manifest{
			Artifacts: []internal.ManifestArtifact{
				{Name: "id_ed25519", R2Key: "artifacts/id_ed25519.enc"},
			},
		},
	}

	r2c := &mockR2ForPull{
		keys: map[string]bool{
			"artifacts/id_ed25519.enc": true,
		},
	}

	dec := &mockDecrypter{
		contentMap:      map[string]string{"artifacts/id_ed25519.enc": "content"},
		correctPassword: "correctpassword123",
	}

	// Wrong password, then quit.
	input := "wrongpassword123\nq\n"
	runner, _ := newPullRunner(input, r2c, dec, mm, sshDir)

	err := runner.run()
	if err == nil {
		t.Fatal("expected error on quit, got nil")
	}
	var ee *exitError
	if !errors.As(err, &ee) || ee.code != 1 {
		t.Errorf("expected exit code 1 on quit, got: %v", err)
	}
}

// TestPull_GCMFailure_ShowsTamperWarningAndContinues verifies tamper warning is shown and other artifacts succeed.
func TestPull_GCMFailure_ShowsTamperWarningAndContinues(t *testing.T) {
	sshDir := t.TempDir()

	mm := &mockManifestManager{
		manifest: internal.Manifest{
			Artifacts: []internal.ManifestArtifact{
				{Name: "id_ed25519", R2Key: "artifacts/id_ed25519.enc"},
				{Name: "config", R2Key: "artifacts/config.enc"},
			},
		},
	}

	r2c := &mockR2ForPull{
		keys: map[string]bool{
			"artifacts/id_ed25519.enc": true,
			"artifacts/config.enc":     true,
		},
	}

	// id_ed25519 has a GCM auth error (tampered), config succeeds.
	dec := &mockDecrypter{
		contentMap: map[string]string{
			"artifacts/config.enc": "Host *\n",
		},
		authErrKeys: map[string]bool{
			"artifacts/id_ed25519.enc": true,
		},
	}

	runner, out := newPullRunner("strongpassword123\n", r2c, dec, mm, sshDir)

	err := runner.run()
	// Should not return an error — tamper is a warning, not a fatal error.
	if err != nil {
		t.Fatalf("expected no fatal error on tamper, got: %v", err)
	}

	outStr := out.String()
	// Tamper warning should appear.
	if !strings.Contains(outStr, "tampered") {
		t.Errorf("expected tamper warning in output, got: %q", outStr)
	}
	if !strings.Contains(outStr, "id_ed25519") {
		t.Errorf("expected artifact name in tamper warning, got: %q", outStr)
	}

	// config should still be written.
	configPath := filepath.Join(sshDir, "config")
	if _, err := os.Stat(configPath); err != nil {
		t.Errorf("expected config to be written despite tamper on other artifact: %v", err)
	}

	// id_ed25519 should NOT be written.
	keyPath := filepath.Join(sshDir, "id_ed25519")
	if _, err := os.Stat(keyPath); err == nil {
		t.Error("expected id_ed25519 NOT to be written when tampered")
	}
}

// TestPull_EmptyManifest_ExitsWithError verifies empty manifest returns exit code 1.
func TestPull_EmptyManifest_ExitsWithError(t *testing.T) {
	sshDir := t.TempDir()

	mm := &mockManifestManager{
		manifest: internal.Manifest{Artifacts: nil},
	}

	r2c := &mockR2ForPull{}
	dec := &mockDecrypter{}

	runner, _ := newPullRunner("", r2c, dec, mm, sshDir)

	err := runner.run()
	if err == nil {
		t.Fatal("expected error for empty manifest, got nil")
	}

	var ee *exitError
	if !errors.As(err, &ee) || ee.code != 1 {
		t.Errorf("expected exit code 1 for empty manifest, got: %v", err)
	}
	if !strings.Contains(err.Error(), "no artifacts found") {
		t.Errorf("expected 'no artifacts found' message, got: %v", err)
	}
}

// TestPull_NetworkError_ExitsWithCode2 verifies network errors produce exit code 2.
func TestPull_NetworkError_ExitsWithCode2(t *testing.T) {
	sshDir := t.TempDir()

	mm := &mockManifestManager{
		manifest: internal.Manifest{
			Artifacts: []internal.ManifestArtifact{
				{Name: "id_ed25519", R2Key: "artifacts/id_ed25519.enc"},
			},
		},
	}

	r2c := &mockR2ForPull{
		downloadErr: &r2.ConnectionError{Cause: fmt.Errorf("connection refused")},
	}

	dec := &mockDecrypter{}

	runner, _ := newPullRunner("strongpassword123\n", r2c, dec, mm, sshDir)

	err := runner.run()
	if err == nil {
		t.Fatal("expected error on network failure, got nil")
	}

	var ee *exitError
	if !errors.As(err, &ee) || ee.code != 2 {
		t.Errorf("expected exit code 2 on network error, got: %v", err)
	}
}

// TestPull_ManifestFetchError_ExitsWithCode2 verifies manifest fetch errors produce exit code 2.
func TestPull_ManifestFetchError_ExitsWithCode2(t *testing.T) {
	sshDir := t.TempDir()

	mm := &mockManifestManager{
		fetchErr: fmt.Errorf("network error fetching manifest"),
	}

	r2c := &mockR2ForPull{}
	dec := &mockDecrypter{}

	runner, _ := newPullRunner("", r2c, dec, mm, sshDir)

	err := runner.run()
	if err == nil {
		t.Fatal("expected error on manifest fetch failure, got nil")
	}

	var ee *exitError
	if !errors.As(err, &ee) || ee.code != 2 {
		t.Errorf("expected exit code 2 on manifest fetch error, got: %v", err)
	}
}
