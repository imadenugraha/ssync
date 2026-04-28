package cmd

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/user/ssync/internal"
	"github.com/user/ssync/internal/r2"
)

// ---- Mock implementations ----

// mockScanner implements scanner.ArtifactScanner.
type mockScanner struct {
	artifacts []internal.SSHArtifact
	err       error
}

func (m *mockScanner) Scan(dir string) ([]internal.SSHArtifact, error) {
	return m.artifacts, m.err
}

// mockR2Client implements r2.R2Client.
type mockR2Client struct {
	uploaded   map[string][]byte
	uploadErrs map[string]error
	downloaded map[string][]byte
	downloadErr error
}

func newMockR2() *mockR2Client {
	return &mockR2Client{
		uploaded:   make(map[string][]byte),
		uploadErrs: make(map[string]error),
		downloaded: make(map[string][]byte),
	}
}

func (m *mockR2Client) Upload(key string, data []byte) error {
	if err, ok := m.uploadErrs[key]; ok {
		return err
	}
	m.uploaded[key] = data
	return nil
}

func (m *mockR2Client) Download(key string) ([]byte, error) {
	if m.downloadErr != nil {
		return nil, m.downloadErr
	}
	if data, ok := m.downloaded[key]; ok {
		return data, nil
	}
	return nil, r2.ErrNotFound
}

func (m *mockR2Client) List() ([]string, error) { return nil, nil }
func (m *mockR2Client) Delete(key string) error  { return nil }

// mockEncrypter implements artifactEncrypter.
type mockEncrypter struct {
	encryptErr error
}

func (m *mockEncrypter) EncryptArtifact(content []byte, name, relativePath, password string) ([]byte, error) {
	if m.encryptErr != nil {
		return nil, m.encryptErr
	}
	// Return a simple deterministic blob for testing.
	return []byte("encrypted:" + name), nil
}

// mockManifestManager implements manifest.ManifestManager.
type mockManifestManager struct {
	manifest    internal.Manifest
	fetchErr    error
	updateErr   error
	updated     *internal.Manifest
}

func (m *mockManifestManager) Fetch() (internal.Manifest, error) {
	return m.manifest, m.fetchErr
}

func (m *mockManifestManager) Update(mf internal.Manifest) error {
	if m.updateErr != nil {
		return m.updateErr
	}
	m.updated = &mf
	return nil
}

// mockBackupManager implements backup.BackupCodeManager.
type mockBackupManager struct {
	hashes      []internal.BackupCodeRecord
	loadErr     error
	generateErr error
	storeErr    error
	generated   []internal.BackupCode
	stored      bool
}

func (m *mockBackupManager) Generate() ([]internal.BackupCode, error) {
	if m.generateErr != nil {
		return nil, m.generateErr
	}
	codes := []internal.BackupCode{
		{Code: "AAAAA-BBBBB-CCCCC-DDDDD"},
		{Code: "EEEEE-FFFFF-GGGGG-HHHHH"},
	}
	m.generated = codes
	return codes, nil
}

func (m *mockBackupManager) StoreHashes(codes []internal.BackupCode) error {
	if m.storeErr != nil {
		return m.storeErr
	}
	m.stored = true
	return nil
}

func (m *mockBackupManager) Verify(code string) (bool, error)   { return false, nil }
func (m *mockBackupManager) Invalidate(code string) error        { return nil }

func (m *mockBackupManager) LoadHashes() ([]internal.BackupCodeRecord, error) {
	return m.hashes, m.loadErr
}

// ---- Helpers ----

// makeTempArtifact creates a real temp file and returns an SSHArtifact pointing to it.
func makeTempArtifact(t *testing.T, name, content string) internal.SSHArtifact {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("write temp artifact: %v", err)
	}
	return internal.SSHArtifact{
		Name:         name,
		RelativePath: name,
		AbsolutePath: path,
		Size:         int64(len(content)),
		ModifiedAt:   time.Now().Add(-1 * time.Hour),
	}
}

func newPushRunner(input string, sc *mockScanner, r2c *mockR2Client, enc *mockEncrypter, mm *mockManifestManager, bm *mockBackupManager, force bool) (*pushRunner, *bytes.Buffer) {
	out := &bytes.Buffer{}
	in := strings.NewReader(input)
	inSc := bufio.NewScanner(in)
	return &pushRunner{
		in:       in,
		out:      out,
		store:    &mockCredStore{},
		scanner:  sc,
		r2:       r2c,
		engine:   enc,
		manifest: mm,
		backup:   bm,
		force:    force,
		sshDir:   "/fake/.ssh",
		pwReader: readerPasswordReader(inSc),
		sc:       inSc,
	}, out
}

// ---- Tests ----

// TestPush_SuccessfulPush verifies the happy path: artifacts are encrypted, uploaded, and manifest updated.
func TestPush_SuccessfulPush(t *testing.T) {
	artifact := makeTempArtifact(t, "id_ed25519", "private-key-content")
	sc := &mockScanner{artifacts: []internal.SSHArtifact{artifact}}
	r2c := newMockR2()
	enc := &mockEncrypter{}
	mm := &mockManifestManager{}
	bm := &mockBackupManager{loadErr: r2.ErrNotFound} // first push

	// Input: push all=Y, password
	input := "Y\nstrongpassword123\n"
	runner, out := newPushRunner(input, sc, r2c, enc, mm, bm, false)

	err := runner.run()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Artifact should be uploaded.
	key := "artifacts/id_ed25519.enc"
	if _, ok := r2c.uploaded[key]; !ok {
		t.Errorf("expected artifact to be uploaded at key %q", key)
	}

	// Manifest should be updated.
	if mm.updated == nil {
		t.Error("expected manifest to be updated")
	}

	// Backup codes should be generated and stored on first push.
	if !bm.stored {
		t.Error("expected backup codes to be stored on first push")
	}

	// Output should contain success indicator.
	if !strings.Contains(out.String(), "✓") {
		t.Errorf("expected success marker in output, got: %q", out.String())
	}
}

// TestPush_ConflictDetection_PromptsUser verifies that when remote is newer, user is prompted.
func TestPush_ConflictDetection_PromptsUser(t *testing.T) {
	artifact := makeTempArtifact(t, "id_ed25519", "private-key-content")
	// Make remote newer than local.
	artifact.ModifiedAt = time.Now().Add(-2 * time.Hour)

	sc := &mockScanner{artifacts: []internal.SSHArtifact{artifact}}
	r2c := newMockR2()
	enc := &mockEncrypter{}
	mm := &mockManifestManager{
		manifest: internal.Manifest{
			Artifacts: []internal.ManifestArtifact{
				{
					Name:       "id_ed25519",
					UploadedAt: time.Now(), // remote is newer
				},
			},
		},
	}
	bm := &mockBackupManager{hashes: []internal.BackupCodeRecord{{ID: "1", Hash: "h", Used: false}}}

	// Input: push all=Y, conflict prompt=y (overwrite), password
	input := "Y\nstrongpassword123\ny\n"
	runner, out := newPushRunner(input, sc, r2c, enc, mm, bm, false)

	err := runner.run()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Should have prompted about conflict.
	if !strings.Contains(out.String(), "Remote is newer") {
		t.Errorf("expected conflict warning in output, got: %q", out.String())
	}

	// Artifact should be uploaded (user said y).
	key := "artifacts/id_ed25519.enc"
	if _, ok := r2c.uploaded[key]; !ok {
		t.Errorf("expected artifact to be uploaded after user confirmed overwrite")
	}
}

// TestPush_ConflictDetection_SkipOnNo verifies that declining the conflict prompt skips the artifact.
func TestPush_ConflictDetection_SkipOnNo(t *testing.T) {
	artifact := makeTempArtifact(t, "id_ed25519", "private-key-content")
	artifact.ModifiedAt = time.Now().Add(-2 * time.Hour)

	sc := &mockScanner{artifacts: []internal.SSHArtifact{artifact}}
	r2c := newMockR2()
	enc := &mockEncrypter{}
	mm := &mockManifestManager{
		manifest: internal.Manifest{
			Artifacts: []internal.ManifestArtifact{
				{Name: "id_ed25519", UploadedAt: time.Now()},
			},
		},
	}
	bm := &mockBackupManager{hashes: []internal.BackupCodeRecord{{ID: "1", Hash: "h", Used: false}}}

	// Input: push all=Y, conflict prompt=N (skip), password
	input := "Y\nstrongpassword123\nN\n"
	runner, out := newPushRunner(input, sc, r2c, enc, mm, bm, false)

	err := runner.run()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Artifact should NOT be uploaded.
	key := "artifacts/id_ed25519.enc"
	if _, ok := r2c.uploaded[key]; ok {
		t.Errorf("expected artifact to be skipped, but it was uploaded")
	}

	// Output should mention skipping.
	if !strings.Contains(out.String(), "Skipping") {
		t.Errorf("expected skip message in output, got: %q", out.String())
	}
}

// TestPush_ForceSkipsConflictPrompt verifies --force bypasses conflict detection entirely.
func TestPush_ForceSkipsConflictPrompt(t *testing.T) {
	artifact := makeTempArtifact(t, "id_ed25519", "private-key-content")
	artifact.ModifiedAt = time.Now().Add(-2 * time.Hour)

	sc := &mockScanner{artifacts: []internal.SSHArtifact{artifact}}
	r2c := newMockR2()
	enc := &mockEncrypter{}
	mm := &mockManifestManager{
		manifest: internal.Manifest{
			Artifacts: []internal.ManifestArtifact{
				{Name: "id_ed25519", UploadedAt: time.Now()},
			},
		},
	}
	bm := &mockBackupManager{hashes: []internal.BackupCodeRecord{{ID: "1", Hash: "h", Used: false}}}

	// With --force, no conflict prompt needed — just push all + password.
	input := "Y\nstrongpassword123\n"
	runner, out := newPushRunner(input, sc, r2c, enc, mm, bm, true /* force */)

	err := runner.run()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Should NOT have prompted about conflict.
	if strings.Contains(out.String(), "Remote is newer") {
		t.Errorf("expected no conflict warning with --force, got: %q", out.String())
	}

	// Artifact should be uploaded.
	key := "artifacts/id_ed25519.enc"
	if _, ok := r2c.uploaded[key]; !ok {
		t.Errorf("expected artifact to be uploaded with --force")
	}
}

// TestPush_FirstPush_GeneratesBackupCodes verifies backup codes are generated and displayed on first push.
func TestPush_FirstPush_GeneratesBackupCodes(t *testing.T) {
	artifact := makeTempArtifact(t, "id_ed25519", "private-key-content")
	sc := &mockScanner{artifacts: []internal.SSHArtifact{artifact}}
	r2c := newMockR2()
	enc := &mockEncrypter{}
	mm := &mockManifestManager{}
	bm := &mockBackupManager{loadErr: r2.ErrNotFound} // first push: no backup codes in R2

	input := "Y\nstrongpassword123\n"
	runner, out := newPushRunner(input, sc, r2c, enc, mm, bm, false)

	err := runner.run()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Backup codes should be generated.
	if bm.generated == nil {
		t.Error("expected backup codes to be generated on first push")
	}

	// Backup codes should be stored.
	if !bm.stored {
		t.Error("expected backup codes to be stored on first push")
	}

	// Output should contain backup codes and offline storage warning.
	outStr := out.String()
	if !strings.Contains(outStr, "BACKUP CODES") {
		t.Errorf("expected backup codes section in output, got: %q", outStr)
	}
	if !strings.Contains(outStr, "offline") {
		t.Errorf("expected offline storage warning in output, got: %q", outStr)
	}
	// Codes themselves should appear.
	for _, c := range bm.generated {
		if !strings.Contains(outStr, c.Code) {
			t.Errorf("expected backup code %q in output", c.Code)
		}
	}
}

// TestPush_SubsequentPush_NoBackupCodes verifies backup codes are NOT regenerated on subsequent pushes.
func TestPush_SubsequentPush_NoBackupCodes(t *testing.T) {
	artifact := makeTempArtifact(t, "id_ed25519", "private-key-content")
	sc := &mockScanner{artifacts: []internal.SSHArtifact{artifact}}
	r2c := newMockR2()
	enc := &mockEncrypter{}
	mm := &mockManifestManager{}
	// Existing backup codes → not first push.
	bm := &mockBackupManager{
		hashes: []internal.BackupCodeRecord{{ID: "1", Hash: "somehash", Used: false}},
	}

	input := "Y\nstrongpassword123\n"
	runner, out := newPushRunner(input, sc, r2c, enc, mm, bm, false)

	err := runner.run()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if bm.stored {
		t.Error("expected backup codes NOT to be stored on subsequent push")
	}
	if strings.Contains(out.String(), "BACKUP CODES") {
		t.Errorf("expected no backup codes section on subsequent push, got: %q", out.String())
	}
}

// TestPush_PartialUploadFailure_ReportsCorrectly verifies partial failures are reported and exit code 2 is returned.
func TestPush_PartialUploadFailure_ReportsCorrectly(t *testing.T) {
	a1 := makeTempArtifact(t, "id_ed25519", "key1")
	a2 := makeTempArtifact(t, "id_rsa", "key2")

	sc := &mockScanner{artifacts: []internal.SSHArtifact{a1, a2}}
	r2c := newMockR2()
	// Make the second artifact's upload fail.
	r2c.uploadErrs["artifacts/id_rsa.enc"] = fmt.Errorf("network error")
	enc := &mockEncrypter{}
	mm := &mockManifestManager{}
	bm := &mockBackupManager{hashes: []internal.BackupCodeRecord{{ID: "1", Hash: "h", Used: false}}}

	input := "Y\nstrongpassword123\n"
	runner, out := newPushRunner(input, sc, r2c, enc, mm, bm, false)

	err := runner.run()
	if err == nil {
		t.Fatal("expected error on partial failure, got nil")
	}

	var ee *exitError
	if !errors.As(err, &ee) || ee.code != 2 {
		t.Errorf("expected exit code 2 on partial failure, got: %v", err)
	}

	outStr := out.String()
	// First artifact should succeed.
	if !strings.Contains(outStr, "✓") {
		t.Errorf("expected success marker for first artifact, got: %q", outStr)
	}
	// Second artifact should fail.
	if !strings.Contains(outStr, "✗") {
		t.Errorf("expected failure marker for second artifact, got: %q", outStr)
	}
}

// TestPush_PasswordTooShort_RePromptsUntilValid verifies short passwords are rejected with re-prompt.
func TestPush_PasswordTooShort_RePromptsUntilValid(t *testing.T) {
	artifact := makeTempArtifact(t, "id_ed25519", "private-key-content")
	sc := &mockScanner{artifacts: []internal.SSHArtifact{artifact}}
	r2c := newMockR2()
	enc := &mockEncrypter{}
	mm := &mockManifestManager{}
	bm := &mockBackupManager{hashes: []internal.BackupCodeRecord{{ID: "1", Hash: "h", Used: false}}}

	// First password too short, second valid.
	input := "Y\nshort\nstrongpassword123\n"
	runner, out := newPushRunner(input, sc, r2c, enc, mm, bm, false)

	err := runner.run()
	if err != nil {
		t.Fatalf("expected no error after valid password, got: %v", err)
	}

	if !strings.Contains(out.String(), "at least 12 characters") {
		t.Errorf("expected password validation message, got: %q", out.String())
	}
}

// TestPush_SelectSubset_OnlyPushesSelected verifies partial artifact selection works.
func TestPush_SelectSubset_OnlyPushesSelected(t *testing.T) {
	a1 := makeTempArtifact(t, "id_ed25519", "key1")
	a2 := makeTempArtifact(t, "id_rsa", "key2")

	sc := &mockScanner{artifacts: []internal.SSHArtifact{a1, a2}}
	r2c := newMockR2()
	enc := &mockEncrypter{}
	mm := &mockManifestManager{}
	bm := &mockBackupManager{hashes: []internal.BackupCodeRecord{{ID: "1", Hash: "h", Used: false}}}

	// Select "n" to push all, then pick only artifact 1.
	input := "n\n1\nstrongpassword123\n"
	runner, _ := newPushRunner(input, sc, r2c, enc, mm, bm, false)

	err := runner.run()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if _, ok := r2c.uploaded["artifacts/id_ed25519.enc"]; !ok {
		t.Error("expected id_ed25519 to be uploaded")
	}
	if _, ok := r2c.uploaded["artifacts/id_rsa.enc"]; ok {
		t.Error("expected id_rsa NOT to be uploaded")
	}
}
