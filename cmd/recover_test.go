package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/user/ssync/internal"
	"github.com/user/ssync/internal/crypto"
	"github.com/user/ssync/internal/r2"
)

// ---- Mock implementations for recover tests ----

// mockBackupManagerWithVerify extends mockBackupManager with a controllable Verify result.
type mockBackupManagerWithVerify struct {
	mockBackupManager
	verifyResult bool
	verifyErr    error
	invalidated  string
	invalidateErr error
}

func (m *mockBackupManagerWithVerify) Verify(code string) (bool, error) {
	return m.verifyResult, m.verifyErr
}

func (m *mockBackupManagerWithVerify) Invalidate(code string) error {
	if m.invalidateErr != nil {
		return m.invalidateErr
	}
	m.invalidated = code
	return nil
}

// mockRecoverEngine is an in-memory encrypt/decrypt engine for testing.
// encrypt stores content keyed by (name+password), decrypt retrieves it.
type mockRecoverEngine struct {
	// store maps "password:name" -> content bytes
	store map[string][]byte
}

func newMockRecoverEngine() *mockRecoverEngine {
	return &mockRecoverEngine{store: make(map[string][]byte)}
}

func (m *mockRecoverEngine) EncryptArtifact(content []byte, name, relativePath, password string) ([]byte, error) {
	key := password + ":" + name
	m.store[key] = content
	// Return a blob that encodes the password and name so DecryptWithMetadata can retrieve it.
	blob := []byte(fmt.Sprintf("enc|%s|%s|%s", password, name, relativePath))
	return blob, nil
}

func (m *mockRecoverEngine) DecryptWithMetadata(blob []byte, password string) (crypto.DecryptResult, error) {
	s := string(blob)
	parts := strings.SplitN(s, "|", 4)
	if len(parts) != 4 || parts[0] != "enc" {
		return crypto.DecryptResult{}, errors.New("invalid mock blob")
	}
	blobPassword := parts[1]
	name := parts[2]
	relativePath := parts[3]
	if blobPassword != password {
		return crypto.DecryptResult{}, errors.New("decryption failed: authentication tag mismatch")
	}
	content := m.store[password+":"+name]
	return crypto.DecryptResult{
		Content:      content,
		Name:         name,
		RelativePath: relativePath,
	}, nil
}

// ---- Helpers ----

func newRecoverRunner(input string, r2c *mockR2Client, eng *mockRecoverEngine, mm *mockManifestManager, bm *mockBackupManagerWithVerify) (*recoverRunner, *bytes.Buffer) {
	out := &bytes.Buffer{}
	return &recoverRunner{
		in:       strings.NewReader(input),
		out:      out,
		r2:       r2c,
		engine:   eng,
		manifest: mm,
		backup:   bm,
	}, out
}

// seedArtifact pre-populates the mock R2 and engine with an encrypted artifact.
func seedArtifact(r2c *mockR2Client, eng *mockRecoverEngine, name, relativePath, password, content string) {
	blob, _ := eng.EncryptArtifact([]byte(content), name, relativePath, password)
	r2c.downloaded["artifacts/"+name+".enc"] = blob
}

// ---- Tests ----

// TestRecover_ValidCode_ReEncryptsAndInvalidates verifies the happy path:
// valid backup code triggers re-encryption of all artifacts and invalidates the code.
func TestRecover_ValidCode_ReEncryptsAndInvalidates(t *testing.T) {
	r2c := newMockR2()
	eng := newMockRecoverEngine()

	// Seed one artifact encrypted with old password.
	oldPw := "oldpassword123"
	newPw := "newpassword456"
	seedArtifact(r2c, eng, "id_ed25519", "id_ed25519", oldPw, "private-key-content")

	mm := &mockManifestManager{
		manifest: internal.Manifest{
			Artifacts: []internal.ManifestArtifact{
				{Name: "id_ed25519", R2Key: "artifacts/id_ed25519.enc"},
			},
		},
	}
	bm := &mockBackupManagerWithVerify{
		verifyResult: true,
		mockBackupManager: mockBackupManager{
			hashes: []internal.BackupCodeRecord{
				{ID: "1", Hash: "h1", Used: false},
			},
		},
	}

	// Input: backup code, old password, new password
	input := "AAAAA-BBBBB-CCCCC-DDDDD\n" + oldPw + "\n" + newPw + "\n"
	runner, out := newRecoverRunner(input, r2c, eng, mm, bm)

	err := runner.run()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Artifact should be re-uploaded.
	if _, ok := r2c.uploaded["artifacts/id_ed25519.enc"]; !ok {
		t.Error("expected artifact to be re-uploaded after recovery")
	}

	// Backup code should be invalidated.
	if bm.invalidated != "AAAAA-BBBBB-CCCCC-DDDDD" {
		t.Errorf("expected backup code to be invalidated, got: %q", bm.invalidated)
	}

	// Manifest should be updated.
	if mm.updated == nil {
		t.Error("expected manifest to be updated after recovery")
	}

	// Output should confirm success.
	outStr := out.String()
	if !strings.Contains(outStr, "complete") {
		t.Errorf("expected completion message in output, got: %q", outStr)
	}
}

// TestRecover_InvalidCode_DecrementsAttemptsAndExits verifies that an invalid backup code
// shows the remaining attempts count and returns exit code 1.
func TestRecover_InvalidCode_DecrementsAttempts(t *testing.T) {
	r2c := newMockR2()
	eng := newMockRecoverEngine()
	mm := &mockManifestManager{}
	bm := &mockBackupManagerWithVerify{
		verifyResult: false,
		mockBackupManager: mockBackupManager{
			hashes: []internal.BackupCodeRecord{
				{ID: "1", Hash: "h1", Used: false},
				{ID: "2", Hash: "h2", Used: false},
				{ID: "3", Hash: "h3", Used: true}, // already used
			},
		},
	}

	input := "WRONG-WRONG-WRONG-WRONG\n"
	runner, out := newRecoverRunner(input, r2c, eng, mm, bm)

	err := runner.run()
	if err == nil {
		t.Fatal("expected error on invalid backup code, got nil")
	}

	var ee *exitError
	if !errors.As(err, &ee) || ee.code != 1 {
		t.Errorf("expected exit code 1 on invalid backup code, got: %v", err)
	}

	// Output should show remaining attempts (2 unused codes remain).
	outStr := out.String()
	if !strings.Contains(outStr, "2") {
		t.Errorf("expected remaining attempts count in output, got: %q", outStr)
	}
	if !strings.Contains(outStr, "Invalid backup code") {
		t.Errorf("expected invalid code message in output, got: %q", outStr)
	}
}

// TestRecover_ExhaustedCodes_ShowsPermanentLossWarning verifies that when no unused codes
// remain, the permanent loss warning is displayed and exit code 1 is returned.
func TestRecover_ExhaustedCodes_ShowsPermanentLossWarning(t *testing.T) {
	r2c := newMockR2()
	eng := newMockRecoverEngine()
	mm := &mockManifestManager{}
	bm := &mockBackupManagerWithVerify{
		verifyResult: false,
		mockBackupManager: mockBackupManager{
			// All codes are used.
			hashes: []internal.BackupCodeRecord{
				{ID: "1", Hash: "h1", Used: true},
				{ID: "2", Hash: "h2", Used: true},
			},
		},
	}

	input := "WRONG-WRONG-WRONG-WRONG\n"
	runner, out := newRecoverRunner(input, r2c, eng, mm, bm)

	err := runner.run()
	if err == nil {
		t.Fatal("expected error when all codes exhausted, got nil")
	}

	var ee *exitError
	if !errors.As(err, &ee) || ee.code != 1 {
		t.Errorf("expected exit code 1 when codes exhausted, got: %v", err)
	}

	// Output should contain permanent loss warning.
	outStr := out.String()
	if !strings.Contains(outStr, "exhausted") && !strings.Contains(outStr, "All backup codes") {
		t.Errorf("expected permanent loss warning in output, got: %q", outStr)
	}
}

// TestRecover_NewPasswordTooShort_RePromptsUntilValid verifies short new passwords are rejected.
func TestRecover_NewPasswordTooShort_RePromptsUntilValid(t *testing.T) {
	r2c := newMockR2()
	eng := newMockRecoverEngine()

	oldPw := "oldpassword123"
	newPw := "newpassword456"
	seedArtifact(r2c, eng, "id_ed25519", "id_ed25519", oldPw, "key-content")

	mm := &mockManifestManager{
		manifest: internal.Manifest{
			Artifacts: []internal.ManifestArtifact{
				{Name: "id_ed25519", R2Key: "artifacts/id_ed25519.enc"},
			},
		},
	}
	bm := &mockBackupManagerWithVerify{
		verifyResult: true,
		mockBackupManager: mockBackupManager{
			hashes: []internal.BackupCodeRecord{{ID: "1", Hash: "h1", Used: false}},
		},
	}

	// New password: first attempt too short, second valid.
	input := "AAAAA-BBBBB-CCCCC-DDDDD\n" + oldPw + "\nshort\n" + newPw + "\n"
	runner, out := newRecoverRunner(input, r2c, eng, mm, bm)

	err := runner.run()
	if err != nil {
		t.Fatalf("expected no error after valid password, got: %v", err)
	}

	if !strings.Contains(out.String(), "at least 12 characters") {
		t.Errorf("expected password validation message, got: %q", out.String())
	}
}

// TestRecover_R2DownloadError_ReturnsExitCode2 verifies network errors during download
// result in exit code 2.
func TestRecover_R2DownloadError_ReturnsExitCode2(t *testing.T) {
	r2c := newMockR2()
	r2c.downloadErr = &r2.ConnectionError{Cause: fmt.Errorf("network timeout")}
	eng := newMockRecoverEngine()
	mm := &mockManifestManager{
		manifest: internal.Manifest{
			Artifacts: []internal.ManifestArtifact{
				{Name: "id_ed25519", R2Key: "artifacts/id_ed25519.enc"},
			},
		},
	}
	bm := &mockBackupManagerWithVerify{
		verifyResult: true,
		mockBackupManager: mockBackupManager{
			hashes: []internal.BackupCodeRecord{{ID: "1", Hash: "h1", Used: false}},
		},
	}

	input := "AAAAA-BBBBB-CCCCC-DDDDD\noldpassword123\nnewpassword456\n"
	runner, _ := newRecoverRunner(input, r2c, eng, mm, bm)

	err := runner.run()
	if err == nil {
		t.Fatal("expected error on download failure, got nil")
	}

	var ee *exitError
	if !errors.As(err, &ee) || ee.code != 2 {
		t.Errorf("expected exit code 2 on download failure, got: %v", err)
	}
}
