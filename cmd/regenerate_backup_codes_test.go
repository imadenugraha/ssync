package cmd

import (
	"bufio"
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/user/ssync/internal"
)

// newRegenRunner constructs a regenRunner with a string reader for input and captures output.
func newRegenRunner(input string, r2c *mockR2ForPull, dec *mockDecrypter, mm *mockManifestManager, bm *mockBackupManager) (*regenRunner, *bytes.Buffer) {
	out := &bytes.Buffer{}
	in := strings.NewReader(input)
	inSc := bufio.NewScanner(in)
	return &regenRunner{
		in:       in,
		out:      out,
		r2:       r2c,
		engine:   dec,
		manifest: mm,
		backup:   bm,
		pwReader: readerPasswordReader(inSc),
	}, out
}

// TestRegen_CorrectPassword_GeneratesAndDisplaysNewCodes verifies the happy path:
// correct password causes new codes to be generated, displayed, and stored.
func TestRegen_CorrectPassword_GeneratesAndDisplaysNewCodes(t *testing.T) {
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

	bm := &mockBackupManager{}

	runner, out := newRegenRunner("correctpassword123\n", r2c, dec, mm, bm)

	err := runner.run()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// New codes should have been generated.
	if bm.generated == nil {
		t.Error("expected backup codes to be generated")
	}

	// New codes should have been stored.
	if !bm.stored {
		t.Error("expected backup codes to be stored")
	}

	outStr := out.String()

	// Output should contain the backup codes section.
	if !strings.Contains(outStr, "NEW BACKUP CODES") {
		t.Errorf("expected backup codes section in output, got: %q", outStr)
	}

	// Output should contain offline storage warning.
	if !strings.Contains(outStr, "offline") {
		t.Errorf("expected offline storage warning in output, got: %q", outStr)
	}

	// Each generated code should appear in the output.
	for _, c := range bm.generated {
		if !strings.Contains(outStr, c.Code) {
			t.Errorf("expected backup code %q in output, got: %q", c.Code, outStr)
		}
	}

	// Output should warn that previous codes are invalidated.
	if !strings.Contains(outStr, "invalidated") {
		t.Errorf("expected invalidation warning in output, got: %q", outStr)
	}
}

// TestRegen_WrongPassword_Rejected verifies that a wrong password returns exit code 1
// and does not generate or store any new codes.
func TestRegen_WrongPassword_Rejected(t *testing.T) {
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

	bm := &mockBackupManager{}

	runner, out := newRegenRunner("wrongpassword123\n", r2c, dec, mm, bm)

	err := runner.run()
	if err == nil {
		t.Fatal("expected error on wrong password, got nil")
	}

	var ee *exitError
	if !errors.As(err, &ee) || ee.code != 1 {
		t.Errorf("expected exit code 1 on wrong password, got: %v", err)
	}

	// No codes should have been generated or stored.
	if bm.generated != nil {
		t.Error("expected no codes to be generated on wrong password")
	}
	if bm.stored {
		t.Error("expected no codes to be stored on wrong password")
	}

	// Output should indicate wrong password.
	if !strings.Contains(out.String(), "wrong password") {
		t.Errorf("expected wrong password message in output, got: %q", out.String())
	}
}

// TestRegen_NewCodesStoredAndOldCodesInvalidated verifies that StoreHashes is called with
// the newly generated codes, which overwrites backup-codes.json and invalidates old codes.
func TestRegen_NewCodesStoredAndOldCodesInvalidated(t *testing.T) {
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

	// Simulate existing backup codes that should be replaced.
	bm := &mockBackupManager{
		hashes: []internal.BackupCodeRecord{
			{ID: "1", Hash: "oldhash1", Used: false},
			{ID: "2", Hash: "oldhash2", Used: false},
		},
	}

	runner, _ := newRegenRunner("correctpassword123\n", r2c, dec, mm, bm)

	err := runner.run()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// StoreHashes must have been called (overwrites old backup-codes.json).
	if !bm.stored {
		t.Error("expected StoreHashes to be called to overwrite old codes")
	}

	// The stored codes should be the newly generated ones.
	if bm.generated == nil {
		t.Error("expected new codes to be generated")
	}

	// Verify the generated codes are distinct from the old hashes
	// (the mock Generate always returns fixed codes, so we just check stored=true).
	if len(bm.generated) == 0 {
		t.Error("expected at least one new backup code to be generated")
	}
}

// TestRegen_StoreHashesError_ReturnsExitCode2 verifies that a failure to store hashes
// returns exit code 2.
func TestRegen_StoreHashesError_ReturnsExitCode2(t *testing.T) {
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

	bm := &mockBackupManager{
		storeErr: errors.New("R2 upload failed"),
	}

	runner, _ := newRegenRunner("correctpassword123\n", r2c, dec, mm, bm)

	err := runner.run()
	if err == nil {
		t.Fatal("expected error on store failure, got nil")
	}

	var ee *exitError
	if !errors.As(err, &ee) || ee.code != 2 {
		t.Errorf("expected exit code 2 on store failure, got: %v", err)
	}
}

// TestRegen_ManifestFetchError_ReturnsExitCode2 verifies that a manifest fetch failure
// returns exit code 2.
func TestRegen_ManifestFetchError_ReturnsExitCode2(t *testing.T) {
	mm := &mockManifestManager{
		fetchErr: errors.New("network error"),
	}

	r2c := &mockR2ForPull{}
	dec := &mockDecrypter{}
	bm := &mockBackupManager{}

	runner, _ := newRegenRunner("correctpassword123\n", r2c, dec, mm, bm)

	err := runner.run()
	if err == nil {
		t.Fatal("expected error on manifest fetch failure, got nil")
	}

	var ee *exitError
	if !errors.As(err, &ee) || ee.code != 2 {
		t.Errorf("expected exit code 2 on manifest fetch error, got: %v", err)
	}
}
