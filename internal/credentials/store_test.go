package credentials

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
	"github.com/user/ssync/internal"
)

// genNonEmptyString generates random non-empty alphanumeric strings (1–64 chars).
func genNonEmptyString() gopter.Gen {
	return gen.RegexMatch(`[a-zA-Z0-9_\-\.]{1,64}`)
}

// newTestStore creates a CredentialStore backed by a temp directory with a fixed passphrase.
func newTestStore(t *testing.T) (CredentialStore, string) {
	t.Helper()
	tmpDir, err := os.MkdirTemp("", "cred-store-test-*")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(tmpDir) })

	passReader := func(prompt string) (string, error) {
		return "testpassword123", nil
	}

	store, err := NewCredentialStore(
		WithConfigDir(tmpDir),
		WithPassReader(passReader),
	)
	if err != nil {
		t.Fatalf("NewCredentialStore: %v", err)
	}
	return store, tmpDir
}

// Feature: ssh-config-sync, Property 5: Credential store round-trip
//
// Validates: Requirements 10.1
func TestProperty5_CredentialStoreRoundTrip(t *testing.T) {
	params := gopter.DefaultTestParameters()
	params.MinSuccessfulTests = 5

	properties := gopter.NewProperties(params)

	properties.Property("Save then Load returns byte-identical credential fields", prop.ForAll(
		func(accessKeyID, secretAccessKey, endpointURL, bucketName string) bool {
			store, _ := newTestStore(t)

			creds := internal.R2Credentials{
				AccessKeyID:     accessKeyID,
				SecretAccessKey: secretAccessKey,
				EndpointURL:     endpointURL,
				BucketName:      bucketName,
			}

			if err := store.Save(creds); err != nil {
				t.Logf("Save error: %v", err)
				return false
			}

			loaded, err := store.Load()
			if err != nil {
				t.Logf("Load error: %v", err)
				return false
			}

			if loaded.AccessKeyID != creds.AccessKeyID {
				t.Logf("AccessKeyID mismatch: got %q, want %q", loaded.AccessKeyID, creds.AccessKeyID)
				return false
			}
			if loaded.SecretAccessKey != creds.SecretAccessKey {
				t.Logf("SecretAccessKey mismatch: got %q, want %q", loaded.SecretAccessKey, creds.SecretAccessKey)
				return false
			}
			if loaded.EndpointURL != creds.EndpointURL {
				t.Logf("EndpointURL mismatch: got %q, want %q", loaded.EndpointURL, creds.EndpointURL)
				return false
			}
			if loaded.BucketName != creds.BucketName {
				t.Logf("BucketName mismatch: got %q, want %q", loaded.BucketName, creds.BucketName)
				return false
			}
			return true
		},
		genNonEmptyString(),
		genNonEmptyString(),
		genNonEmptyString(),
		genNonEmptyString(),
	))

	properties.TestingRun(t)
}

// Feature: ssh-config-sync, Property 6: Tampered credential file fails load
//
// Validates: Requirements 10.2
func TestProperty6_TamperedCredentialFileFailsLoad(t *testing.T) {
	params := gopter.DefaultTestParameters()
	params.MinSuccessfulTests = 5

	properties := gopter.NewProperties(params)

	properties.Property("mutating any byte in the credential file causes Load to return an error", prop.ForAll(
		func(accessKeyID, secretAccessKey, endpointURL, bucketName string, mutationOffset uint) bool {
			store, tmpDir := newTestStore(t)

			creds := internal.R2Credentials{
				AccessKeyID:     accessKeyID,
				SecretAccessKey: secretAccessKey,
				EndpointURL:     endpointURL,
				BucketName:      bucketName,
			}

			if err := store.Save(creds); err != nil {
				t.Logf("Save error: %v", err)
				return false
			}

			credPath := filepath.Join(tmpDir, credFileName)

			data, err := os.ReadFile(credPath)
			if err != nil {
				t.Logf("ReadFile error: %v", err)
				return false
			}

			if len(data) == 0 {
				// Nothing to tamper; skip.
				return true
			}

			offset := int(mutationOffset) % len(data)
			tampered := make([]byte, len(data))
			copy(tampered, data)
			tampered[offset] ^= 0xFF

			if err := os.WriteFile(credPath, tampered, 0600); err != nil {
				t.Logf("WriteFile (tampered) error: %v", err)
				return false
			}

			loaded, err := store.Load()
			if err == nil {
				t.Logf("expected error after tampering byte %d, got nil; loaded: %+v", offset, loaded)
				return false
			}
			// Ensure no credential data is returned on error.
			if loaded != (internal.R2Credentials{}) {
				t.Logf("expected empty credentials on tamper error, got: %+v", loaded)
				return false
			}
			return true
		},
		genNonEmptyString(),
		genNonEmptyString(),
		genNonEmptyString(),
		genNonEmptyString(),
		gen.UInt(),
	))

	properties.TestingRun(t)
}

// Feature: ssh-config-sync, Property 7: Credential file permissions are enforced
//
// Validates: Requirements 4.3, 4.5
func TestProperty7_CredentialFilePermissionsEnforced(t *testing.T) {
	params := gopter.DefaultTestParameters()
	params.MinSuccessfulTests = 5

	properties := gopter.NewProperties(params)

	properties.Property("Save writes mode 0600; widening permissions causes Load to return a security error", prop.ForAll(
		func(accessKeyID, secretAccessKey, endpointURL, bucketName string) bool {
			store, tmpDir := newTestStore(t)

			creds := internal.R2Credentials{
				AccessKeyID:     accessKeyID,
				SecretAccessKey: secretAccessKey,
				EndpointURL:     endpointURL,
				BucketName:      bucketName,
			}

			if err := store.Save(creds); err != nil {
				t.Logf("Save error: %v", err)
				return false
			}

			credPath := filepath.Join(tmpDir, credFileName)

			info, err := os.Stat(credPath)
			if err != nil {
				t.Logf("Stat error: %v", err)
				return false
			}

			// Assert file was saved with exactly 0600.
			if info.Mode().Perm() != 0600 {
				t.Logf("expected mode 0600, got %04o", info.Mode().Perm())
				return false
			}

			// Widen permissions to 0644 and attempt Load.
			if err := os.Chmod(credPath, 0644); err != nil {
				t.Logf("Chmod error: %v", err)
				return false
			}

			loaded, err := store.Load()
			if err == nil {
				t.Logf("expected security error after widening permissions, got nil; loaded: %+v", loaded)
				return false
			}
			if loaded != (internal.R2Credentials{}) {
				t.Logf("expected empty credentials on permission error, got: %+v", loaded)
				return false
			}
			return true
		},
		genNonEmptyString(),
		genNonEmptyString(),
		genNonEmptyString(),
		genNonEmptyString(),
	))

	properties.TestingRun(t)
}
