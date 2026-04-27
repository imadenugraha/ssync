package crypto

import (
	"bytes"
	"testing"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
)

// genContent generates random byte slices (0–4096 bytes) for artifact content.
func genContent() gopter.Gen {
	return gen.SliceOf(gen.UInt8())
}

// genFilename generates random non-empty filenames (printable ASCII, 1–64 chars).
func genFilename() gopter.Gen {
	return gen.RegexMatch(`[a-zA-Z0-9_\-\.]{1,64}`)
}

// genRelativePath generates random relative paths (1–128 chars).
func genRelativePath() gopter.Gen {
	return gen.RegexMatch(`[a-zA-Z0-9_\-\.\/]{1,128}`)
}

// genValidPassword generates random passwords of length ≥ 12.
func genValidPassword() gopter.Gen {
	return gen.RegexMatch(`[a-zA-Z0-9!@#$%^&*]{12,32}`)
}

// Feature: ssh-config-sync, Property 1: Encryption round-trip preserves content and metadata
//
// Validates: Requirements 9.1, 9.3, 2.2
func TestProperty1_EncryptionRoundTrip(t *testing.T) {
	params := gopter.DefaultTestParameters()
	params.MinSuccessfulTests = 5

	properties := gopter.NewProperties(params)

	properties.Property("encrypt then decrypt yields identical content and metadata", prop.ForAll(
		func(content []byte, name, relativePath, password string) bool {
			engine := NewAESEngine()

			blob, err := engine.EncryptArtifact(content, name, relativePath, password)
			if err != nil {
				t.Logf("EncryptArtifact error: %v", err)
				return false
			}

			result, err := engine.DecryptWithMetadata(blob, password)
			if err != nil {
				t.Logf("DecryptWithMetadata error: %v", err)
				return false
			}

			if !bytes.Equal(result.Content, content) {
				t.Logf("content mismatch: got %v, want %v", result.Content, content)
				return false
			}
			if result.Name != name {
				t.Logf("name mismatch: got %q, want %q", result.Name, name)
				return false
			}
			if result.RelativePath != relativePath {
				t.Logf("relativePath mismatch: got %q, want %q", result.RelativePath, relativePath)
				return false
			}
			return true
		},
		genContent(),
		genFilename(),
		genRelativePath(),
		genValidPassword(),
	))

	properties.TestingRun(t)
}

// Feature: ssh-config-sync, Property 2: Each encryption produces unique ciphertext
//
// Validates: Requirements 9.2, 1.2, 1.3
func TestProperty2_UniqueEncryptions(t *testing.T) {
	params := gopter.DefaultTestParameters()
	params.MinSuccessfulTests = 5

	properties := gopter.NewProperties(params)

	properties.Property("same plaintext and password produce different blobs each time", prop.ForAll(
		func(content []byte, name, relativePath, password string) bool {
			engine := NewAESEngine()

			blob1, err := engine.EncryptArtifact(content, name, relativePath, password)
			if err != nil {
				t.Logf("EncryptArtifact (1) error: %v", err)
				return false
			}
			blob2, err := engine.EncryptArtifact(content, name, relativePath, password)
			if err != nil {
				t.Logf("EncryptArtifact (2) error: %v", err)
				return false
			}

			// Salt: bytes [5:37]
			salt1 := blob1[5:37]
			salt2 := blob2[5:37]
			if bytes.Equal(salt1, salt2) {
				t.Log("salts are identical — expected unique salts")
				return false
			}

			// Nonce: bytes [37:49]
			nonce1 := blob1[37:49]
			nonce2 := blob2[37:49]
			if bytes.Equal(nonce1, nonce2) {
				t.Log("nonces are identical — expected unique nonces")
				return false
			}

			// Ciphertext: bytes [65:]
			ct1 := blob1[65:]
			ct2 := blob2[65:]
			if bytes.Equal(ct1, ct2) {
				t.Log("ciphertexts are identical — expected unique ciphertexts")
				return false
			}

			return true
		},
		genContent(),
		genFilename(),
		genRelativePath(),
		genValidPassword(),
	))

	properties.TestingRun(t)
}

// Feature: ssh-config-sync, Property 3: Wrong password fails decryption
//
// Validates: Requirements 2.5
func TestProperty3_WrongPasswordFailsDecryption(t *testing.T) {
	params := gopter.DefaultTestParameters()
	params.MinSuccessfulTests = 5

	properties := gopter.NewProperties(params)

	properties.Property("decrypting with wrong password returns error and no plaintext", prop.ForAll(
		func(content []byte, name, relativePath, passwordA, passwordB string) bool {
			// Ensure the two passwords are distinct.
			if passwordA == passwordB {
				return true // skip equal-password cases
			}

			engine := NewAESEngine()

			blob, err := engine.EncryptArtifact(content, name, relativePath, passwordA)
			if err != nil {
				t.Logf("EncryptArtifact error: %v", err)
				return false
			}

			plaintext, err := engine.Decrypt(blob, passwordB)
			if err == nil {
				t.Log("expected error when decrypting with wrong password, got nil")
				return false
			}
			if len(plaintext) != 0 {
				t.Logf("expected no plaintext on wrong-password decrypt, got %d bytes", len(plaintext))
				return false
			}
			return true
		},
		genContent(),
		genFilename(),
		genRelativePath(),
		genValidPassword(),
		genValidPassword(),
	))

	properties.TestingRun(t)
}

// Feature: ssh-config-sync, Property 4: Tampered ciphertext fails decryption
//
// Validates: Requirements 2.3, 2.4
func TestProperty4_TamperedCiphertextFailsDecryption(t *testing.T) {
	params := gopter.DefaultTestParameters()
	params.MinSuccessfulTests = 5

	properties := gopter.NewProperties(params)

	properties.Property("mutating any byte at offset ≥ 65 causes authentication failure", prop.ForAll(
		func(content []byte, name, relativePath, password string, mutationOffset uint) bool {
			engine := NewAESEngine()

			blob, err := engine.EncryptArtifact(content, name, relativePath, password)
			if err != nil {
				t.Logf("EncryptArtifact error: %v", err)
				return false
			}

			// The ciphertext+tag region starts at byte 65.
			// We need at least one byte to mutate there.
			if len(blob) <= 65 {
				// blob too short to have a ciphertext region; skip.
				return true
			}

			// Pick a mutation offset in [65, len(blob)-1].
			offset := 65 + int(mutationOffset)%(len(blob)-65)

			tampered := make([]byte, len(blob))
			copy(tampered, blob)
			tampered[offset] ^= 0xFF // flip all bits

			plaintext, err := engine.Decrypt(tampered, password)
			if err == nil {
				t.Logf("expected authentication error after tampering byte %d, got nil", offset)
				return false
			}
			if len(plaintext) != 0 {
				t.Logf("expected no plaintext after tampering, got %d bytes", len(plaintext))
				return false
			}
			return true
		},
		genContent(),
		genFilename(),
		genRelativePath(),
		genValidPassword(),
		gen.UInt(),
	))

	properties.TestingRun(t)
}

// Feature: ssh-config-sync, Property 13: Short passwords are rejected
//
// Validates: Requirements 1.5
func TestProperty13_ShortPasswordsRejected(t *testing.T) {
	params := gopter.DefaultTestParameters()
	params.MinSuccessfulTests = 20

	properties := gopter.NewProperties(params)

	// Generator for strings of length 0–11 (including empty and whitespace-only).
	genShortPassword := gen.OneGenOf(
		gen.Const(""),
		gen.RegexMatch(`\s{1,11}`),
		gen.RegexMatch(`.{0,11}`),
	)

	properties.Property("ValidatePassword rejects any string shorter than 12 characters", prop.ForAll(
		func(password string) bool {
			if len(password) >= 12 {
				// Generator produced something too long; skip.
				return true
			}
			err := ValidatePassword(password)
			if err == nil {
				t.Logf("expected error for short password %q (len=%d), got nil", password, len(password))
				return false
			}
			return true
		},
		genShortPassword,
	))

	properties.TestingRun(t)
}

// Feature: ssh-config-sync, Property 11: Re-encryption after recovery uses new password
//
// Validates: Requirements 6.3
func TestProperty11_ReEncryptionAfterRecoveryUsesNewPassword(t *testing.T) {
	params := gopter.DefaultTestParameters()
	params.MinSuccessfulTests = 5

	properties := gopter.NewProperties(params)

	properties.Property("after re-encryption with password B, artifacts decrypt with B and fail with A", prop.ForAll(
		func(passwordA, passwordB string,
			content1 []byte, name1, path1 string,
			content2 []byte, name2, path2 string,
			content3 []byte, name3, path3 string,
		) bool {
			if passwordA == passwordB {
				return true // skip equal-password cases
			}

			type artifact struct {
				content      []byte
				name         string
				relativePath string
			}
			artifacts := []artifact{
				{content1, name1, path1},
				{content2, name2, path2},
				{content3, name3, path3},
			}

			engine := NewAESEngine()

			// Encrypt all artifacts with password A.
			blobs := make([][]byte, len(artifacts))
			for i, a := range artifacts {
				blob, err := engine.EncryptArtifact(a.content, a.name, a.relativePath, passwordA)
				if err != nil {
					t.Logf("EncryptArtifact (A) error: %v", err)
					return false
				}
				blobs[i] = blob
			}

			// Simulate recovery: decrypt with A, re-encrypt with B.
			newBlobs := make([][]byte, len(artifacts))
			for i, blob := range blobs {
				result, err := engine.DecryptWithMetadata(blob, passwordA)
				if err != nil {
					t.Logf("DecryptWithMetadata (A) error: %v", err)
					return false
				}
				newBlob, err := engine.EncryptArtifact(result.Content, result.Name, result.RelativePath, passwordB)
				if err != nil {
					t.Logf("EncryptArtifact (B) error: %v", err)
					return false
				}
				newBlobs[i] = newBlob
			}

			// Assert: each new blob decrypts successfully with B and content matches.
			for i, newBlob := range newBlobs {
				result, err := engine.DecryptWithMetadata(newBlob, passwordB)
				if err != nil {
					t.Logf("DecryptWithMetadata (B) error: %v", err)
					return false
				}
				if !bytes.Equal(result.Content, artifacts[i].content) {
					t.Logf("content mismatch after re-encryption: got %v, want %v", result.Content, artifacts[i].content)
					return false
				}
			}

			// Assert: each new blob fails decryption with old password A.
			for _, newBlob := range newBlobs {
				_, err := engine.DecryptWithMetadata(newBlob, passwordA)
				if err == nil {
					t.Log("expected decryption with old password A to fail after re-encryption, but it succeeded")
					return false
				}
			}

			return true
		},
		genValidPassword(),
		genValidPassword(),
		genContent(), genFilename(), genRelativePath(),
		genContent(), genFilename(), genRelativePath(),
		genContent(), genFilename(), genRelativePath(),
	))

	properties.TestingRun(t)
}
