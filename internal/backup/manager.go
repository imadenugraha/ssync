package backup

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/user/ssync/internal"
	"github.com/user/ssync/internal/r2"
	"golang.org/x/crypto/argon2"
)

const (
	backupCodesKey = "backup-codes.json"
	numCodes       = 8

	argon2Memory      = 65536
	argon2Iterations  = 3
	argon2Parallelism = 4
	argon2KeyLen      = 32
	argon2SaltLen     = 16
)

// BackupCodeManager defines the interface for managing backup codes.
type BackupCodeManager interface {
	Generate() ([]internal.BackupCode, error)
	StoreHashes(codes []internal.BackupCode) error
	Verify(code string) (bool, error)
	Invalidate(code string) error
	LoadHashes() ([]internal.BackupCodeRecord, error)
}

type backupCodesFile struct {
	Codes       []internal.BackupCodeRecord `json:"codes"`
	GeneratedAt time.Time                   `json:"generated_at"`
}

type manager struct {
	r2 r2.R2Client
}

// NewManager creates a new BackupCodeManager backed by the given R2 client.
func NewManager(client r2.R2Client) BackupCodeManager {
	return &manager{r2: client}
}

// Generate creates 8 cryptographically random backup codes in XXXXX-XXXXX-XXXXX-XXXXX format.
func (m *manager) Generate() ([]internal.BackupCode, error) {
	codes := make([]internal.BackupCode, numCodes)
	for i := range codes {
		raw := make([]byte, 16)
		if _, err := rand.Read(raw); err != nil {
			return nil, fmt.Errorf("generating random bytes: %w", err)
		}
		// base32 encode, take first 20 chars, split into 4 groups of 5
		encoded := base32.StdEncoding.EncodeToString(raw) // 26 chars for 16 bytes
		seg := encoded[:20]
		code := seg[0:5] + "-" + seg[5:10] + "-" + seg[10:15] + "-" + seg[15:20]
		codes[i] = internal.BackupCode{Code: code}
	}
	return codes, nil
}

// StoreHashes hashes each code with Argon2id and uploads backup-codes.json to R2.
func (m *manager) StoreHashes(codes []internal.BackupCode) error {
	records := make([]internal.BackupCodeRecord, len(codes))
	for i, c := range codes {
		hash, err := hashCode(c.Code)
		if err != nil {
			return fmt.Errorf("hashing code %d: %w", i+1, err)
		}
		records[i] = internal.BackupCodeRecord{
			ID:   fmt.Sprintf("%d", i+1),
			Hash: hash,
			Used: false,
		}
	}

	file := backupCodesFile{
		Codes:       records,
		GeneratedAt: time.Now().UTC(),
	}
	data, err := json.Marshal(file)
	if err != nil {
		return fmt.Errorf("marshaling backup codes: %w", err)
	}
	return m.r2.Upload(backupCodesKey, data)
}

// Verify checks whether the provided code matches any unused stored hash.
func (m *manager) Verify(code string) (bool, error) {
	records, err := m.LoadHashes()
	if err != nil {
		return false, err
	}
	for _, rec := range records {
		if rec.Used {
			continue
		}
		match, err := verifyCode(code, rec.Hash)
		if err != nil {
			return false, fmt.Errorf("verifying code against record %s: %w", rec.ID, err)
		}
		if match {
			return true, nil
		}
	}
	return false, nil
}

// Invalidate marks the matching code as used and re-uploads backup-codes.json.
func (m *manager) Invalidate(code string) error {
	data, err := m.r2.Download(backupCodesKey)
	if err != nil {
		return fmt.Errorf("downloading backup codes: %w", err)
	}
	var file backupCodesFile
	if err := json.Unmarshal(data, &file); err != nil {
		return fmt.Errorf("unmarshaling backup codes: %w", err)
	}

	invalidated := false
	for i, rec := range file.Codes {
		if rec.Used {
			continue
		}
		match, err := verifyCode(code, rec.Hash)
		if err != nil {
			return fmt.Errorf("verifying code against record %s: %w", rec.ID, err)
		}
		if match {
			file.Codes[i].Used = true
			invalidated = true
			break
		}
	}
	if !invalidated {
		return errors.New("code not found or already used")
	}

	updated, err := json.Marshal(file)
	if err != nil {
		return fmt.Errorf("marshaling updated backup codes: %w", err)
	}
	return m.r2.Upload(backupCodesKey, updated)
}

// LoadHashes downloads and returns the stored backup code records from R2.
func (m *manager) LoadHashes() ([]internal.BackupCodeRecord, error) {
	data, err := m.r2.Download(backupCodesKey)
	if err != nil {
		return nil, fmt.Errorf("downloading backup codes: %w", err)
	}
	var file backupCodesFile
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("unmarshaling backup codes: %w", err)
	}
	return file.Codes, nil
}

// hashCode hashes a backup code using Argon2id with a random salt, returning a PHC string.
func hashCode(code string) (string, error) {
	salt := make([]byte, argon2SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generating salt: %w", err)
	}
	hash := argon2.IDKey([]byte(code), salt, argon2Iterations, argon2Memory, argon2Parallelism, argon2KeyLen)

	saltB64 := base64.RawStdEncoding.EncodeToString(salt)
	hashB64 := base64.RawStdEncoding.EncodeToString(hash)

	phc := fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		argon2Memory, argon2Iterations, argon2Parallelism, saltB64, hashB64)
	return phc, nil
}

// verifyCode checks a plaintext code against a PHC-format Argon2id hash using constant-time comparison.
func verifyCode(code, phc string) (bool, error) {
	salt, storedHash, err := parsePHC(phc)
	if err != nil {
		return false, fmt.Errorf("parsing PHC string: %w", err)
	}
	computed := argon2.IDKey([]byte(code), salt, argon2Iterations, argon2Memory, argon2Parallelism, argon2KeyLen)
	return subtle.ConstantTimeCompare(computed, storedHash) == 1, nil
}

// parsePHC parses a PHC-format Argon2id string and returns the salt and hash bytes.
// Expected format: $argon2id$v=19$m=65536,t=3,p=4$<salt-b64>$<hash-b64>
func parsePHC(phc string) (salt, hash []byte, err error) {
	// Split on $ — first element is empty (leading $)
	parts := strings.Split(phc, "$")
	// parts: ["", "argon2id", "v=19", "m=65536,t=3,p=4", "<salt>", "<hash>"]
	if len(parts) != 6 {
		return nil, nil, fmt.Errorf("invalid PHC format: expected 6 parts, got %d", len(parts))
	}
	if parts[1] != "argon2id" {
		return nil, nil, fmt.Errorf("invalid PHC format: expected argon2id, got %s", parts[1])
	}

	salt, err = base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, nil, fmt.Errorf("decoding salt: %w", err)
	}
	hash, err = base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return nil, nil, fmt.Errorf("decoding hash: %w", err)
	}
	return salt, hash, nil
}
