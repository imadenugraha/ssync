package credentials

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/user/ssync/internal"
	"github.com/user/ssync/internal/crypto"
	"github.com/zalando/go-keyring"
)

const (
	keychainService = "ssync"
	keychainAccount = "master-key"
	masterKeySize   = 32
	credFileName    = "credentials.enc"
	saltFileName    = "credentials.salt"
	configDirName   = "ssync"
)

// CredentialStore defines the interface for saving and loading R2 credentials.
type CredentialStore interface {
	Save(creds internal.R2Credentials) error
	Load() (internal.R2Credentials, error)
}

// fileCredentialStore is the concrete implementation of CredentialStore.
type fileCredentialStore struct {
	configDir  string
	engine     crypto.EncryptionEngine
	passReader func(prompt string) (string, error)
}

// Option is a functional option for configuring the store.
type Option func(*fileCredentialStore)

// WithConfigDir overrides the default config directory (useful for testing).
func WithConfigDir(dir string) Option {
	return func(s *fileCredentialStore) {
		s.configDir = dir
	}
}

// WithPassReader overrides the passphrase reader (useful for testing).
func WithPassReader(fn func(prompt string) (string, error)) Option {
	return func(s *fileCredentialStore) {
		s.passReader = fn
	}
}

// NewCredentialStore creates a new CredentialStore backed by the filesystem.
// By default it uses ~/.config/ssync as the config directory.
func NewCredentialStore(opts ...Option) (CredentialStore, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("get home dir: %w", err)
	}
	s := &fileCredentialStore{
		configDir:  filepath.Join(home, ".config", configDirName),
		engine:     crypto.NewAESEngine(),
		passReader: stdinPassReader,
	}
	for _, o := range opts {
		o(s)
	}
	return s, nil
}

// Save encrypts and persists the credentials to disk.
func (s *fileCredentialStore) Save(creds internal.R2Credentials) error {
	if err := os.MkdirAll(s.configDir, 0700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	password, err := s.resolvePassword(true)
	if err != nil {
		return fmt.Errorf("resolve encryption key: %w", err)
	}

	plaintext, err := json.Marshal(creds)
	if err != nil {
		return fmt.Errorf("marshal credentials: %w", err)
	}

	blob, err := s.engine.Encrypt(plaintext, password)
	if err != nil {
		return fmt.Errorf("encrypt credentials: %w", err)
	}

	credPath := filepath.Join(s.configDir, credFileName)
	if err := os.WriteFile(credPath, blob, 0600); err != nil {
		return fmt.Errorf("write credentials file: %w", err)
	}
	// Ensure permissions are exactly 0600 even if umask interfered.
	if err := os.Chmod(credPath, 0600); err != nil {
		return fmt.Errorf("chmod credentials file: %w", err)
	}
	return nil
}

// Load reads, decrypts, and returns the stored credentials.
func (s *fileCredentialStore) Load() (internal.R2Credentials, error) {
	credPath := filepath.Join(s.configDir, credFileName)

	info, err := os.Stat(credPath)
	if err != nil {
		return internal.R2Credentials{}, fmt.Errorf("stat credentials file: %w", err)
	}

	// Check that permissions are not broader than 0600.
	if info.Mode().Perm()&^0600 != 0 {
		return internal.R2Credentials{}, fmt.Errorf(
			"security error: credential file %s has permissions %04o; expected 0600 — fix with: chmod 0600 %s",
			credPath, info.Mode().Perm(), credPath,
		)
	}

	blob, err := os.ReadFile(credPath)
	if err != nil {
		return internal.R2Credentials{}, fmt.Errorf("read credentials file: %w", err)
	}

	password, err := s.resolvePassword(false)
	if err != nil {
		return internal.R2Credentials{}, fmt.Errorf("resolve encryption key: %w", err)
	}

	plaintext, err := s.engine.Decrypt(blob, password)
	if err != nil {
		return internal.R2Credentials{}, fmt.Errorf("decrypt credentials: %w", err)
	}

	var creds internal.R2Credentials
	if err := json.Unmarshal(plaintext, &creds); err != nil {
		return internal.R2Credentials{}, fmt.Errorf("unmarshal credentials: %w", err)
	}
	return creds, nil
}

// resolvePassword returns the hex-encoded master key (keychain path) or a
// user-supplied passphrase (fallback path).
// forSave=true means we may need to generate/store a new master key.
func (s *fileCredentialStore) resolvePassword(forSave bool) (string, error) {
	// Try keychain first.
	masterKeyHex, err := keyring.Get(keychainService, keychainAccount)
	if err == nil {
		// Keychain available and key already stored.
		return masterKeyHex, nil
	}

	// If the error is "not found" and we are saving, generate a new master key.
	if errors.Is(err, keyring.ErrNotFound) && forSave {
		key := make([]byte, masterKeySize)
		if _, err := io.ReadFull(rand.Reader, key); err != nil {
			return "", fmt.Errorf("generate master key: %w", err)
		}
		// 64 hex chars — satisfies the ≥12 char password requirement.
		hexKey := hex.EncodeToString(key)
		if setErr := keyring.Set(keychainService, keychainAccount, hexKey); setErr == nil {
			return hexKey, nil
		}
		// Keychain set failed — fall through to passphrase path.
	}

	// Fallback: passphrase-based key derivation.
	return s.resolvePassphrase(forSave)
}

// resolvePassphrase handles the fallback path where no OS keychain is available.
// It prompts the user for a passphrase and manages the salt file.
func (s *fileCredentialStore) resolvePassphrase(forSave bool) (string, error) {
	saltPath := filepath.Join(s.configDir, saltFileName)

	if forSave {
		passphrase, err := s.passReader("Enter local passphrase for credential encryption (≥12 chars): ")
		if err != nil {
			return "", fmt.Errorf("read passphrase: %w", err)
		}
		if len(passphrase) < 12 {
			return "", fmt.Errorf("passphrase must be at least 12 characters")
		}

		// Generate and store a salt (kept for future use / reference; the blob
		// carries its own Argon2id salt for the actual KDF).
		salt := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, salt); err != nil {
			return "", fmt.Errorf("generate salt: %w", err)
		}
		if err := os.WriteFile(saltPath, salt, 0600); err != nil {
			return "", fmt.Errorf("write salt file: %w", err)
		}
		return passphrase, nil
	}

	// On load, verify the salt file exists then prompt for the passphrase.
	if _, err := os.Stat(saltPath); err != nil {
		return "", fmt.Errorf("salt file not found; run 'ssync configure' to set up credentials")
	}

	passphrase, err := s.passReader("Enter local passphrase for credential decryption: ")
	if err != nil {
		return "", fmt.Errorf("read passphrase: %w", err)
	}
	return passphrase, nil
}

// stdinPassReader reads a passphrase from stdin.
func stdinPassReader(prompt string) (string, error) {
	fmt.Print(prompt)
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// Ensure fileCredentialStore satisfies the interface at compile time.
var _ CredentialStore = (*fileCredentialStore)(nil)
