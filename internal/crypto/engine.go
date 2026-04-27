package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
)

// Magic bytes identifying the SSCS blob format: "SSCS"
var magic = [4]byte{0x53, 0x53, 0x43, 0x53}

const (
	blobVersion    byte = 0x01
	saltSize            = 32
	nonceSize           = 12
	tagSize             = 16
	headerSize          = 4 + 1 + saltSize + nonceSize + tagSize // 65 bytes
	minPasswordLen      = 12

	// Argon2id parameters
	argonMemory  uint32 = 65536
	argonTime    uint32 = 3
	argonThreads uint8  = 4
	argonKeyLen  uint32 = 32
)

// envelope is the JSON payload encrypted inside each blob.
type envelope struct {
	Name         string `json:"name"`
	RelativePath string `json:"relative_path"`
	Content      string `json:"content"` // base64-encoded file bytes
}

// DecryptResult holds the decrypted content along with its metadata.
type DecryptResult struct {
	Content      []byte
	Name         string
	RelativePath string
}

// EncryptionEngine defines the interface for encrypting and decrypting SSH artifacts.
type EncryptionEngine interface {
	Encrypt(plaintext []byte, password string) ([]byte, error)
	Decrypt(blob []byte, password string) ([]byte, error)
	DecryptWithMetadata(blob []byte, password string) (DecryptResult, error)
}

// AESEngine is the concrete AES-256-GCM + Argon2id implementation.
type AESEngine struct{}

// NewAESEngine returns a new AESEngine.
func NewAESEngine() *AESEngine {
	return &AESEngine{}
}

// ValidatePassword returns an error if the password is shorter than 12 characters.
func ValidatePassword(password string) error {
	if len(password) < minPasswordLen {
		return fmt.Errorf("password must be at least %d characters long", minPasswordLen)
	}
	return nil
}

// Encrypt encrypts plaintext using AES-256-GCM with Argon2id key derivation.
// The name and relativePath parameters are embedded in the encrypted envelope.
// To encrypt a raw artifact, use EncryptArtifact instead.
// This low-level method encrypts arbitrary bytes; the caller is responsible for
// constructing the envelope JSON before calling this if metadata is needed.
//
// For artifact encryption with metadata, use EncryptArtifact.
func (e *AESEngine) Encrypt(plaintext []byte, password string) ([]byte, error) {
	return encryptRaw(plaintext, password)
}

// EncryptArtifact encrypts an SSH artifact with its metadata embedded in the envelope.
func (e *AESEngine) EncryptArtifact(content []byte, name, relativePath, password string) ([]byte, error) {
	if err := ValidatePassword(password); err != nil {
		return nil, err
	}

	env := envelope{
		Name:         name,
		RelativePath: relativePath,
		Content:      base64.StdEncoding.EncodeToString(content),
	}
	payload, err := json.Marshal(env)
	if err != nil {
		return nil, fmt.Errorf("marshal envelope: %w", err)
	}

	return encryptRaw(payload, password)
}

// Decrypt decrypts a blob and returns the raw plaintext bytes.
// If the blob contains a JSON envelope, the caller must parse it.
// For artifact decryption with metadata extraction, use DecryptWithMetadata.
func (e *AESEngine) Decrypt(blob []byte, password string) ([]byte, error) {
	return decryptRaw(blob, password)
}

// DecryptWithMetadata decrypts a blob and extracts the envelope metadata.
func (e *AESEngine) DecryptWithMetadata(blob []byte, password string) (DecryptResult, error) {
	plaintext, err := decryptRaw(blob, password)
	if err != nil {
		return DecryptResult{}, err
	}

	var env envelope
	if err := json.Unmarshal(plaintext, &env); err != nil {
		return DecryptResult{}, fmt.Errorf("unmarshal envelope: %w", err)
	}

	content, err := base64.StdEncoding.DecodeString(env.Content)
	if err != nil {
		return DecryptResult{}, fmt.Errorf("decode content: %w", err)
	}

	return DecryptResult{
		Content:      content,
		Name:         env.Name,
		RelativePath: env.RelativePath,
	}, nil
}

// encryptRaw performs the low-level AES-256-GCM encryption with Argon2id KDF.
// It validates the password, generates random salt and nonce, derives the key,
// and returns the binary blob: magic + version + salt + nonce + tag + ciphertext.
func encryptRaw(plaintext []byte, password string) ([]byte, error) {
	if err := ValidatePassword(password); err != nil {
		return nil, err
	}

	// Generate random salt and nonce.
	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}

	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	// Derive key with Argon2id.
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)

	// AES-256-GCM seal.
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	// Seal appends tag to ciphertext: result = ciphertext || tag
	sealed := gcm.Seal(nil, nonce, plaintext, nil)

	// Split ciphertext and tag.
	// Go's GCM appends the tag at the end of the sealed output.
	ciphertext := sealed[:len(sealed)-tagSize]
	tag := sealed[len(sealed)-tagSize:]

	// Build binary blob: magic(4) + version(1) + salt(32) + nonce(12) + tag(16) + ciphertext
	blob := make([]byte, 0, headerSize+len(ciphertext))
	blob = append(blob, magic[:]...)
	blob = append(blob, blobVersion)
	blob = append(blob, salt...)
	blob = append(blob, nonce...)
	blob = append(blob, tag...)
	blob = append(blob, ciphertext...)

	return blob, nil
}

// decryptRaw parses the binary blob header, derives the key, and decrypts.
func decryptRaw(blob []byte, password string) ([]byte, error) {
	if err := ValidatePassword(password); err != nil {
		return nil, err
	}

	if len(blob) < headerSize {
		return nil, errors.New("blob too short: invalid format")
	}

	// Validate magic bytes.
	if blob[0] != magic[0] || blob[1] != magic[1] || blob[2] != magic[2] || blob[3] != magic[3] {
		return nil, errors.New("invalid magic bytes: not an SSCS blob")
	}

	// Validate version.
	version := blob[4]
	if version != blobVersion {
		return nil, fmt.Errorf("unsupported blob version: %d", version)
	}

	// Parse header fields.
	offset := 5
	salt := blob[offset : offset+saltSize]
	offset += saltSize
	nonce := blob[offset : offset+nonceSize]
	offset += nonceSize
	tag := blob[offset : offset+tagSize]
	offset += tagSize
	ciphertext := blob[offset:]

	// Derive key with Argon2id using stored salt.
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)

	// AES-256-GCM open: reassemble ciphertext || tag for Go's GCM.
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	// Go's gcm.Open expects ciphertext with tag appended.
	combined := make([]byte, len(ciphertext)+tagSize)
	copy(combined, ciphertext)
	copy(combined[len(ciphertext):], tag)

	plaintext, err := gcm.Open(nil, nonce, combined, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: authentication tag mismatch")
	}

	return plaintext, nil
}
