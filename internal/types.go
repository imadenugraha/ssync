package internal

import "time"

// SSHArtifact represents a discovered SSH file from the user's SSH directory.
type SSHArtifact struct {
	Name         string
	RelativePath string
	AbsolutePath string
	Size         int64
	ModifiedAt   time.Time
}

// R2Credentials holds the configuration needed to connect to Cloudflare R2.
type R2Credentials struct {
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
	EndpointURL     string `json:"endpoint_url"`
	BucketName      string `json:"bucket_name"`
}

// ManifestArtifact records metadata for a single uploaded SSH artifact.
type ManifestArtifact struct {
	Name            string    `json:"name"`
	RelativePath    string    `json:"relative_path"`
	R2Key           string    `json:"r2_key"`
	SizeBytes       int64     `json:"size_bytes"`
	LocalModifiedAt time.Time `json:"local_modified_at"`
	UploadedAt      time.Time `json:"uploaded_at"`
	SHA256          string    `json:"sha256"`
}

// Manifest is the metadata file stored in R2 tracking all uploaded artifacts.
type Manifest struct {
	Version   int                `json:"version"`
	UpdatedAt time.Time          `json:"updated_at"`
	Artifacts []ManifestArtifact `json:"artifacts"`
}

// EncryptedBlob is the binary representation of an encrypted SSH artifact.
// Format: magic(4) + version(1) + salt(32) + nonce(12) + tag(16) + ciphertext(variable)
type EncryptedBlob struct {
	Magic      [4]byte
	Version    byte
	Salt       [32]byte
	Nonce      [12]byte
	Tag        [16]byte
	Ciphertext []byte
}

// BackupCodeRecord stores the hashed representation of a single backup code.
type BackupCodeRecord struct {
	ID   string `json:"id"`
	Hash string `json:"hash"`
	Used bool   `json:"used"`
}

// BackupCode holds a plaintext backup code string.
type BackupCode struct {
	Code string
}
