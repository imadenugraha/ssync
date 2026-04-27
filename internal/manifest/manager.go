package manifest

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/user/ssync/internal"
	"github.com/user/ssync/internal/r2"
)

const manifestKey = "manifest.json"

// ManifestManager defines the interface for fetching and updating the remote manifest.
type ManifestManager interface {
	Fetch() (internal.Manifest, error)
	Update(manifest internal.Manifest) error
}

type manifestManager struct {
	client r2.R2Client
}

// NewManifestManager constructs a ManifestManager backed by the given R2Client.
func NewManifestManager(client r2.R2Client) ManifestManager {
	return &manifestManager{client: client}
}

// Fetch downloads manifest.json from R2 and unmarshals it.
// If the object does not exist, an empty Manifest is returned.
func (m *manifestManager) Fetch() (internal.Manifest, error) {
	data, err := m.client.Download(manifestKey)
	if err != nil {
		if errors.Is(err, r2.ErrNotFound) {
			return internal.Manifest{}, nil
		}
		return internal.Manifest{}, fmt.Errorf("fetch manifest: %w", err)
	}

	var manifest internal.Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return internal.Manifest{}, fmt.Errorf("parse manifest: %w", err)
	}
	return manifest, nil
}

// Update marshals the manifest to JSON and uploads it to R2 as manifest.json.
func (m *manifestManager) Update(manifest internal.Manifest) error {
	data, err := json.Marshal(manifest)
	if err != nil {
		return fmt.Errorf("marshal manifest: %w", err)
	}
	if err := m.client.Upload(manifestKey, data); err != nil {
		return fmt.Errorf("upload manifest: %w", err)
	}
	return nil
}
