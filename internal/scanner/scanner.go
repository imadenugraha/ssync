package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/user/ssync/internal"
)

// ArtifactScanner discovers SSH artifacts in a directory.
type ArtifactScanner interface {
	Scan(dir string) ([]internal.SSHArtifact, error)
}

// FileScanner implements ArtifactScanner using the local filesystem.
type FileScanner struct{}

// New returns a new FileScanner.
func New() ArtifactScanner {
	return &FileScanner{}
}

// Scan discovers SSH artifacts in dir. Returns an error if the directory does
// not exist or contains no recognized SSH files.
func (s *FileScanner) Scan(dir string) ([]internal.SSHArtifact, error) {
	info, err := os.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("ssh directory does not exist: %s", dir)
		}
		return nil, fmt.Errorf("cannot access ssh directory %s: %w", dir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("path is not a directory: %s", dir)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("cannot read ssh directory %s: %w", dir, err)
	}

	var artifacts []internal.SSHArtifact
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		absPath := filepath.Join(dir, name)

		fi, err := entry.Info()
		if err != nil {
			continue
		}

		if !isRecognized(name, fi) {
			continue
		}

		artifacts = append(artifacts, internal.SSHArtifact{
			Name:         name,
			RelativePath: name,
			AbsolutePath: absPath,
			Size:         fi.Size(),
			ModifiedAt:   fi.ModTime(),
		})
	}

	if len(artifacts) == 0 {
		return nil, fmt.Errorf("no SSH artifacts found in directory: %s", dir)
	}

	return artifacts, nil
}

// isRecognized returns true if the file should be treated as an SSH artifact.
func isRecognized(name string, fi os.FileInfo) bool {
	// Public keys
	if strings.HasSuffix(name, ".pub") {
		return true
	}

	// Config and known_hosts (exact names)
	if name == "config" || name == "known_hosts" {
		return true
	}

	// Private keys: no extension or .pem, mode 0600
	ext := filepath.Ext(name)
	if ext == "" || ext == ".pem" {
		mode := fi.Mode().Perm()
		if mode == 0600 {
			return true
		}
	}

	return false
}
