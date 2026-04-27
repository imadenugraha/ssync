package backup

// Feature: ssh-config-sync, Property 8: Backup codes are stored as hashes, not plaintext
// Feature: ssh-config-sync, Property 9: Backup code lifecycle — valid before use, invalid after
// Feature: ssh-config-sync, Property 10: Regeneration invalidates all previous backup codes

import (
	"bytes"
	"errors"
	"sync"
	"testing"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
	"github.com/user/ssync/internal/r2"
)

// memR2 is an in-memory mock R2 client for testing.
type memR2 struct {
	mu      sync.Mutex
	objects map[string][]byte
}

func newMemR2() *memR2 {
	return &memR2{objects: make(map[string][]byte)}
}

func (m *memR2) Upload(key string, data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]byte, len(data))
	copy(cp, data)
	m.objects[key] = cp
	return nil
}

func (m *memR2) Download(key string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	data, ok := m.objects[key]
	if !ok {
		return nil, r2.ErrNotFound
	}
	cp := make([]byte, len(data))
	copy(cp, data)
	return cp, nil
}

func (m *memR2) List() ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	keys := make([]string, 0, len(m.objects))
	for k := range m.objects {
		keys = append(keys, k)
	}
	return keys, nil
}

func (m *memR2) Delete(key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.objects[key]; !ok {
		return r2.ErrNotFound
	}
	delete(m.objects, key)
	return nil
}

// rawBytes returns the raw bytes stored under the given key (no copy needed for assertions).
func (m *memR2) rawBytes(key string) []byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.objects[key]
}

// TestProperty8_BackupCodesStoredAsHashes validates Property 8:
// Backup codes are stored as hashes, not plaintext.
//
// Validates: Requirements 5.3
func TestProperty8_BackupCodesStoredAsHashes(t *testing.T) {
	params := gopter.DefaultTestParameters()
	params.MinSuccessfulTests = 5
	properties := gopter.NewProperties(params)

	properties.Property("raw backup-codes.json contains no plaintext code strings", prop.ForAll(
		func(_ int) bool {
			store := newMemR2()
			mgr := NewManager(store)

			codes, err := mgr.Generate()
			if err != nil {
				return false
			}
			if err := mgr.StoreHashes(codes); err != nil {
				return false
			}

			raw := store.rawBytes(backupCodesKey)
			if len(raw) == 0 {
				return false
			}

			// None of the plaintext code strings should appear in the raw JSON.
			for _, c := range codes {
				if bytes.Contains(raw, []byte(c.Code)) {
					return false
				}
			}
			return true
		},
		gen.IntRange(0, 0), // single dummy parameter to drive iterations
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// TestProperty9_BackupCodeLifecycle validates Property 9:
// Backup code lifecycle — valid before use, invalid after.
//
// Validates: Requirements 6.1, 6.4
func TestProperty9_BackupCodeLifecycle(t *testing.T) {
	params := gopter.DefaultTestParameters()
	params.MinSuccessfulTests = 3
	properties := gopter.NewProperties(params)

	properties.Property("codes are valid before use and invalid after Invalidate", prop.ForAll(
		func(pickIdx int) bool {
			store := newMemR2()
			mgr := NewManager(store)

			codes, err := mgr.Generate()
			if err != nil {
				return false
			}
			if err := mgr.StoreHashes(codes); err != nil {
				return false
			}

			// All codes must be valid before any use.
			for _, c := range codes {
				ok, err := mgr.Verify(c.Code)
				if err != nil || !ok {
					return false
				}
			}

			// Pick a random code to invalidate.
			idx := pickIdx % len(codes)
			chosen := codes[idx].Code

			if err := mgr.Invalidate(chosen); err != nil {
				return false
			}

			// Chosen code must now be invalid.
			ok, err := mgr.Verify(chosen)
			if err != nil || ok {
				return false
			}

			// All other codes must still be valid.
			for i, c := range codes {
				if i == idx {
					continue
				}
				ok, err := mgr.Verify(c.Code)
				if err != nil || !ok {
					return false
				}
			}
			return true
		},
		gen.IntRange(0, 7),
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// TestProperty10_RegenerationInvalidatesPreviousCodes validates Property 10:
// Regeneration invalidates all previous backup codes.
//
// Validates: Requirements 5.4
func TestProperty10_RegenerationInvalidatesPreviousCodes(t *testing.T) {
	params := gopter.DefaultTestParameters()
	params.MinSuccessfulTests = 3
	properties := gopter.NewProperties(params)

	properties.Property("all original codes fail Verify after new codes are stored", prop.ForAll(
		func(_ int) bool {
			store := newMemR2()
			mgr := NewManager(store)

			// Generate and store the initial set.
			original, err := mgr.Generate()
			if err != nil {
				return false
			}
			if err := mgr.StoreHashes(original); err != nil {
				return false
			}

			// Generate and store a new set (overwrites backup-codes.json).
			newCodes, err := mgr.Generate()
			if err != nil {
				return false
			}
			if err := mgr.StoreHashes(newCodes); err != nil {
				return false
			}

			// Every original code must now fail Verify.
			for _, c := range original {
				ok, err := mgr.Verify(c.Code)
				if err != nil && !errors.Is(err, r2.ErrNotFound) {
					return false
				}
				if ok {
					return false
				}
			}
			return true
		},
		gen.IntRange(0, 0),
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}
