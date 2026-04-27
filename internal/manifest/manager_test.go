package manifest

// Feature: ssh-config-sync, Property 14: Manifest serialization round-trip

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
	"github.com/user/ssync/internal"
)

// genHexString generates a random hex-like string of fixed length (simulating SHA256).
func genSHA256() gopter.Gen {
	const hexChars = "0123456789abcdef"
	return gen.SliceOfN(64, gen.RuneRange('0', 'f')).Map(func(runes []rune) string {
		return string(runes)
	})
}

// genTimestamp generates a random time.Time with second precision (to survive JSON round-trip).
func genTimestamp() gopter.Gen {
	return gen.Int64Range(0, 1_000_000_000).Map(func(secs int64) time.Time {
		return time.Unix(secs, 0).UTC()
	})
}

// genManifestArtifact generates a random ManifestArtifact.
func genManifestArtifact() gopter.Gen {
	return gopter.CombineGens(
		gen.AlphaString(),
		gen.AlphaString(),
		gen.AlphaString(),
		gen.Int64Range(0, 1<<40),
		genTimestamp(),
		genTimestamp(),
		genSHA256(),
	).Map(func(vals []interface{}) internal.ManifestArtifact {
		return internal.ManifestArtifact{
			Name:            vals[0].(string),
			RelativePath:    vals[1].(string),
			R2Key:           vals[2].(string),
			SizeBytes:       vals[3].(int64),
			LocalModifiedAt: vals[4].(time.Time),
			UploadedAt:      vals[5].(time.Time),
			SHA256:          vals[6].(string),
		}
	})
}

// genManifest generates a random Manifest with 0–5 artifacts.
func genManifest() gopter.Gen {
	return gopter.CombineGens(
		gen.IntRange(1, 3),
		genTimestamp(),
		gen.SliceOfN(5, genManifestArtifact()),
	).Map(func(vals []interface{}) internal.Manifest {
		version := vals[0].(int)
		updatedAt := vals[1].(time.Time)
		artifacts := vals[2].([]internal.ManifestArtifact)
		return internal.Manifest{
			Version:   version,
			UpdatedAt: updatedAt,
			Artifacts: artifacts,
		}
	})
}

// TestProperty14_ManifestSerializationRoundTrip verifies that marshaling a Manifest
// to JSON and unmarshaling it back produces an identical struct.
//
// Validates: Requirements 3.4
func TestProperty14_ManifestSerializationRoundTrip(t *testing.T) {
	params := gopter.DefaultTestParameters()
	params.MinSuccessfulTests = 20
	properties := gopter.NewProperties(params)

	properties.Property("marshal→unmarshal produces identical manifest", prop.ForAll(
		func(original internal.Manifest) bool {
			data, err := json.Marshal(original)
			if err != nil {
				return false
			}

			var restored internal.Manifest
			if err := json.Unmarshal(data, &restored); err != nil {
				return false
			}

			// Check top-level fields.
			if original.Version != restored.Version {
				return false
			}
			if !original.UpdatedAt.Equal(restored.UpdatedAt) {
				return false
			}
			if len(original.Artifacts) != len(restored.Artifacts) {
				return false
			}

			// Check each artifact entry.
			for i, orig := range original.Artifacts {
				rest := restored.Artifacts[i]
				if orig.Name != rest.Name {
					return false
				}
				if orig.RelativePath != rest.RelativePath {
					return false
				}
				if orig.R2Key != rest.R2Key {
					return false
				}
				if orig.SizeBytes != rest.SizeBytes {
					return false
				}
				if !orig.LocalModifiedAt.Equal(rest.LocalModifiedAt) {
					return false
				}
				if !orig.UploadedAt.Equal(rest.UploadedAt) {
					return false
				}
				if orig.SHA256 != rest.SHA256 {
					return false
				}
			}
			return true
		},
		genManifest(),
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}
