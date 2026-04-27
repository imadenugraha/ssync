package conflict

// Feature: ssh-config-sync, Property 12: Conflict detection correctly identifies newer artifact

import (
	"testing"
	"time"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
)

// genTimestamp generates a random time.Time within a reasonable range.
func genTimestamp() gopter.Gen {
	// Generate a Unix timestamp in seconds within a 10-year window.
	return gen.Int64Range(0, 10*365*24*3600).Map(func(secs int64) time.Time {
		return time.Unix(secs, 0).UTC()
	})
}

// TestProperty12_ConflictDetection validates Property 12:
// Conflict detection correctly identifies newer artifact.
//
// Validates: Requirements 8.1, 8.2, 8.3
func TestProperty12_ConflictDetection(t *testing.T) {
	params := gopter.DefaultTestParameters()
	params.MinSuccessfulTests = 20
	properties := gopter.NewProperties(params)

	// Case 1: RemoteNewer — remote is strictly after local.
	properties.Property("RemoteNewer when remote timestamp is strictly after local", prop.ForAll(
		func(localSecs, deltaSecs int64) bool {
			local := time.Unix(localSecs, 0).UTC()
			// delta is always > 0, so remote is strictly after local
			remote := local.Add(time.Duration(deltaSecs+1) * time.Second)
			result := Detect(local, remote)
			return result == RemoteNewer
		},
		gen.Int64Range(0, 10*365*24*3600),
		gen.Int64Range(0, 365*24*3600), // positive delta
	))

	// Case 2: LocalNewer — local is strictly after remote.
	properties.Property("LocalNewer when local timestamp is strictly after remote", prop.ForAll(
		func(remoteSecs, deltaSecs int64) bool {
			remote := time.Unix(remoteSecs, 0).UTC()
			// delta is always > 0, so local is strictly after remote
			local := remote.Add(time.Duration(deltaSecs+1) * time.Second)
			result := Detect(local, remote)
			return result == LocalNewer
		},
		gen.Int64Range(0, 10*365*24*3600),
		gen.Int64Range(0, 365*24*3600), // positive delta
	))

	// Case 3: Equal — both timestamps are identical.
	properties.Property("Equal when timestamps are identical", prop.ForAll(
		func(secs int64) bool {
			ts := time.Unix(secs, 0).UTC()
			result := Detect(ts, ts)
			return result == Equal
		},
		gen.Int64Range(0, 10*365*24*3600),
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}
