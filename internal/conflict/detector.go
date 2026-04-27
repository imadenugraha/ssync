package conflict

import "time"

// ConflictResult represents the outcome of comparing local and remote artifact timestamps.
type ConflictResult int

const (
	// Equal indicates both timestamps are identical.
	Equal ConflictResult = iota
	// RemoteNewer indicates the remote artifact was uploaded after the local modification.
	RemoteNewer
	// LocalNewer indicates the local artifact was modified after the remote upload.
	LocalNewer
)

// Detect compares localModifiedAt and remoteUploadedAt and returns the appropriate ConflictResult.
// Returns RemoteNewer when remote is strictly after local, LocalNewer when local is strictly after
// remote, and Equal when the timestamps are identical.
func Detect(localModifiedAt, remoteUploadedAt time.Time) ConflictResult {
	if remoteUploadedAt.After(localModifiedAt) {
		return RemoteNewer
	}
	if localModifiedAt.After(remoteUploadedAt) {
		return LocalNewer
	}
	return Equal
}
