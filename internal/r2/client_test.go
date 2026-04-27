package r2

import (
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/user/ssync/internal"
)

// mockS3Store is an in-memory store used by the mock S3 server.
type mockS3Store struct {
	mu      sync.Mutex
	objects map[string][]byte
	// failKeys causes GET/PUT for these keys to return 500.
	failKeys map[string]bool
}

func newMockS3Store() *mockS3Store {
	return &mockS3Store{
		objects:  make(map[string][]byte),
		failKeys: make(map[string]bool),
	}
}

// newMockS3Server creates an httptest.Server that mimics S3 path-style API.
// Bucket name is fixed to "test-bucket".
func newMockS3Server(store *mockS3Store) *httptest.Server {
	const bucket = "test-bucket"

	mux := http.NewServeMux()

	// Handle all requests under /{bucket}/
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Strip leading slash and bucket prefix.
		path := strings.TrimPrefix(r.URL.Path, "/")
		parts := strings.SplitN(path, "/", 2)
		if len(parts) < 1 || parts[0] != bucket {
			http.Error(w, "bucket not found", http.StatusNotFound)
			return
		}

		// List objects: GET /{bucket}?list-type=2
		if r.Method == http.MethodGet && len(parts) == 1 {
			if r.URL.Query().Get("list-type") == "2" {
				store.mu.Lock()
				defer store.mu.Unlock()
				handleList(w, store)
				return
			}
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		if len(parts) < 2 || parts[1] == "" {
			http.Error(w, "missing key", http.StatusBadRequest)
			return
		}
		key := parts[1]

		store.mu.Lock()
		defer store.mu.Unlock()

		// Simulate failure for specific keys.
		if store.failKeys[key] {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		switch r.Method {
		case http.MethodPut:
			data, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "read error", http.StatusInternalServerError)
				return
			}
			store.objects[key] = data
			w.WriteHeader(http.StatusOK)

		case http.MethodGet:
			data, ok := store.objects[key]
			if !ok {
				// Return S3-style NoSuchKey XML error.
				w.Header().Set("Content-Type", "application/xml")
				w.WriteHeader(http.StatusNotFound)
				fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?><Error><Code>NoSuchKey</Code><Message>The specified key does not exist.</Message></Error>`)
				return
			}
			w.WriteHeader(http.StatusOK)
			w.Write(data)

		case http.MethodDelete:
			delete(store.objects, key)
			w.WriteHeader(http.StatusNoContent)

		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	return httptest.NewServer(mux)
}

// listObjectsV2Result is the XML response for ListObjectsV2.
type listObjectsV2Result struct {
	XMLName     xml.Name      `xml:"ListBucketResult"`
	Name        string        `xml:"Name"`
	IsTruncated bool          `xml:"IsTruncated"`
	Contents    []s3ObjectXML `xml:"Contents"`
}

type s3ObjectXML struct {
	Key  string `xml:"Key"`
	Size int64  `xml:"Size"`
}

func handleList(w http.ResponseWriter, store *mockS3Store) {
	result := listObjectsV2Result{
		Name:        "test-bucket",
		IsTruncated: false,
	}
	for key, data := range store.objects {
		result.Contents = append(result.Contents, s3ObjectXML{
			Key:  key,
			Size: int64(len(data)),
		})
	}
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	xml.NewEncoder(w).Encode(result)
}

// newTestClient creates an R2Client pointed at the given httptest server URL.
func newTestClient(t *testing.T, serverURL string) R2Client {
	t.Helper()
	creds := internal.R2Credentials{
		AccessKeyID:     "test-access-key",
		SecretAccessKey: "test-secret-key",
		EndpointURL:     serverURL,
		BucketName:      "test-bucket",
	}
	client, err := NewR2Client(creds)
	if err != nil {
		t.Fatalf("NewR2Client: %v", err)
	}
	return client
}

// TestUploadSuccess verifies that Upload stores data in the mock S3 backend.
func TestUploadSuccess(t *testing.T) {
	store := newMockS3Store()
	srv := newMockS3Server(store)
	defer srv.Close()

	client := newTestClient(t, srv.URL)

	data := []byte("hello, world")
	if err := client.Upload("mykey", data); err != nil {
		t.Fatalf("Upload failed: %v", err)
	}

	store.mu.Lock()
	got, ok := store.objects["mykey"]
	store.mu.Unlock()

	if !ok {
		t.Fatal("expected object to be stored, but it was not found")
	}
	if string(got) != string(data) {
		t.Fatalf("stored data mismatch: got %q, want %q", got, data)
	}
}

// TestDownloadSuccess verifies that Download retrieves previously uploaded data.
func TestDownloadSuccess(t *testing.T) {
	store := newMockS3Store()
	srv := newMockS3Server(store)
	defer srv.Close()

	client := newTestClient(t, srv.URL)

	want := []byte("ssh-rsa AAAA...")
	if err := client.Upload("id_rsa.pub", want); err != nil {
		t.Fatalf("Upload failed: %v", err)
	}

	got, err := client.Download("id_rsa.pub")
	if err != nil {
		t.Fatalf("Download failed: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("downloaded data mismatch: got %q, want %q", got, want)
	}
}

// TestDownloadNotFound verifies that downloading a missing key returns ErrNotFound.
func TestDownloadNotFound(t *testing.T) {
	store := newMockS3Store()
	srv := newMockS3Server(store)
	defer srv.Close()

	client := newTestClient(t, srv.URL)

	_, err := client.Download("nonexistent-key")
	if err == nil {
		t.Fatal("expected error for missing key, got nil")
	}
	if err != ErrNotFound {
		t.Fatalf("expected ErrNotFound, got: %v", err)
	}
}

// TestListObjects verifies that List returns all uploaded keys.
func TestListObjects(t *testing.T) {
	store := newMockS3Store()
	srv := newMockS3Server(store)
	defer srv.Close()

	client := newTestClient(t, srv.URL)

	keys := []string{"key1", "key2", "key3"}
	for _, k := range keys {
		if err := client.Upload(k, []byte("data-"+k)); err != nil {
			t.Fatalf("Upload(%q) failed: %v", k, err)
		}
	}

	listed, err := client.List()
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	if len(listed) != len(keys) {
		t.Fatalf("expected %d keys, got %d: %v", len(keys), len(listed), listed)
	}

	listedSet := make(map[string]bool, len(listed))
	for _, k := range listed {
		listedSet[k] = true
	}
	for _, k := range keys {
		if !listedSet[k] {
			t.Errorf("expected key %q in list, but not found", k)
		}
	}
}

// TestListEmpty verifies that List returns an empty slice when the bucket is empty.
func TestListEmpty(t *testing.T) {
	store := newMockS3Store()
	srv := newMockS3Server(store)
	defer srv.Close()

	client := newTestClient(t, srv.URL)

	listed, err := client.List()
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(listed) != 0 {
		t.Fatalf("expected empty list, got: %v", listed)
	}
}

// TestConnectionFailureReturnsExitCode2Error verifies that a connection failure
// (server closed / unreachable) returns a *ConnectionError (exit code 2).
func TestConnectionFailureReturnsExitCode2Error(t *testing.T) {
	// Start a server and immediately close it to simulate a connection failure.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close() // close before any request is made

	client := newTestClient(t, url)

	err := client.Upload("somekey", []byte("data"))
	if err == nil {
		t.Fatal("expected connection error, got nil")
	}

	var connErr *ConnectionError
	ok := isConnectionError(err, &connErr)
	if !ok {
		t.Fatalf("expected *ConnectionError, got %T: %v", err, err)
	}
}

// isConnectionError checks whether err is (or wraps) a *ConnectionError.
func isConnectionError(err error, target **ConnectionError) bool {
	if err == nil {
		return false
	}
	if ce, ok := err.(*ConnectionError); ok {
		if target != nil {
			*target = ce
		}
		return true
	}
	// Unwrap one level.
	type unwrapper interface{ Unwrap() error }
	if u, ok := err.(unwrapper); ok {
		return isConnectionError(u.Unwrap(), target)
	}
	return false
}

// TestPartialFailureReportsPerArtifactResults verifies that when some uploads
// succeed and others fail, the caller can distinguish per-artifact outcomes.
// This test exercises the R2Client directly: successful uploads return nil,
// failed uploads return a *ConnectionError (server returns 500 for those keys).
func TestPartialFailureReportsPerArtifactResults(t *testing.T) {
	store := newMockS3Store()
	// Mark "bad-key" to always return 500.
	store.failKeys["bad-key"] = true

	srv := newMockS3Server(store)
	defer srv.Close()

	client := newTestClient(t, srv.URL)

	artifacts := []struct {
		key  string
		data []byte
	}{
		{"good-key-1", []byte("artifact 1")},
		{"bad-key", []byte("artifact 2")},
		{"good-key-2", []byte("artifact 3")},
	}

	results := make(map[string]error)
	for _, a := range artifacts {
		results[a.key] = client.Upload(a.key, a.data)
	}

	// good-key-1 and good-key-2 should succeed.
	if results["good-key-1"] != nil {
		t.Errorf("good-key-1: expected nil error, got %v", results["good-key-1"])
	}
	if results["good-key-2"] != nil {
		t.Errorf("good-key-2: expected nil error, got %v", results["good-key-2"])
	}

	// bad-key should fail with a ConnectionError.
	if results["bad-key"] == nil {
		t.Error("bad-key: expected error, got nil")
	} else {
		var connErr *ConnectionError
		if !isConnectionError(results["bad-key"], &connErr) {
			t.Errorf("bad-key: expected *ConnectionError, got %T: %v", results["bad-key"], results["bad-key"])
		}
	}

	// Verify that successful uploads are actually stored.
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, ok := store.objects["good-key-1"]; !ok {
		t.Error("good-key-1 was not stored in the backend")
	}
	if _, ok := store.objects["good-key-2"]; !ok {
		t.Error("good-key-2 was not stored in the backend")
	}
	if _, ok := store.objects["bad-key"]; ok {
		t.Error("bad-key should not have been stored in the backend")
	}
}

// TestDeleteSuccess verifies that Delete removes an object from the backend.
func TestDeleteSuccess(t *testing.T) {
	store := newMockS3Store()
	srv := newMockS3Server(store)
	defer srv.Close()

	client := newTestClient(t, srv.URL)

	if err := client.Upload("to-delete", []byte("bye")); err != nil {
		t.Fatalf("Upload failed: %v", err)
	}

	if err := client.Delete("to-delete"); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	_, err := client.Download("to-delete")
	if err != ErrNotFound {
		t.Fatalf("expected ErrNotFound after delete, got: %v", err)
	}
}
