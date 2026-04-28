package cmd

import (
	"bufio"
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/user/ssync/internal"
	"github.com/user/ssync/internal/backup"
	"github.com/user/ssync/internal/crypto"
	"github.com/user/ssync/internal/manifest"
	"github.com/user/ssync/internal/r2"
	"github.com/user/ssync/internal/scanner"
)

// ---------------------------------------------------------------------------
// Mock S3 server (mirrors internal/r2/client_test.go)
// ---------------------------------------------------------------------------

type integMockS3Store struct {
	mu       sync.Mutex
	objects  map[string][]byte
	failKeys map[string]bool
}

func newIntegMockS3Store() *integMockS3Store {
	return &integMockS3Store{
		objects:  make(map[string][]byte),
		failKeys: make(map[string]bool),
	}
}

type integListResult struct {
	XMLName     xml.Name          `xml:"ListBucketResult"`
	Name        string            `xml:"Name"`
	IsTruncated bool              `xml:"IsTruncated"`
	Contents    []integS3ObjXML   `xml:"Contents"`
}

type integS3ObjXML struct {
	Key  string `xml:"Key"`
	Size int64  `xml:"Size"`
}

func newIntegMockS3Server(store *integMockS3Store) *httptest.Server {
	const bucket = "test-bucket"

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		path := strings.TrimPrefix(req.URL.Path, "/")
		parts := strings.SplitN(path, "/", 2)
		if len(parts) < 1 || parts[0] != bucket {
			http.Error(w, "bucket not found", http.StatusNotFound)
			return
		}

		// List objects: GET /{bucket}?list-type=2
		if req.Method == http.MethodGet && len(parts) == 1 {
			if req.URL.Query().Get("list-type") == "2" {
				store.mu.Lock()
				defer store.mu.Unlock()
				result := integListResult{Name: bucket}
				for k, v := range store.objects {
					result.Contents = append(result.Contents, integS3ObjXML{Key: k, Size: int64(len(v))})
				}
				w.Header().Set("Content-Type", "application/xml")
				w.WriteHeader(http.StatusOK)
				xml.NewEncoder(w).Encode(result)
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

		if store.failKeys[key] {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		switch req.Method {
		case http.MethodPut:
			data, err := io.ReadAll(req.Body)
			if err != nil {
				http.Error(w, "read error", http.StatusInternalServerError)
				return
			}
			store.objects[key] = data
			w.WriteHeader(http.StatusOK)

		case http.MethodGet:
			data, ok := store.objects[key]
			if !ok {
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

func newIntegR2Client(t *testing.T, serverURL string) r2.R2Client {
	t.Helper()
	creds := internal.R2Credentials{
		AccessKeyID:     "test-access-key",
		SecretAccessKey: "test-secret-key",
		EndpointURL:     serverURL,
		BucketName:      "test-bucket",
	}
	client, err := r2.NewR2Client(creds)
	if err != nil {
		t.Fatalf("NewR2Client: %v", err)
	}
	return client
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// createTestSSHDir creates a temp directory with a few SSH-like artifacts and
// returns the directory path along with a map of filename→content.
func createTestSSHDir(t *testing.T) (string, map[string][]byte) {
	t.Helper()
	dir := t.TempDir()

	artifacts := map[string][]byte{
		"id_ed25519":     []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nfakekey\n-----END OPENSSH PRIVATE KEY-----\n"),
		"id_ed25519.pub": []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI fakekey user@host\n"),
		"config":         []byte("Host example\n  HostName example.com\n  User git\n"),
	}

	for name, content := range artifacts {
		path := filepath.Join(dir, name)
		perm := os.FileMode(0644)
		if name == "id_ed25519" {
			perm = 0600
		}
		if err := os.WriteFile(path, content, perm); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	return dir, artifacts
}

// runPush wires up a pushRunner against the given R2 client and SSH dir,
// feeds the provided input, and returns the output and error.
func runPush(t *testing.T, r2Client r2.R2Client, sshDir, password string, inputLines ...string) (string, error) {
	t.Helper()

	engine := crypto.NewAESEngine()
	manifestMgr := manifest.NewManifestManager(r2Client)
	backupMgr := backup.NewManager(r2Client)

	// Build input: "Y\n<password>\n" (push all, then password)
	input := strings.Join(inputLines, "\n") + "\n"
	in := strings.NewReader(input)
	inSc := bufio.NewScanner(in)

	var outBuf bytes.Buffer
	runner := &pushRunner{
		in:       in,
		out:      &outBuf,
		r2:       r2Client,
		engine:   engine,
		manifest: manifestMgr,
		backup:   backupMgr,
		scanner:  scanner.New(),
		sshDir:   sshDir,
		pwReader: readerPasswordReader(inSc),
		sc:       inSc,
	}

	err := runner.run()
	return outBuf.String(), err
}

// runPull wires up a pullRunner against the given R2 client and SSH dir,
// feeds the provided input, and returns the output and error.
func runPull(t *testing.T, r2Client r2.R2Client, sshDir, password string) (string, error) {
	t.Helper()

	engine := crypto.NewAESEngine()
	manifestMgr := manifest.NewManifestManager(r2Client)

	in := strings.NewReader(password + "\n")
	inSc := bufio.NewScanner(in)
	var outBuf bytes.Buffer
	runner := &pullRunner{
		in:       in,
		out:      &outBuf,
		r2:       r2Client,
		engine:   engine,
		manifest: manifestMgr,
		sshDir:   sshDir,
		pwReader: readerPasswordReader(inSc),
		sc:       inSc,
	}

	err := runner.run()
	return outBuf.String(), err
}

// ---------------------------------------------------------------------------
// Integration Tests
// ---------------------------------------------------------------------------

// TestIntegration_FullPushPullCycle verifies that a full push→pull round-trip
// preserves all artifact content exactly.
//
// Requirements: 3.1, 3.2, 3.3, 9.1
func TestIntegration_FullPushPullCycle(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// 1. Create source SSH dir with test artifacts.
	srcDir, origContents := createTestSSHDir(t)

	// 2. Create mock S3 server.
	store := newIntegMockS3Store()
	srv := newIntegMockS3Server(store)
	defer srv.Close()

	r2Client := newIntegR2Client(t, srv.URL)

	// 3. Run push: "Y" (push all), then password.
	const password = "supersecretpassword123"
	pushOut, pushErr := runPush(t, r2Client, srcDir, password, "Y", password)
	if pushErr != nil {
		t.Fatalf("push failed: %v\noutput: %s", pushErr, pushOut)
	}

	// Verify push output contains success markers.
	if !strings.Contains(pushOut, "✓") {
		t.Errorf("push output missing success markers:\n%s", pushOut)
	}

	// 4. Create a new temp SSH dir (simulating a new machine).
	destDir := t.TempDir()

	// 5. Run pull: download and decrypt all artifacts.
	pullOut, pullErr := runPull(t, r2Client, destDir, password)
	if pullErr != nil {
		t.Fatalf("pull failed: %v\noutput: %s", pullErr, pullOut)
	}

	// 6. Assert all artifact contents match the originals.
	for name, want := range origContents {
		gotPath := filepath.Join(destDir, name)
		got, err := os.ReadFile(gotPath)
		if err != nil {
			t.Errorf("artifact %q not found in dest dir: %v", name, err)
			continue
		}
		if !bytes.Equal(got, want) {
			t.Errorf("artifact %q content mismatch:\n  got:  %q\n  want: %q", name, got, want)
		}
	}
}

// TestIntegration_PartialUploadFailureReportsCorrectly verifies that when one
// artifact's upload fails, the error is reported and exit code 2 is returned.
//
// Requirements: 3.6
func TestIntegration_PartialUploadFailureReportsCorrectly(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	srcDir, _ := createTestSSHDir(t)

	store := newIntegMockS3Store()
	// Make the private key upload fail.
	store.failKeys["artifacts/id_ed25519.enc"] = true

	srv := newIntegMockS3Server(store)
	defer srv.Close()

	r2Client := newIntegR2Client(t, srv.URL)

	const password = "supersecretpassword123"
	pushOut, pushErr := runPush(t, r2Client, srcDir, password, "Y", password)

	// Push should return an exitError with code 2.
	if pushErr == nil {
		t.Fatalf("expected push to fail due to partial upload, but got nil error\noutput: %s", pushOut)
	}

	ee, ok := pushErr.(*exitError)
	if !ok {
		t.Fatalf("expected *exitError, got %T: %v", pushErr, pushErr)
	}
	if ee.code != 2 {
		t.Errorf("expected exit code 2, got %d", ee.code)
	}

	// Output should mention the failure.
	if !strings.Contains(pushOut, "✗") {
		t.Errorf("push output missing failure marker:\n%s", pushOut)
	}
}

// TestIntegration_ConflictDetectionWorksEndToEnd verifies that when a remote
// artifact has a newer timestamp than the local file, the conflict warning
// appears and the artifact is skipped (unless forced).
//
// Requirements: 3.2, 3.3
func TestIntegration_ConflictDetectionWorksEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	srcDir, _ := createTestSSHDir(t)

	store := newIntegMockS3Store()
	srv := newIntegMockS3Server(store)
	defer srv.Close()

	r2Client := newIntegR2Client(t, srv.URL)

	const password = "supersecretpassword123"

	// First push: upload all artifacts.
	pushOut, pushErr := runPush(t, r2Client, srcDir, password, "Y", password)
	if pushErr != nil {
		t.Fatalf("first push failed: %v\noutput: %s", pushErr, pushOut)
	}

	// Simulate remote being newer: update the manifest's UploadedAt to the future.
	manifestMgr := manifest.NewManifestManager(r2Client)
	mf, err := manifestMgr.Fetch()
	if err != nil {
		t.Fatalf("fetch manifest: %v", err)
	}
	for i := range mf.Artifacts {
		mf.Artifacts[i].UploadedAt = time.Now().Add(24 * time.Hour)
	}
	if err := manifestMgr.Update(mf); err != nil {
		t.Fatalf("update manifest: %v", err)
	}

	// Second push: user answers "n" (don't overwrite) for each conflict prompt.
	// We need one "n" per artifact that has a conflict.
	numArtifacts := len(mf.Artifacts)
	inputLines := []string{"Y", password}
	for i := 0; i < numArtifacts; i++ {
		inputLines = append(inputLines, "n")
	}

	engine := crypto.NewAESEngine()
	backupMgr := backup.NewManager(r2Client)

	conflictIn := strings.NewReader(strings.Join(inputLines, "\n") + "\n")
	conflictInSc := bufio.NewScanner(conflictIn)
	var outBuf bytes.Buffer
	runner := &pushRunner{
		in:       conflictIn,
		out:      &outBuf,
		r2:       r2Client,
		engine:   engine,
		manifest: manifestMgr,
		backup:   backupMgr,
		scanner:  scanner.New(),
		sshDir:   srcDir,
		force:    false,
		pwReader: readerPasswordReader(conflictInSc),
		sc:       conflictInSc,
	}

	runErr := runner.run()
	output := outBuf.String()

	// The push should succeed (no hard error) but artifacts should be skipped.
	if runErr != nil {
		// A partial skip is reported as exit code 2 only if there are real failures.
		// Skipped artifacts are not hard failures, so this may or may not error.
		// Accept either outcome as long as the output mentions the conflict.
		t.Logf("push returned error (may be expected for skipped artifacts): %v", runErr)
	}

	// Output should mention "Remote is newer" or "Skipping" for at least one artifact.
	if !strings.Contains(output, "Remote is newer") && !strings.Contains(output, "Skipping") {
		t.Errorf("expected conflict warning in output, got:\n%s", output)
	}
}

// TestIntegration_PullWithWrongPasswordFails verifies that pulling with the
// wrong password returns exit code 1 (user error).
//
// Requirements: 3.5
func TestIntegration_PullWithWrongPasswordFails(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	srcDir, _ := createTestSSHDir(t)

	store := newIntegMockS3Store()
	srv := newIntegMockS3Server(store)
	defer srv.Close()

	r2Client := newIntegR2Client(t, srv.URL)

	const password = "supersecretpassword123"
	pushOut, pushErr := runPush(t, r2Client, srcDir, password, "Y", password)
	if pushErr != nil {
		t.Fatalf("push failed: %v\noutput: %s", pushErr, pushOut)
	}

	destDir := t.TempDir()

	// Pull with wrong password, then quit.
	engine := crypto.NewAESEngine()
	manifestMgr := manifest.NewManifestManager(r2Client)

	wrongIn := strings.NewReader("wrongpassword123\nq\n")
	wrongInSc := bufio.NewScanner(wrongIn)
	var outBuf bytes.Buffer
	runner := &pullRunner{
		in:       wrongIn,
		out:      &outBuf,
		r2:       r2Client,
		engine:   engine,
		manifest: manifestMgr,
		sshDir:   destDir,
		pwReader: readerPasswordReader(wrongInSc),
		sc:       wrongInSc,
	}

	pullErr := runner.run()
	output := outBuf.String()

	if pullErr == nil {
		t.Fatalf("expected pull to fail with wrong password, but got nil\noutput: %s", output)
	}

	ee, ok := pullErr.(*exitError)
	if !ok {
		t.Fatalf("expected *exitError, got %T: %v", pullErr, pullErr)
	}
	if ee.code != 1 {
		t.Errorf("expected exit code 1 for wrong password, got %d", ee.code)
	}

	// Output should mention wrong password.
	if !strings.Contains(output, "wrong password") {
		t.Errorf("expected 'wrong password' in output, got:\n%s", output)
	}
}
