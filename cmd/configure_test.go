package cmd

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/user/ssync/internal"
)

// mockCredStore is a test double for credentials.CredentialStore.
type mockCredStore struct {
	saved   *internal.R2Credentials
	saveErr error
	loadErr error
}

func (m *mockCredStore) Save(creds internal.R2Credentials) error {
	if m.saveErr != nil {
		return m.saveErr
	}
	m.saved = &creds
	return nil
}

func (m *mockCredStore) Load() (internal.R2Credentials, error) {
	if m.loadErr != nil {
		return internal.R2Credentials{}, m.loadErr
	}
	if m.saved != nil {
		return *m.saved, nil
	}
	return internal.R2Credentials{}, nil
}

func newRunner(input string, store *mockCredStore) (*configureRunner, *bytes.Buffer) {
	out := &bytes.Buffer{}
	return &configureRunner{
		in:    strings.NewReader(input),
		out:   out,
		store: store,
	}, out
}

func TestConfigure_ValidInput_SavesCredentials(t *testing.T) {
	input := "AKID123\nSECRET456\nhttps://endpoint.example.com\nmy-bucket\n"
	store := &mockCredStore{}
	runner, out := newRunner(input, store)

	if err := runner.run(); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if store.saved == nil {
		t.Fatal("expected credentials to be saved, but Save was not called")
	}
	if store.saved.AccessKeyID != "AKID123" {
		t.Errorf("AccessKeyID = %q, want %q", store.saved.AccessKeyID, "AKID123")
	}
	if store.saved.SecretAccessKey != "SECRET456" {
		t.Errorf("SecretAccessKey = %q, want %q", store.saved.SecretAccessKey, "SECRET456")
	}
	if store.saved.EndpointURL != "https://endpoint.example.com" {
		t.Errorf("EndpointURL = %q, want %q", store.saved.EndpointURL, "https://endpoint.example.com")
	}
	if store.saved.BucketName != "my-bucket" {
		t.Errorf("BucketName = %q, want %q", store.saved.BucketName, "my-bucket")
	}
	if !strings.Contains(out.String(), "saved successfully") {
		t.Errorf("expected success message in output, got: %q", out.String())
	}
}

func TestConfigure_EmptyAccessKeyID_ReturnsValidationError(t *testing.T) {
	input := "\nSECRET456\nhttps://endpoint.example.com\nmy-bucket\n"
	store := &mockCredStore{}
	runner, _ := newRunner(input, store)

	err := runner.run()
	if err == nil {
		t.Fatal("expected validation error, got nil")
	}
	if !strings.Contains(err.Error(), "access key ID") {
		t.Errorf("expected error about access key ID, got: %v", err)
	}
	var ee *exitError
	if !errors.As(err, &ee) || ee.code != 1 {
		t.Errorf("expected exit code 1, got error: %v", err)
	}
	if store.saved != nil {
		t.Error("expected Save not to be called on validation error")
	}
}

func TestConfigure_EmptySecretAccessKey_ReturnsValidationError(t *testing.T) {
	input := "AKID123\n\nhttps://endpoint.example.com\nmy-bucket\n"
	store := &mockCredStore{}
	runner, _ := newRunner(input, store)

	err := runner.run()
	if err == nil {
		t.Fatal("expected validation error, got nil")
	}
	if !strings.Contains(err.Error(), "secret access key") {
		t.Errorf("expected error about secret access key, got: %v", err)
	}
	var ee *exitError
	if !errors.As(err, &ee) || ee.code != 1 {
		t.Errorf("expected exit code 1, got error: %v", err)
	}
}

func TestConfigure_EmptyEndpointURL_ReturnsValidationError(t *testing.T) {
	input := "AKID123\nSECRET456\n\nmy-bucket\n"
	store := &mockCredStore{}
	runner, _ := newRunner(input, store)

	err := runner.run()
	if err == nil {
		t.Fatal("expected validation error, got nil")
	}
	if !strings.Contains(err.Error(), "endpoint URL") {
		t.Errorf("expected error about endpoint URL, got: %v", err)
	}
}

func TestConfigure_EmptyBucketName_ReturnsValidationError(t *testing.T) {
	input := "AKID123\nSECRET456\nhttps://endpoint.example.com\n\n"
	store := &mockCredStore{}
	runner, _ := newRunner(input, store)

	err := runner.run()
	if err == nil {
		t.Fatal("expected validation error, got nil")
	}
	if !strings.Contains(err.Error(), "bucket name") {
		t.Errorf("expected error about bucket name, got: %v", err)
	}
}

func TestConfigure_StoreError_SurfacesError(t *testing.T) {
	input := "AKID123\nSECRET456\nhttps://endpoint.example.com\nmy-bucket\n"
	storeErr := errors.New("keychain unavailable")
	store := &mockCredStore{saveErr: storeErr}
	runner, _ := newRunner(input, store)

	err := runner.run()
	if err == nil {
		t.Fatal("expected store error to surface, got nil")
	}
	if !strings.Contains(err.Error(), "keychain unavailable") {
		t.Errorf("expected store error message in output, got: %v", err)
	}
	var ee *exitError
	if !errors.As(err, &ee) || ee.code != 2 {
		t.Errorf("expected exit code 2 for store error, got error: %v", err)
	}
}
