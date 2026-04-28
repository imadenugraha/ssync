package cmd

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"github.com/user/ssync/internal"
)

// readerPasswordReader returns a passwordReader that reads lines from sc instead
// of the terminal. Used in tests to inject passwords via a shared bufio.Scanner.
func readerPasswordReader(sc *bufio.Scanner) passwordReader {
	return func(out io.Writer, prompt string) (string, error) {
		fmt.Fprint(out, prompt)
		if !sc.Scan() {
			if err := sc.Err(); err != nil {
				return "", err
			}
			return "", fmt.Errorf("EOF")
		}
		return strings.TrimSpace(sc.Text()), nil
	}
}

// mockCredStore is a no-op CredentialStore used across cmd tests.
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
