package cmd

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/user/ssync/internal"
	"github.com/user/ssync/internal/credentials"
)

// configureRunner holds injectable dependencies for the configure command.
type configureRunner struct {
	in    io.Reader
	out   io.Writer
	store credentials.CredentialStore
}

// run prompts for R2 credentials, validates them, and saves via the store.
func (r *configureRunner) run() error {
	scanner := bufio.NewScanner(r.in)

	prompt := func(label string) (string, error) {
		fmt.Fprintf(r.out, "%s: ", label)
		if !scanner.Scan() {
			if err := scanner.Err(); err != nil {
				return "", err
			}
			return "", fmt.Errorf("unexpected end of input")
		}
		return strings.TrimSpace(scanner.Text()), nil
	}

	accessKeyID, err := prompt("R2 Access Key ID")
	if err != nil {
		return err
	}
	secretAccessKey, err := prompt("R2 Secret Access Key")
	if err != nil {
		return err
	}
	endpointURL, err := prompt("R2 Endpoint URL")
	if err != nil {
		return err
	}
	bucketName, err := prompt("R2 Bucket Name")
	if err != nil {
		return err
	}

	// Validate — no field may be empty.
	switch {
	case accessKeyID == "":
		return &exitError{code: 1, msg: "access key ID must not be empty"}
	case secretAccessKey == "":
		return &exitError{code: 1, msg: "secret access key must not be empty"}
	case endpointURL == "":
		return &exitError{code: 1, msg: "endpoint URL must not be empty"}
	case bucketName == "":
		return &exitError{code: 1, msg: "bucket name must not be empty"}
	}

	creds := internal.R2Credentials{
		AccessKeyID:     accessKeyID,
		SecretAccessKey: secretAccessKey,
		EndpointURL:     endpointURL,
		BucketName:      bucketName,
	}

	if err := r.store.Save(creds); err != nil {
		return &exitError{code: 2, msg: fmt.Sprintf("failed to save credentials: %v", err)}
	}

	fmt.Fprintln(r.out, "Credentials saved successfully.")
	return nil
}

// exitError carries an exit code alongside an error message.
type exitError struct {
	code int
	msg  string
}

func (e *exitError) Error() string { return e.msg }

var configureCmd = &cobra.Command{
	Use:   "configure",
	Short: "Store R2 credentials",
	Long:  `Prompts for R2 access key ID, secret access key, endpoint URL, and bucket name, then stores them securely.`,
	// Exit code contract:
	//   0 — credentials saved successfully
	//   1 — user error (empty field, validation failure)
	//   2 — I/O error (credential store unavailable, write failure)
	RunE: func(cmd *cobra.Command, args []string) error {
		store, err := credentials.NewCredentialStore()
		if err != nil {
			os.Exit(2)
		}
		runner := &configureRunner{
			in:    os.Stdin,
			out:   os.Stdout,
			store: store,
		}
		if err := runner.run(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			if ee, ok := err.(*exitError); ok {
				os.Exit(ee.code)
			}
			os.Exit(1)
		}
		return nil
	},
}
