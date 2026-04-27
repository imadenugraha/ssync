package cmd

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/user/ssync/internal/credentials"
	"github.com/user/ssync/internal/crypto"
	"github.com/user/ssync/internal/manifest"
	"github.com/user/ssync/internal/r2"
)

// artifactDecrypter is a local interface for decrypting blobs with metadata.
type artifactDecrypter interface {
	DecryptWithMetadata(blob []byte, password string) (crypto.DecryptResult, error)
}

// pullRunner holds injectable dependencies for the pull command.
type pullRunner struct {
	in       io.Reader
	out      io.Writer
	store    credentials.CredentialStore
	r2       r2.R2Client
	engine   artifactDecrypter
	manifest manifest.ManifestManager
	sshDir   string
}

func (r *pullRunner) run() error {
	sc := bufio.NewScanner(r.in)

	prompt := func(label string) (string, error) {
		fmt.Fprintf(r.out, "%s", label)
		if !sc.Scan() {
			if err := sc.Err(); err != nil {
				return "", err
			}
			return "", fmt.Errorf("unexpected end of input")
		}
		return strings.TrimSpace(sc.Text()), nil
	}

	// 1. Fetch manifest.
	mf, err := r.manifest.Fetch()
	if err != nil {
		return &exitError{code: 2, msg: fmt.Sprintf("fetch manifest: %v", err)}
	}
	if len(mf.Artifacts) == 0 {
		return &exitError{code: 1, msg: "no artifacts found in remote manifest"}
	}

	// 2. Prompt for encryption password.
	password, err := prompt("Encryption password: ")
	if err != nil {
		return err
	}

	for {
		// 3. Download and decrypt each artifact.
		type result struct {
			name    string
			err     error
			tamper  bool
			network bool
		}
		results := make([]result, 0, len(mf.Artifacts))
		authFailCount := 0

		for _, artifact := range mf.Artifacts {
			blob, dlErr := r.r2.Download(artifact.R2Key)
			if dlErr != nil {
				results = append(results, result{name: artifact.Name, err: dlErr, network: true})
				continue
			}

			decrypted, decErr := r.engine.DecryptWithMetadata(blob, password)
			if decErr != nil {
				// Distinguish authentication/tamper errors from wrong-password errors.
				// A GCM tag failure on a single artifact while others succeed = tamper.
				// We collect all results first, then decide.
				errMsg := decErr.Error()
				isAuthErr := strings.Contains(errMsg, "authentication") ||
					strings.Contains(errMsg, "tag mismatch") ||
					strings.Contains(errMsg, "auth")
				if isAuthErr {
					authFailCount++
					results = append(results, result{name: artifact.Name, err: decErr})
				} else {
					results = append(results, result{name: artifact.Name, err: decErr})
				}
				continue
			}

			// Write decrypted content to local SSH directory.
			destPath := filepath.Join(r.sshDir, decrypted.RelativePath)
			if mkErr := os.MkdirAll(filepath.Dir(destPath), 0700); mkErr != nil {
				results = append(results, result{name: artifact.Name, err: fmt.Errorf("create dir: %w", mkErr)})
				continue
			}
			if writeErr := os.WriteFile(destPath, decrypted.Content, 0600); writeErr != nil {
				results = append(results, result{name: artifact.Name, err: fmt.Errorf("write file: %w", writeErr)})
				continue
			}

			results = append(results, result{name: artifact.Name})
		}

		// 4. Determine if ALL artifacts failed with auth errors (wrong password).
		totalDecryptAttempts := 0
		for _, res := range results {
			if !res.network {
				totalDecryptAttempts++
			}
		}
		allAuthFailed := authFailCount > 0 && authFailCount == totalDecryptAttempts

		if allAuthFailed {
			fmt.Fprintln(r.out, "Error: wrong password — decryption failed for all artifacts.")
			ans, promptErr := prompt("Retry with different password or use backup code? [r=retry/b=backup/q=quit] ")
			if promptErr != nil {
				return promptErr
			}
			switch strings.ToLower(ans) {
			case "r":
				password, err = prompt("Encryption password: ")
				if err != nil {
					return err
				}
				continue // retry the loop
			case "b":
				fmt.Fprintln(r.out, "Please use 'ssync recover' to reset your password with a backup code.")
				return &exitError{code: 1, msg: "recovery required"}
			default:
				return &exitError{code: 1, msg: "pull aborted"}
			}
		}

		// 5. Report per-artifact results.
		anyNetwork := false
		fmt.Fprintln(r.out, "\nPull results:")
		for _, res := range results {
			if res.err != nil {
				if res.network {
					fmt.Fprintf(r.out, "  ✗ %s: %v\n", res.name, res.err)
					anyNetwork = true
				} else {
					// Auth/tamper error on individual artifact while others may succeed.
					fmt.Fprintf(r.out, "  WARNING: artifact %q may have been tampered with — skipping\n", res.name)
				}
			} else {
				fmt.Fprintf(r.out, "  ✓ %s\n", res.name)
			}
		}

		if anyNetwork {
			return &exitError{code: 2, msg: "one or more artifacts failed due to network errors"}
		}
		return nil
	}
}

var pullCmd = &cobra.Command{
	Use:   "pull",
	Short: "Download and decrypt SSH artifacts from R2",
	Long:  `Downloads encrypted SSH artifacts from Cloudflare R2 and decrypts them to the local SSH directory.`,
	// Exit code contract:
	//   0 — all artifacts downloaded and decrypted successfully
	//   1 — user error (wrong password after retries, empty manifest, pull aborted)
	//   2 — I/O/network error (credential load failure, R2 download failure, write failure)
	RunE: func(cmd *cobra.Command, args []string) error {
		store, err := credentials.NewCredentialStore()
		if err != nil {
			fmt.Fprintln(os.Stderr, "failed to initialize credential store:", err)
			os.Exit(2)
		}
		creds, err := store.Load()
		if err != nil {
			fmt.Fprintln(os.Stderr, "failed to load credentials:", err)
			os.Exit(2)
		}
		r2Client, err := r2.NewR2Client(creds)
		if err != nil {
			fmt.Fprintln(os.Stderr, "failed to create R2 client:", err)
			os.Exit(2)
		}

		runner := &pullRunner{
			in:       os.Stdin,
			out:      os.Stdout,
			store:    store,
			r2:       r2Client,
			engine:   crypto.NewAESEngine(),
			manifest: manifest.NewManifestManager(r2Client),
			sshDir:   sshDir,
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

// isConnectionError checks if an error is a network/connection error.
func isConnectionError(err error) bool {
	var ce *r2.ConnectionError
	return errors.As(err, &ce)
}
