package cmd

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/user/ssync/internal/backup"
	"github.com/user/ssync/internal/crypto"
	"github.com/user/ssync/internal/credentials"
	"github.com/user/ssync/internal/manifest"
	"github.com/user/ssync/internal/r2"
)

// recoverEngine is a local interface for re-encryption during recovery.
type recoverEngine interface {
	EncryptArtifact(content []byte, name, relativePath, password string) ([]byte, error)
	DecryptWithMetadata(blob []byte, password string) (crypto.DecryptResult, error)
}

// recoverRunner holds injectable dependencies for the recover command.
type recoverRunner struct {
	in       io.Reader
	out      io.Writer
	r2       r2.R2Client
	engine   recoverEngine
	manifest manifest.ManifestManager
	backup   backup.BackupCodeManager
}

func (r *recoverRunner) run() error {
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

	// 1. Prompt for backup code.
	backupCode, err := prompt("Backup code: ")
	if err != nil {
		return err
	}

	// 2. Verify backup code.
	valid, err := r.backup.Verify(backupCode)
	if err != nil {
		return &exitError{code: 2, msg: fmt.Sprintf("verify backup code: %v", err)}
	}
	if !valid {
		// Count remaining unused codes.
		records, loadErr := r.backup.LoadHashes()
		remaining := 0
		if loadErr == nil {
			for _, rec := range records {
				if !rec.Used {
					remaining++
				}
			}
		}

		if remaining == 0 {
			fmt.Fprintln(r.out, "ERROR: All backup codes have been exhausted. Your data cannot be recovered.")
			fmt.Fprintln(r.out, "You will need to re-upload your SSH artifacts with a new password.")
			return &exitError{code: 1, msg: "all backup codes exhausted — permanent loss"}
		}

		fmt.Fprintf(r.out, "Invalid backup code. %d code(s) remaining.\n", remaining)
		return &exitError{code: 1, msg: "invalid backup code"}
	}

	// 3. Prompt for OLD encryption password (needed to decrypt existing artifacts).
	oldPassword, err := prompt("Current encryption password: ")
	if err != nil {
		return err
	}

	// 4. Prompt for NEW encryption password (≥12 chars).
	newPassword, err := r.promptNewPassword(prompt)
	if err != nil {
		return err
	}

	// 5. Fetch manifest.
	mf, err := r.manifest.Fetch()
	if err != nil {
		return &exitError{code: 2, msg: fmt.Sprintf("fetch manifest: %v", err)}
	}

	// 6. For each artifact: download → decrypt with old password → re-encrypt with new password → re-upload.
	type result struct {
		name string
		err  error
	}
	results := make([]result, 0, len(mf.Artifacts))

	for _, artifact := range mf.Artifacts {
		blob, dlErr := r.r2.Download(artifact.R2Key)
		if dlErr != nil {
			results = append(results, result{name: artifact.Name, err: fmt.Errorf("download: %w", dlErr)})
			continue
		}

		decrypted, decErr := r.engine.DecryptWithMetadata(blob, oldPassword)
		if decErr != nil {
			results = append(results, result{name: artifact.Name, err: fmt.Errorf("decrypt: %w", decErr)})
			continue
		}

		newBlob, encErr := r.engine.EncryptArtifact(decrypted.Content, decrypted.Name, decrypted.RelativePath, newPassword)
		if encErr != nil {
			results = append(results, result{name: artifact.Name, err: fmt.Errorf("re-encrypt: %w", encErr)})
			continue
		}

		if upErr := r.r2.Upload(artifact.R2Key, newBlob); upErr != nil {
			results = append(results, result{name: artifact.Name, err: fmt.Errorf("upload: %w", upErr)})
			continue
		}

		results = append(results, result{name: artifact.Name})
	}

	// Check for any failures before invalidating the code.
	anyFailed := false
	for _, res := range results {
		if res.err != nil {
			anyFailed = true
			break
		}
	}

	if anyFailed {
		fmt.Fprintln(r.out, "\nRe-encryption results:")
		for _, res := range results {
			if res.err != nil {
				fmt.Fprintf(r.out, "  ✗ %s: %v\n", res.name, res.err)
			} else {
				fmt.Fprintf(r.out, "  ✓ %s\n", res.name)
			}
		}
		return &exitError{code: 2, msg: "one or more artifacts failed to re-encrypt"}
	}

	// 7. Invalidate the backup code after successful re-encryption.
	if invErr := r.backup.Invalidate(backupCode); invErr != nil {
		return &exitError{code: 2, msg: fmt.Sprintf("invalidate backup code: %v", invErr)}
	}

	// 8. Update manifest (timestamps stay the same; only blobs changed).
	if updErr := r.manifest.Update(mf); updErr != nil {
		return &exitError{code: 2, msg: fmt.Sprintf("update manifest: %v", updErr)}
	}

	fmt.Fprintln(r.out, "\nRe-encryption results:")
	for _, res := range results {
		fmt.Fprintf(r.out, "  ✓ %s\n", res.name)
	}
	fmt.Fprintln(r.out, "Password recovery complete. Your backup code has been invalidated.")
	return nil
}

// promptNewPassword prompts for a new password, re-prompting if too short.
func (r *recoverRunner) promptNewPassword(prompt func(string) (string, error)) (string, error) {
	for {
		pw, err := prompt("New encryption password (≥12 chars): ")
		if err != nil {
			return "", err
		}
		if len(pw) >= 12 {
			return pw, nil
		}
		fmt.Fprintln(r.out, "Password must be at least 12 characters. Please try again.")
	}
}

var recoverCmd = &cobra.Command{
	Use:   "recover",
	Short: "Reset encryption password using a backup code",
	Long:  `Allows resetting the encryption password by providing a valid backup code.`,
	// Exit code contract:
	//   0 — password recovery and re-encryption completed successfully
	//   1 — user error (invalid backup code, all codes exhausted, password too short)
	//   2 — I/O/network error (credential load failure, R2 download/upload failure, re-encryption failure)
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

		runner := &recoverRunner{
			in:       os.Stdin,
			out:      os.Stdout,
			r2:       r2Client,
			engine:   crypto.NewAESEngine(),
			manifest: manifest.NewManifestManager(r2Client),
			backup:   backup.NewManager(r2Client),
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
