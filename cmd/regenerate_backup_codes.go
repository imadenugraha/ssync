package cmd

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	"github.com/user/ssync/internal/backup"
	"github.com/user/ssync/internal/credentials"
	"github.com/user/ssync/internal/crypto"
	"github.com/user/ssync/internal/manifest"
	"github.com/user/ssync/internal/r2"
)

// regenRunner holds injectable dependencies for the regenerate-backup-codes command.
type regenRunner struct {
	in       io.Reader
	out      io.Writer
	r2       r2.R2Client
	engine   artifactDecrypter
	manifest manifest.ManifestManager
	backup   backup.BackupCodeManager
	pwReader passwordReader
}

func (r *regenRunner) run() error {
	// 1. Prompt for current encryption password (hidden).
	password, err := r.pwReader(r.out, "Current encryption password: ")
	if err != nil {
		return err
	}

	// 2. Verify password by fetching manifest and decrypting the first artifact.
	mf, err := r.manifest.Fetch()
	if err != nil {
		return &exitError{code: 2, msg: fmt.Sprintf("fetch manifest: %v", err)}
	}
	if len(mf.Artifacts) == 0 {
		return &exitError{code: 1, msg: "no artifacts found in remote manifest — nothing to verify password against"}
	}

	firstArtifact := mf.Artifacts[0]
	blob, err := r.r2.Download(firstArtifact.R2Key)
	if err != nil {
		return &exitError{code: 2, msg: fmt.Sprintf("download artifact for verification: %v", err)}
	}

	_, err = r.engine.DecryptWithMetadata(blob, password)
	if err != nil {
		fmt.Fprintln(r.out, "Error: wrong password — could not verify encryption password.")
		return &exitError{code: 1, msg: "wrong password"}
	}

	// 3. Generate 8 new backup codes.
	newCodes, err := r.backup.Generate()
	if err != nil {
		return &exitError{code: 2, msg: fmt.Sprintf("generate backup codes: %v", err)}
	}

	// 4. Display new codes once with offline storage warning.
	fmt.Fprintln(r.out, "\n*** NEW BACKUP CODES — store these offline, they will not be shown again ***")
	for i, c := range newCodes {
		fmt.Fprintf(r.out, "  %d. %s\n", i+1, c.Code)
	}
	fmt.Fprintln(r.out, "*** END BACKUP CODES ***")
	fmt.Fprintln(r.out, "WARNING: All previous backup codes have been invalidated.")

	// 5. Store new hashes (overwrites old backup-codes.json, invalidating all previous codes).
	if err := r.backup.StoreHashes(newCodes); err != nil {
		return &exitError{code: 2, msg: fmt.Sprintf("store backup code hashes: %v", err)}
	}

	fmt.Fprintln(r.out, "New backup codes stored successfully.")
	return nil
}

var regenerateBackupCodesCmd = &cobra.Command{
	Use:   "regenerate-backup-codes",
	Short: "Generate a new set of backup codes",
	Long:  `Generates a new set of backup codes and invalidates all previous codes. Requires the current encryption password.`,
	// Exit code contract:
	//   0 — new backup codes generated and stored successfully
	//   1 — user error (wrong encryption password)
	//   2 — I/O/network error (credential load failure, R2 download/upload failure, code generation failure)
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

		runner := &regenRunner{
			in:       os.Stdin,
			out:      os.Stdout,
			r2:       r2Client,
			engine:   crypto.NewAESEngine(),
			manifest: manifest.NewManifestManager(r2Client),
			backup:   backup.NewManager(r2Client),
			pwReader: readPassword,
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
